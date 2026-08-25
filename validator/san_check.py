"""RFC7817 SAN + weak checks + stapled OCSP (B) — strict, no fetch, no regex-only X.509.

LE 2025 OCSP deprecation: Let's Encrypt retired OCSP Aug 2025 in favour of
short-lived certs + CRLs; staple is legacy but checked if present. We never
fetch CRL/OCSP live — only report what the handshake carried (CertificateStatus
type 22 or TLS1.3 encrypted). If absent → "unknown — no fetch, no staple observed" (honest).
For TLS1.3, staple (like cert) is encrypted → ocsp_staple_opaque=True legend
"staple encrypted like cert".
"""
from __future__ import annotations
import argparse, json, pathlib, sys, datetime, struct
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, dh

HOSTNAME_DEFAULT = "mail.lab.local"

# ---------- RFC7817 hostname matching ----------
def _dns_match(pattern: str, hostname: str) -> bool:
    p = pattern.lower().rstrip(".")
    h = hostname.lower().rstrip(".")
    if p == h:
        return True
    if p.startswith("*."):
        suffix = p[2:]
        if "." not in h:
            return False
        # wildcard only matches single leftmost label per RFC6125
        return h.split(".", 1)[1] == suffix and h.count(".") == suffix.count(".") + 1
    return False

def _extract_sans(cert: x509.Certificate) -> list[str] | None:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        return ext.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None
    except Exception:
        return None

def _extract_cn(cert: x509.Certificate) -> str | None:
    try:
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else None
    except Exception:
        return None

def _has_srv_id(sans: list[str] | None) -> bool:
    if not sans:
        return False
    return any(s.startswith("_") for s in sans)

def check_san(cert: x509.Certificate, hostname: str, sni: str | None = None) -> dict:
    """RFC7817: MUST match SAN dNSName vs hostname (or SNI if provided).
    CN fallback only if SAN absent → Medium not pass. SRV-ID if RFC6186.
    Returns dict with san_match bool, sans, cn, used_cn_fallback, srv_id, severity hint.
    """
    target = (sni or hostname or "").strip()
    sans = _extract_sans(cert)
    cn = _extract_cn(cert)
    srv = _has_srv_id(sans)
    if sans is not None:
        # SAN present → MUST use SAN, CN ignored per RFC6125/7817
        matched = any(_dns_match(p, target) for p in sans)
        sev = None if matched else "High"
        return {"san_match": matched, "sans": sans, "cn": cn, "used_cn_fallback": False, "srv_id": srv, "severity": sev, "evidence": f"SAN {sans} vs {target}"}
    # SAN absent → CN fallback (Medium, not pass)
    if cn is not None:
        matched = _dns_match(cn, target)
        # Even if matched, flag Medium per spec (not strict pass)
        sev = "Medium" if matched else "High"
        return {"san_match": matched, "sans": None, "cn": cn, "used_cn_fallback": True, "srv_id": False, "severity": sev, "evidence": f"CN fallback {cn} vs {target} (SAN absent)"}
    return {"san_match": False, "sans": None, "cn": None, "used_cn_fallback": False, "srv_id": False, "severity": "High", "evidence": f"no SAN/CN vs {target}"}

# ---------- Must-Staple via TLSFeature ----------
def get_must_staple(cert: x509.Certificate) -> bool:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE).value
        # RFC7633: TLSFeature contains list of TLSFeatureType, 5 = status_request
        return any(getattr(f, "value", f) == 5 for f in ext)
    except x509.ExtensionNotFound:
        return False
    except Exception:
        return False

# ---------- Stapled OCSP (B) — pcap parsing ----------
def _detect_ocsp_request(pcap_path: pathlib.Path) -> bool:
    """Detect ClientHello extension status_request 0x0005 / status_request_v2 0x0011 RFC6961."""
    try:
        raw = pcap_path.read_bytes()
        # cheap scan: look for TLS handshake ClientHello with those extension ids
        # Parse via scapy-like manual if available else byte search
        # Use analyzer.parse._parse_ch_body if exists
        import struct
        # scan for 0x0005 / 0x0011 in extension headers near ClientHello
        # We brute-force search for pattern 00 05 or 00 11 as extension type
        # plus validate surrounding record header 16 03
        if b"\x16\x03" in raw:
            # Try proper parse via analyzer if available
            try:
                from analyzer.parse import _scapy_fallback, _parse_ch_body
                fb = _scapy_fallback(pcap_path)
                if fb and fb.get("ch"):
                    exts = fb["ch"].get("extensions", [])
                    return 0x0005 in exts or 0x0011 in exts or 0x0017 in exts
            except Exception:
                pass
            return b"\x00\x05" in raw or b"\x00\x11" in raw
        return False
    except Exception:
        return False

def _parse_stapled_ocsp(pcap_path: pathlib.Path) -> dict:
    """If server sent CertificateStatus (handshake type 22) with DER OCSP response,
    parse via cryptography.x509.ocsp.load_der_ocsp_response.
    Returns dict with ocsp_stapled_status good/revoked/unknown/not_stapled + this/next_update.
    If absent → unknown honest (no fetch). For TLS1.3 → opaque.
    """
    # TLS1.3 opaque handled by caller
    try:
        raw = pcap_path.read_bytes()
        # Look for handshake type 22 (0x16) — CertificateStatus
        # Minimal: scan for record containing 0x16 0x16 (handshake type 22 inside TLS record)
        if b"\x16" not in raw:
            return {"ocsp_stapled_status": "unknown", "reason": "unknown — no fetch, no staple observed", "this_update": None, "next_update": None}
        # Try to find CertificateStatus via scapy raw layers
        # Fallback: search for OCSP DER magic via load attempts on handshake bodies
        from scapy.all import rdpcap, Raw  # type: ignore
        pkts = rdpcap(str(pcap_path))
        for pkt in pkts:
            if not pkt.haslayer(Raw):
                continue
            b = bytes(pkt[Raw].load)
            # TLS record header 5 bytes + handshake header 4 bytes
            idx = 0
            while idx + 9 < len(b):
                if b[idx] != 0x16:
                    idx += 1
                    continue
                hlen = struct.unpack("!H", b[idx+3:idx+5])[0] if idx+5 <= len(b) else 0
                if idx+5+hlen > len(b):
                    break
                # handshake type at idx+5
                htype = b[idx+5]
                if htype == 22:  # CertificateStatus
                    # handshake body: status_type(1) + ocsp_response_len(3) + DER
                    if hlen >= 4:
                        body = b[idx+5+4:idx+5+hlen]
                        if len(body) >= 4:
                            ocsp_len = struct.unpack("!I", b"\x00"+body[1:4])[0] if len(body) >=4 else 0
                            der = body[4:4+ocsp_len] if ocsp_len else body[1:]
                            if der:
                                try:
                                    from cryptography.x509.ocsp import load_der_ocsp_response
                                    resp = load_der_ocsp_response(der)
                                    st = resp.certificate_status.name.lower() if hasattr(resp.certificate_status, 'name') else str(resp.certificate_status).lower()
                                    # Map GOOD/REVOKED/UNKNOWN
                                    if "good" in st: s="good"
                                    elif "revoked" in st: s="revoked"
                                    else: s="unknown"
                                    return {"ocsp_stapled_status": s, "reason": f"stapled {s}", "this_update": resp.this_update.isoformat() if resp.this_update else None, "next_update": resp.next_update.isoformat() if resp.next_update else None}
                                except Exception as e:
                                    return {"ocsp_stapled_status": "unknown", "reason": f"staple present but parse failed: {e}", "this_update": None, "next_update": None}
                idx += 5+hlen
    except Exception:
        pass
    return {"ocsp_stapled_status": "unknown", "reason": "unknown — no fetch, no staple observed", "this_update": None, "next_update": None}

def ocsp_info_for_pcap(pcap_path: str | pathlib.Path | None, is_tls13_opaque: bool, cert: x509.Certificate | None = None) -> dict:
    """B helper: returns ocsp_* fields honoring TLS1.3 opaque legend."""
    if is_tls13_opaque:
        return {"ocsp_staple_requested": False, "ocsp_stapled_status": "opaque", "ocsp_staple_opaque": True, "ocsp_must_staple": False, "legend": "staple encrypted like cert (TLS1.3)", "this_update": None, "next_update": None, "reason": "opaque — TLS1.3 encrypts Certificate/CertificateStatus"}
    must = get_must_staple(cert) if cert else False
    req = False
    staple = {"ocsp_stapled_status": "unknown", "reason": "unknown — no fetch, no staple observed", "this_update": None, "next_update": None}
    if pcap_path and pathlib.Path(pcap_path).exists():
        req = _detect_ocsp_request(pathlib.Path(pcap_path))
        staple = _parse_stapled_ocsp(pathlib.Path(pcap_path))
        # if no staple observed, normalize to not_stapled vs unknown per spec — keep unknown honest when no pcap staple
        if staple["ocsp_stapled_status"] == "unknown" and not req:
            staple["ocsp_stapled_status"] = "unknown"
    else:
        # no pcap → honest unknown, not not_stapled
        staple = {"ocsp_stapled_status": "unknown", "reason": "unknown — no fetch, no staple observed", "this_update": None, "next_update": None}
        if staple["ocsp_stapled_status"] == "unknown":
            pass
    return {"ocsp_staple_requested": req, "ocsp_stapled_status": staple["ocsp_stapled_status"], "ocsp_staple_opaque": False, "ocsp_must_staple": must, "legend": "LE 2025: OCSP retired, short-lived CRL; staple legacy" if not must else "Must-Staple via TLSFeature", "this_update": staple.get("this_update"), "next_update": staple.get("next_update"), "reason": staple.get("reason")}

# ---------- CLI ----------
def _load_cert(path: pathlib.Path) -> x509.Certificate:
    import base64, re
    from cryptography.x509 import load_der_x509_certificate
    raw = path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in raw:
        m = re.search(b"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", raw, re.S)
        if not m: raise ValueError("no PEM cert")
        der = base64.b64decode(re.sub(rb"\s", b"", m.group(1)))
        return load_der_x509_certificate(der)
    return load_der_x509_certificate(raw)

def main():
    ap = argparse.ArgumentParser(description="RFC7817 SAN check + weak + OCSP")
    ap.add_argument("cert", help="cert file")
    ap.add_argument("hostname", nargs="?", default=HOSTNAME_DEFAULT, help="hostname to check (or SNI)")
    ap.add_argument("--sni", help="SNI override")
    ap.add_argument("--pcap", help="pcap for OCSP staple detection")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    cert = _load_cert(pathlib.Path(args.cert))
    san = check_san(cert, args.hostname, sni=args.sni)
    must = get_must_staple(cert)
    ocsp = ocsp_info_for_pcap(args.pcap, False, cert)
    # weak bits for CLI
    pub = cert.public_key()
    bits = getattr(pub, "key_size", None)
    algo = "RSA" if isinstance(pub, rsa.RSAPublicKey) else "EC" if isinstance(pub, ec.EllipticCurvePublicKey) else "DSA" if isinstance(pub, dsa.DSAPublicKey) else "DH" if isinstance(pub, dh.DHPublicKey) else pub.__class__.__name__
    res = {"san_match": san["san_match"], "sans": san["sans"], "cn": san["cn"], "used_cn_fallback": san["used_cn_fallback"], "srv_id": san["srv_id"], "severity": san["severity"], "evidence": san["evidence"], "ocsp_must_staple": must, "ocsp_stapled_status": ocsp["ocsp_stapled_status"], "ocsp_staple_requested": ocsp["ocsp_staple_requested"], "this_update": ocsp["this_update"], "next_update": ocsp["next_update"], "pubkey_algo": algo, "pubkey_bits": bits}
    if args.json:
        json.dump(res, sys.stdout, indent=2); sys.stdout.write("\n")
    else:
        print(json.dumps(res, indent=2))

if __name__ == "__main__":
    main()
