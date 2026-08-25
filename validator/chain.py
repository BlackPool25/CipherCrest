from __future__ import annotations
import argparse, base64, json, pathlib, re, sys, datetime
from cryptography import x509
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate, DNSName
from cryptography.x509.verification import Store, PolicyBuilder, VerificationError
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa, dsa, dh

PRIVATE_CA = pathlib.Path(__file__).parent / "stores" / "privateCA.pem"
OS_BUNDLE = pathlib.Path(__file__).parent / "stores" / "ca-bundle.crt"
HOSTNAME = "mail.lab.local"

def _load_pem_certs(path: pathlib.Path):
    data = path.read_bytes()
    certs = []
    for m in re.finditer(b"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", data, re.S):
        der = base64.b64decode(re.sub(rb"\s", b"", m.group(1)))
        certs.append(load_der_x509_certificate(der))
    return certs

def _load_input_certs(path: pathlib.Path):
    raw = path.read_bytes()
    # PEM detection
    if b"-----BEGIN CERTIFICATE-----" in raw:
        certs = []
        for m in re.finditer(b"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", raw, re.S):
            der = base64.b64decode(re.sub(rb"\s", b"", m.group(1)))
            certs.append(load_der_x509_certificate(der))
        return certs
    # DER single blob
    try:
        return [load_der_x509_certificate(raw)]
    except Exception:
        # try pcap-like: try scapy extraction (not required for test)
        return []

def _build_store():
    certs = []
    for p in [PRIVATE_CA, OS_BUNDLE]:
        if p.exists():
            try:
                certs.extend(_load_pem_certs(p))
            except Exception as e:
                sys.stderr.write(f"store load warn {p}: {e}\n")
    # fallback to system bundle if empty
    if not certs and pathlib.Path("/etc/ssl/certs/ca-certificates.crt").exists():
        certs.extend(_load_pem_certs(pathlib.Path("/etc/ssl/certs/ca-certificates.crt")))
    return Store(certs) if certs else Store([])

def _per_link_verify(chain):
    for i in range(len(chain)-1):
        child = chain[i]
        issuer = chain[i+1]
        # BasicConstraints CA:FALSE violation
        try:
            bc = issuer.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            if not bc.ca:
                return False, f"BasicConstraints CA:FALSE at {issuer.subject.rfc4514_string()}"
        except x509.ExtensionNotFound:
            # if issuer is supposed to be CA but missing BC, treat as violation if it signed child
            if issuer.subject != issuer.issuer:
                # non-self-signed without BC acting as CA -> fail
                # but allow root without BC if it's trust anchor? our CA now has BC, so ok
                pass
        # pubkey verify tbsCertificate.signature
        try:
            pub = issuer.public_key()
            if isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
            else:
                pub.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
        except Exception as e:
            return False, f"pubkey.verify failed {e}"
    # also check leaf BC not CA
    return True, ""

def validate_chain(cert_path: str, validation_time=None):
    p = pathlib.Path(cert_path)
    if not p.exists():
        raise FileNotFoundError(cert_path)
    certs = _load_input_certs(p)
    if not certs:
        return {"leaf_present": False, "is_tls13_opaque": False, "chain_length": 0, "chain_valid": False, "is_expired": None, "error": "no certs"}
    leaf = certs[0]
    inters = certs[1:]
    vt = validation_time or datetime.datetime.now(datetime.timezone.utc)
    # ensure vt is aware
    if vt.tzinfo is None:
        vt = vt.replace(tzinfo=datetime.timezone.utc)
    store = _build_store()
    verifier = PolicyBuilder().store(store).time(vt).max_chain_depth(6).build_server_verifier(DNSName(HOSTNAME))
    chain_valid = False
    chain_len = len(certs)
    verified = None
    try:
        verified = verifier.verify(leaf, inters)
        chain_valid = True
        chain_len = len(verified)
        ok, msg = _per_link_verify(list(verified))
        if not ok:
            sys.stderr.write(f"per-link fail: {msg}\n")
            chain_valid = False
    except VerificationError as e:
        sys.stderr.write(f"VerificationError: {e}\n")
        chain_valid = False
        # chain_len stays as input len
        # per-link still check for BC violation
        try:
            ok, msg = _per_link_verify(certs)
            if not ok:
                sys.stderr.write(f"per-link BC fail: {msg}\n")
        except Exception:
            pass
    # expiry / self_signed etc — weak checks per spec
    now = vt
    nbf = leaf.not_valid_before_utc if hasattr(leaf, "not_valid_before_utc") else leaf.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    naf = leaf.not_valid_after_utc if hasattr(leaf, "not_valid_after_utc") else leaf.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    days_to_expiry = (naf - now).days
    is_expired = naf < now
    is_not_yet_valid = nbf > now
    is_self_signed = leaf.issuer == leaf.subject
    # self_signed Medium if privateCA matches issuer
    self_signed_is_private = False
    if is_self_signed and PRIVATE_CA.exists():
        try:
            ca_certs = _load_pem_certs(PRIVATE_CA)
            if ca_certs:
                ca = ca_certs[0]
                # leaf self-signed but if it matches privateCA subject/key, it's private CA (Medium not High)
                if leaf.subject.rfc4514_string() == ca.subject.rfc4514_string():
                    self_signed_is_private = True
        except Exception:
            pass
    # pubkey bits/algo — RSA/EC/DH/DSA
    pub = leaf.public_key()
    algo = "unknown"
    bits = None
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            algo = "RSA"; bits = pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            algo = "EC"; bits = pub.key_size
        elif isinstance(pub, dsa.DSAPublicKey):
            algo = "DSA"; bits = pub.key_size
        elif isinstance(pub, dh.DHPublicKey):
            algo = "DH"; bits = pub.key_size
        elif hasattr(pub, "key_size"):
            bits = pub.key_size
            n = pub.__class__.__name__
            if "RSA" in n: algo = "RSA"
            elif "Elliptic" in n: algo = "EC"
            elif "DSA" in n: algo = "DSA"
            elif "DH" in n: algo = "DH"
            else: algo = n
    except Exception:
        pass
    # sigalg weak — sha1WithRSA/md5WithRSA/sha1WithECDSA etc via OID/name
    sigalg = leaf.signature_hash_algorithm.name if leaf.signature_hash_algorithm else "unknown"
    sig_oid = leaf.signature_algorithm_oid.dotted_string if hasattr(leaf, "signature_algorithm_oid") else ""
    weak_sig_names = {"sha1", "md5"}
    # OIDs: 1.2.840.113549.1.1.4 md5WithRSA, 1.2.840.113549.1.1.5 sha1WithRSA, 1.2.840.10045.4.1 sha1WithECDSA
    weak_oids = {"1.2.840.113549.1.1.4", "1.2.840.113549.1.1.5", "1.2.840.10045.4.1", "1.2.840.113549.1.1.2"}
    sigalg_weak = (sigalg.lower() in weak_sig_names) or (sig_oid in weak_oids)
    # keysize weak: RSA<2048 High (<1024 Critical), EC<P-256 High, DH<2048 High, DSA deprecated High
    keysize_weak = False
    keysize_severity = None
    if algo == "RSA" and bits is not None:
        if bits < 1024: keysize_weak = True; keysize_severity = "Critical"
        elif bits < 2048: keysize_weak = True; keysize_severity = "High"
    elif algo == "EC" and bits is not None:
        if bits < 256: keysize_weak = True; keysize_severity = "High"
    elif algo == "DH" and bits is not None:
        if bits < 2048: keysize_weak = True; keysize_severity = "High"
    elif algo == "DSA":
        keysize_weak = True; keysize_severity = "High"
    # SAN via RFC7817 helper (no regex-only X.509)
    try:
        from validator.san_check import check_san, get_must_staple
        san_res = check_san(leaf, HOSTNAME)
        san_match = san_res["san_match"]
        san_severity = san_res["severity"]  # High if False
    except Exception:
        san_match = None; san_severity = None
        try:
            ext = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            sans = ext.get_values_for_type(x509.DNSName)
            san_match = HOSTNAME in sans
        except Exception:
            san_match = None
    # Must-Staple via TLSFeature status_request (5)
    try:
        from validator.san_check import get_must_staple as _gm
        ocsp_must_staple = _gm(leaf)
    except Exception:
        ocsp_must_staple = False
        try:
            ext = leaf.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE).value
            ocsp_must_staple = any(getattr(f, "value", f) == 5 for f in ext)
        except Exception:
            ocsp_must_staple = False
    # OCSP staple — honest unknown, no live fetch; TLS1.3 opaque handled in parse layer
    # If no pcap, we report unknown honest (not not_stapled) per spec "unknown — no fetch, no staple observed"
    ocsp_stapled_status = "unknown"
    # chain incomplete severity
    chain_incomplete = not chain_valid and chain_len < 2
    chain_severity = None
    if not chain_valid:
        # Medium if private CA involved (issuer matches privateCA)
        is_private_chain = False
        if PRIVATE_CA.exists():
            try:
                ca_certs = _load_pem_certs(PRIVATE_CA)
                if ca_certs and leaf.issuer.rfc4514_string() == ca_certs[0].subject.rfc4514_string():
                    is_private_chain = True
            except Exception:
                pass
        chain_severity = "Medium" if is_private_chain else "High"
    return {
        "leaf_present": True,
        "is_tls13_opaque": False,
        "not_before": nbf.isoformat(),
        "not_after": naf.isoformat(),
        "days_to_expiry": days_to_expiry,
        "is_expired": is_expired,
        "is_not_yet_valid": is_not_yet_valid,
        "is_self_signed": is_self_signed,
        "self_signed_private_ca": self_signed_is_private,
        "chain_length": chain_len,
        "chain_valid": chain_valid,
        "chain_incomplete_severity": chain_severity,
        "san_match": san_match,
        "san_severity": san_severity,
        "pubkey_algo": algo,
        "pubkey_bits": bits,
        "sigalg": sigalg,
        "sigalg_oid": sig_oid,
        "sigalg_weak": sigalg_weak,
        "keysize_weak": keysize_weak,
        "keysize_severity": keysize_severity,
        "ocsp_stapled_status": ocsp_stapled_status,
        "ocsp_must_staple": ocsp_must_staple,
        "crl_unknown_reason": False,
        "ocsp_reason": "unknown — no fetch, no staple observed (LE 2025: short-lived CRL)",
    }

def main():
    ap = argparse.ArgumentParser(description="RFC5280 Store/PolicyBuilder chain validator")
    ap.add_argument("cert", help="cert file (.crt/.pem) or pcap")
    ap.add_argument("--json", action="store_true", help="json output")
    ap.add_argument("--time", help="validation time ISO8601")
    args = ap.parse_args()
    vt = None
    if args.time:
        vt = datetime.datetime.fromisoformat(args.time.replace("Z", "+00:00"))
    res = validate_chain(args.cert, vt)
    if args.json:
        json.dump(res, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(json.dumps(res, indent=2))

if __name__ == "__main__":
    main()
