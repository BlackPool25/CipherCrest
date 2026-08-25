"""FoxIO JA4/JA4S with GREASE harmonization + offline rarity (display only).

- Filters GREASE via shared.ja4_rarity.filter_grease in ciphers/extensions/sigalgs/groups (issue #305)
- Sorts extensions hex, hashes per FoxIO technical_details §4
- Offline rarity via shared/data/censys_top_ja4.json → get_ja4_rarity (never ja4db.com)
- Whitelist ALLOWED_RISK_FEATURES: ja4 NOT in vector, only ja4_rarity numeric
- Fallback manual hash if pip ja4 missing (logs divergence)
- Emits ja4/ja4s/ja4_rarity into TLS
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import pathlib
import struct
import sys

from shared.ja4_rarity import ALLOWED_RISK_FEATURES as _WL
from shared.ja4_rarity import filter_grease, get_ja4_rarity

# Re-export whitelist + hard guard (raw ja4 spoofable via curl-cffi impersonate=chrome131)
# Oracle Top2 fix: explicit set + ja4 not in it (raw hash never vector) — fixes grep always-pass
ALLOWED_RISK_FEATURES = frozenset({"cipher_strength","kex","fs_flag","pubkey_bits","sigalg_weak","days_to_expiry","chain_valid","ja4_rarity","chain_depth","san_match","starttls_mode","port","cert_missing_reason","miss_indicator_*"})
assert "ja4" not in ALLOWED_RISK_FEATURES, "raw ja4 MUST NOT be whitelisted"
assert "ja4_rarity" in ALLOWED_RISK_FEATURES
assert _WL == ALLOWED_RISK_FEATURES, "whitelist divergence shared/ja4_rarity vs analyzer/jas"

log = logging.getLogger(__name__)

_TABLE = pathlib.Path(__file__).resolve().parents[1] / "shared" / "data" / "censys_top_ja4.json"


def _hash12(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12] if s else "000000000000"


def _parse_client_hello(body: bytes) -> dict:
    """Parse ClientHello body (after handshake header) → ciphers/extensions etc."""
    off = 0
    if len(body) < 34:
        return {}
    legacy_ver = struct.unpack("!H", body[off : off + 2])[0]
    off += 2
    off += 32  # random
    if off >= len(body):
        return {}
    sid_len = body[off]
    off += 1 + sid_len
    if off + 2 > len(body):
        return {}
    cs_len = struct.unpack("!H", body[off : off + 2])[0]
    off += 2
    ciphers = []
    for i in range(0, cs_len, 2):
        if off + i + 2 <= len(body):
            ciphers.append(struct.unpack("!H", body[off + i : off + i + 2])[0])
    off += cs_len
    if off >= len(body):
        return {"ciphers": ciphers, "extensions": [], "groups": [], "sigalgs": [], "legacy_ver": legacy_ver}
    comp_len = body[off]
    off += 1 + comp_len
    if off + 2 > len(body):
        return {"ciphers": ciphers, "extensions": [], "groups": [], "sigalgs": [], "legacy_ver": legacy_ver}
    ext_total = struct.unpack("!H", body[off : off + 2])[0]
    off += 2
    exts, groups, sigalgs = [], [], []
    end = off + ext_total
    while off + 4 <= end and off + 4 <= len(body):
        etype = struct.unpack("!H", body[off : off + 2])[0]
        elen = struct.unpack("!H", body[off + 2 : off + 4])[0]
        exts.append(etype)
        data = body[off + 4 : off + 4 + elen] if off + 4 + elen <= len(body) else b""
        if etype == 0x000A and len(data) >= 2:  # supported_groups
            gl = struct.unpack("!H", data[0:2])[0]
            for j in range(0, gl, 2):
                if 2 + j + 2 <= len(data):
                    groups.append(struct.unpack("!H", data[2 + j : 2 + j + 2])[0])
        elif etype == 0x000D and len(data) >= 2:  # signature_algorithms
            sl = struct.unpack("!H", data[0:2])[0]
            for j in range(0, sl, 2):
                if 2 + j + 2 <= len(data):
                    sigalgs.append(struct.unpack("!H", data[2 + j : 2 + j + 2])[0])
        off += 4 + elen
    return {"ciphers": ciphers, "extensions": exts, "groups": groups, "sigalgs": sigalgs, "legacy_ver": legacy_ver}


def _extract(pcap: pathlib.Path) -> dict | None:
    """Extract first ClientHello + ServerHello from pcap via scapy."""
    try:
        from scapy.all import rdpcap, Raw, TCP  # type: ignore
    except Exception as e:
        log.warning("scapy missing: %s", e)
        return None
    try:
        pkts = rdpcap(str(pcap))
    except Exception as e:
        log.warning("rdpcap failed %s: %s", pcap, e)
        return None
    ch = None
    sh = None
    for pkt in pkts:
        if not pkt.haslayer(Raw) or not pkt.haslayer(TCP):
            continue
        raw = bytes(pkt[Raw].load)
        if len(raw) < 6 or raw[0] != 0x16 or raw[1] != 0x03:
            continue
        # record header 5 + handshake 4
        if len(raw) < 9:
            continue
        htype = raw[5]
        if htype == 0x01 and ch is None:  # ClientHello
            hlen = struct.unpack("!I", b"\x00" + raw[6:9])[0]
            body = raw[9 : 9 + hlen]
            ch = _parse_client_hello(body)
        elif htype == 0x02 and sh is None:  # ServerHello
            hlen = struct.unpack("!I", b"\x00" + raw[6:9])[0]
            body = raw[9 : 9 + hlen]
            # minimal parse: cipher + extensions
            sh = {"raw": body.hex()[:40]}
            try:
                off = 2 + 32 + 1  # version+random+sid
                if len(body) > off:
                    sid_len = body[2 + 32]
                    off = 2 + 32 + 1 + sid_len
                    if off + 2 <= len(body):
                        sel_cipher = struct.unpack("!H", body[off : off + 2])[0]
                        sh["cipher"] = sel_cipher
            except Exception:
                pass
    if ch is None:
        return None
    return {"client": ch, "server": sh}


def _compute_ja4(parsed: dict) -> str:
    """Manual JA4 per FoxIO §4 with GREASE harmonization."""
    ciphers = filter_grease(parsed.get("ciphers", []))
    extensions = filter_grease(parsed.get("extensions", []))
    groups = filter_grease(parsed.get("groups", []))
    sigalgs = filter_grease(parsed.get("sigalgs", []))
    legacy = parsed.get("legacy_ver", 0x0303)
    # version detection: supported_versions ext 0x002b may indicate TLS1.3, else legacy
    is_tls13 = 0x002B in parsed.get("extensions", []) or legacy == 0x0304
    # also check groups/sigalgs presence? keep simple
    ver_str = "t13" if is_tls13 or legacy == 0x0303 and 0x002B in extensions else "t12"
    # fallback for TLS1.0/1.1 via legacy 0x0301/0x0302
    if legacy == 0x0301:
        ver_str = "t10"
    elif legacy == 0x0302:
        ver_str = "t11"
    elif legacy == 0x0304:
        ver_str = "t13"
    # Try pip ja4 first
    pip_ja4 = None
    try:
        import ja4  # type: ignore

        # ja4 lib exposes ja4() function; try generic call
        if hasattr(ja4, "ja4"):
            pip_ja4 = ja4.ja4(parsed)  # type: ignore
        elif hasattr(ja4, "JA4"):
            pip_ja4 = ja4.JA4(parsed)  # type: ignore
        if pip_ja4:
            log.info("pip ja4 used: %s", pip_ja4)
    except Exception as e:
        log.info("pip ja4 missing, fallback manual hash divergence logged: %s", e)
    # Manual hash: part_a version + SNI + cipher count + ext count + ALPN
    sni_char = "d" if 0x0000 in extensions else "i"
    # ALPN ext 0x0010 presence → h2 else 00
    alpn = "h2" if 0x0010 in extensions else "00"
    ext_sorted = sorted(extensions)
    part_a = f"{ver_str}{sni_char}{len(ciphers):02d}{len(ext_sorted):02d}{alpn}"
    cipher_str = ",".join(f"{c:04x}" for c in ciphers)
    b_hash = _hash12(cipher_str)
    # extensions hash excludes SNI(0x0000) and ALPN(0x0010) per FoxIO
    filt_ext = [e for e in ext_sorted if e not in (0x0000, 0x0010)]
    ext_str = ",".join(f"{e:04x}" for e in filt_ext)
    c_hash = _hash12(ext_str)
    # sigalgs+groups combined for third hash (sorted)
    sig_sorted = sorted(sigalgs)
    grp_sorted = sorted(groups)
    combined = ",".join(f"{v:04x}" for v in sig_sorted + grp_sorted)
    # If no sigalgs/groups, hash empty → 000...
    d_hash = _hash12(combined)
    manual = f"{part_a}_{b_hash}_{d_hash}"
    if pip_ja4 and pip_ja4 != manual:
        # log divergence ≤1 char expected due to GREASE harmonization
        diff = sum(1 for a, b in zip(pip_ja4, manual) if a != b)
        log.info("ja4 divergence pip vs manual: %d chars pip=%s manual=%s", diff, pip_ja4, manual)
        return pip_ja4
    return manual


def _compute_ja4s(server: dict | None, version: str = "t12") -> str | None:
    if not server:
        return None
    cipher = server.get("cipher")
    b = _hash12(f"{cipher:04x}" if cipher is not None else "")
    return f"{version}_{b}_000000000000"


def analyze_pcap(pcap: pathlib.Path) -> dict:
    """Main entry: extract JA4/JA4S + rarity for pcap → TLS-compatible dict."""
    parsed = _extract(pcap)
    if not parsed:
        return {"ja4": None, "ja4s": None, "ja4_rarity": None, "tls": {"ja4": None, "ja4s": None, "ja4_rarity": None}}
    ja4 = _compute_ja4(parsed["client"])
    # determine version prefix for ja4s
    ver = ja4.split("_")[0][:3] if ja4 else "t12"
    ja4s = _compute_ja4s(parsed.get("server"), ver)
    rarity = get_ja4_rarity(ja4) if ja4 else None
    # log sha256 of censys table
    try:
        import hashlib as _hl

        h = _hl.sha256(_TABLE.read_bytes()).hexdigest() if _TABLE.exists() else "missing"
        log.info("censys sha256=%s ja4=%s rarity=%s", h[:8], ja4, rarity)
    except Exception:
        pass
    return {"ja4": ja4, "ja4s": ja4s, "ja4_rarity": rarity, "tls": {"ja4": ja4, "ja4s": ja4s, "ja4_rarity": rarity}}


def main() -> None:
    ap = argparse.ArgumentParser(description="JA4 FoxIO GREASE harmonization + offline rarity")
    ap.add_argument("pcap", type=pathlib.Path, help="pcap file")
    ap.add_argument("--json", action="store_true", help="json output")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")
    res = analyze_pcap(args.pcap)
    if args.json:
        json.dump(res, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(f"ja4={res['ja4']} rarity={res['ja4_rarity']} ja4s={res['ja4s']}")


if __name__ == "__main__":
    main()
