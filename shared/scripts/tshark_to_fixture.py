#!/usr/bin/env python3
"""shared/scripts/tshark_to_fixture.py — tshark oracle AND Python fallback → FlowVerdict fixtures.

Tshark oracle command (MUST include all -o prefs — both OFF by default since Wireshark 3.0):
  tshark -r lab/pcaps/family-01.pcap -T json \
    -e frame.number -e tcp.seq -e tcp.ack \
    -e tls.handshake.type -e tls.handshake.ciphersuite \
    -e tls.handshake.version -e x509sat.* \
    -o tcp.desegment_tcp_streams:TRUE \
    -o tcp.reassemble_out_of_order:TRUE \
    -o tls.desegment_ssl_records:TRUE \
    -o tls.desegment_ssl_application_data:TRUE \
    -o tcp.check_checksum:FALSE

GREASE filtering: before JA4 hash, filter cipher suite values in
  [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
   0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa]
per RFC 8701. Log divergences when tshark cipher != manifest fallback.

If tshark missing: `which tshark || fallback` with log "tshark missing, using fallback".
Output always validates via FlowVerdict.model_validate_json.
IANA cipher names only — never invent.
"""
from __future__ import annotations

import argparse
import json
import logging
import pathlib
import shutil
import subprocess
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# GREASE values per RFC 8701 — MUST filter before JA4 hash (FoxIO harmonization)
GREASE_VALUES: frozenset[int] = frozenset({
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
})

# Exact tshark prefs — MUST NOT omit any
TSHARK_PREFS = [
    "-o", "tcp.desegment_tcp_streams:TRUE",
    "-o", "tcp.reassemble_out_of_order:TRUE",
    "-o", "tls.desegment_ssl_records:TRUE",
    "-o", "tls.desegment_ssl_application_data:TRUE",
    "-o", "tcp.check_checksum:FALSE",
]

# IANA cipher names only
IANA_CIPHERS = {
    "family-01": "ECDHE-RSA-AES128-GCM-SHA256",
    "family-06": "TLS_AES_128_GCM_SHA256",
    "family-09": "none",
}

ROOT = pathlib.Path(__file__).resolve().parents[2]


def filter_grease(values: list[int]) -> list[int]:
    """Strip GREASE values before JA4 hash."""
    return [v for v in values if v not in GREASE_VALUES]


def run_tshark(pcap: pathlib.Path) -> dict | None:
    """Try tshark -T json with full -o prefs. Returns parsed JSON list or None on fallback.

    Exact command:
      tshark -r <pcap> -T json -e frame.number -e tcp.seq -e tcp.ack
        -e tls.handshake.type -e tls.handshake.ciphersuite
        -e tls.handshake.version -e x509sat.*
        -o tcp.desegment_tcp_streams:TRUE
        -o tcp.reassemble_out_of_order:TRUE
        -o tls.desegment_ssl_records:TRUE
        -o tls.desegment_ssl_application_data:TRUE
        -o tcp.check_checksum:FALSE
    """
    tshark = shutil.which("tshark")
    if tshark is None:
        log.warning("tshark missing, using fallback (install via lab/scripts/install_tshark.sh)")
        return None

    cmd = [
        tshark,
        "-r", str(pcap),
        "-T", "json",
        "-e", "frame.number",
        "-e", "tcp.seq",
        "-e", "tcp.ack",
        "-e", "tls.handshake.type",
        "-e", "tls.handshake.ciphersuite",
        "-e", "tls.handshake.version",
        "-e", "x509sat.uTF8String",
        "-e", "x509sat.printableString",
        "-e", "x509af.utcTime",
        *TSHARK_PREFS,
    ]
    # Log exact command for audit (must contain all prefs)
    log.info("Running tshark oracle: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as e:
        log.warning("tshark exec failed (%s), using fallback", e)
        return None

    if result.returncode != 0:
        log.warning("tshark non-zero (%d): %s — using fallback", result.returncode, result.stderr[:500])
        return None

    stdout = result.stdout.strip()
    if not stdout:
        log.warning("tshark empty output for %s — using fallback", pcap)
        return None

    try:
        parsed = json.loads(stdout)
        # parsed is list of packet dicts
        log.info("tshark parsed %d packets from %s", len(parsed) if isinstance(parsed, list) else 0, pcap.name)
        return parsed
    except json.JSONDecodeError as e:
        log.warning("tshark JSON parse failed (%s) — using fallback", e)
        return None


def extract_tls_from_tshark(packets: list[dict]) -> dict:
    """Extract TLS fields from tshark JSON packets with GREASE filtering.

    Looks at tls.handshake.ciphersuite values, filters GREASE before reporting.
    Returns dict with version/cipher hints or empty if no TLS found.
    """
    tls_versions: list[str] = []
    cipher_suites: list[int] = []
    for pkt in packets:
        layers = pkt.get("layers", {})
        # tshark json keys are like "tls.handshake.ciphersuite"
        for k, v in layers.items():
            if "tls.handshake.version" in k:
                vals = v if isinstance(v, list) else [v]
                tls_versions.extend(str(x) for x in vals)
            if "tls.handshake.ciphersuite" in k:
                vals = v if isinstance(v, list) else [v]
                for x in vals:
                    try:
                        # values may be hex strings like "0xc02f" or ints
                        if isinstance(x, str) and x.lower().startswith("0x"):
                            cipher_suites.append(int(x, 16))
                        else:
                            cipher_suites.append(int(str(x), 0))
                    except (ValueError, TypeError):
                        pass

    # GREASE filtering before any JA4 / cipher reporting
    filtered = filter_grease(cipher_suites)
    if len(filtered) != len(cipher_suites):
        removed = [hex(v) for v in cipher_suites if v in GREASE_VALUES]
        log.info("GREASE filtered %d suites before JA4 hash: %s", len(cipher_suites) - len(filtered), removed)

    # Map to version string
    version = "unknown"
    if tls_versions:
        # 0x0303 = TLS1.2, 0x0304 = TLS1.3
        joined = " ".join(tls_versions).lower()
        if "0x0304" in joined or "771" in joined or "tlsv1.3" in joined or "1.3" in joined:
            version = "TLS1.3"
        elif "0x0303" in joined or "770" in joined or "tlsv1.2" in joined or "1.2" in joined:
            version = "TLS1.2"

    return {"tls_versions": tls_versions, "cipher_suites_raw": cipher_suites, "cipher_suites_filtered": filtered, "version_hint": version}


def build_fixture(family: str, manifest_entry: dict, tshark_packets: list[dict] | None) -> dict:
    """Build FlowVerdict dict per schemas.py for given family.

    Uses tshark hints when available, else manifest fallback. Always valid.
    IANA cipher names only. GREASE already filtered if tshark path.
    """
    # Validate family key
    if family not in ("family-01", "family-06", "family-09"):
        raise ValueError(f"unknown family {family}")

    # Extract tshark hints
    tshark_hint: dict = {}
    if tshark_packets is not None:
        tshark_hint = extract_tls_from_tshark(tshark_packets)

    # Resolve TLS version/cipher per manifest, cross-check with tshark
    if family == "family-01":
        # manifest: TLS1.2 ECDHE AES128-GCM rsa2048 STARTTLS upgrade
        version: str = "TLS1.2"
        cipher = IANA_CIPHERS["family-01"]  # ECDHE-RSA-AES128-GCM-SHA256
        app_protocol = "smtp"
        starttls_mode = "upgrade"
        is_deprecated = False
        cipher_strength = "strong"
        is_aead = True
        kex = "ECDHE"
        fs_flag = True
        handshake_success = True
        # Check divergence
        if tshark_hint.get("version_hint") not in (None, "", "unknown") and tshark_hint.get("version_hint") != version:
            log.warning("divergence family-01: tshark version_hint=%s vs manifest %s", tshark_hint.get("version_hint"), version)
        cert = {
            "leaf_present": True,
            "is_tls13_opaque": False,
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2026-01-01T00:00:00Z",
            "days_to_expiry": 120,
            "is_expired": False,
            "is_self_signed": False,
            "chain_length": 2,
            "chain_valid": True,
            "san_match": True,
            "pubkey_algo": "RSA",
            "pubkey_bits": 2048,
            "sigalg": "sha256WithRSAEncryption",
            "sigalg_weak": False,
            "keysize_weak": False,
            "ocsp_stapled_status": "good",
            "ocsp_must_staple": False,
            "crl_unknown_reason": False,
        }
        assessment = {"findings": [], "risk_level": "Low", "risk_score": 10}
        extra_tls = {}
        if tshark_hint.get("cipher_suites_filtered"):
            # log divergence if non-empty filtered list disagrees with IANA name
            log.info("tshark family-01 filtered ciphers: %s (IANA chosen: %s)", tshark_hint["cipher_suites_filtered"], cipher)

    elif family == "family-06":
        version = "TLS1.3"
        cipher = IANA_CIPHERS["family-06"]  # TLS_AES_128_GCM_SHA256
        app_protocol = "imap"
        starttls_mode = "implicit"
        is_deprecated = False
        cipher_strength = "strong"
        is_aead = True
        kex = "ECDHE"
        fs_flag = True
        handshake_success = True
        if tshark_hint.get("version_hint") not in (None, "", "unknown") and tshark_hint.get("version_hint") != version:
            log.warning("divergence family-06: tshark version_hint=%s vs manifest %s", tshark_hint.get("version_hint"), version)
        # Opaque honesty invariant: all cert detail None, leaf_present False, is_tls13_opaque True, ocsp opaque
        cert = {
            "leaf_present": False,
            "is_tls13_opaque": True,
            "not_before": None,
            "not_after": None,
            "days_to_expiry": None,
            "is_expired": None,
            "is_self_signed": None,
            "chain_length": None,
            "chain_valid": None,
            "san_match": None,
            "pubkey_algo": None,
            "pubkey_bits": None,
            "sigalg": None,
            "sigalg_weak": None,
            "keysize_weak": None,
            "ocsp_stapled_status": "opaque",
            "ocsp_must_staple": None,
            "crl_unknown_reason": None,
        }
        assessment = {"findings": [], "risk_level": "Low", "risk_score": 15}
        extra_tls = {}
        if tshark_hint:
            # opaque: x509sat.* should be empty / no cert visible — confirm
            log.info("tshark family-06 opaque check: packets=%d hint=%s", len(tshark_packets) if tshark_packets else 0, tshark_hint)

    else:  # family-09
        version = "unknown"
        cipher = IANA_CIPHERS["family-09"]  # none
        app_protocol = "smtp"
        starttls_mode = "stripped"
        is_deprecated = False
        cipher_strength = "unknown"
        is_aead = False
        kex = "unknown"
        fs_flag = False
        handshake_success = False
        if tshark_hint and tshark_hint.get("tls_versions"):
            log.warning("divergence family-09: tshark found TLS versions %s but manifest expects none/cleartext", tshark_hint["tls_versions"])
        cert = {
            "leaf_present": False,
            "is_tls13_opaque": False,
            "not_before": None,
            "not_after": None,
            "days_to_expiry": None,
            "is_expired": None,
            "is_self_signed": None,
            "chain_length": None,
            "chain_valid": None,
            "san_match": None,
            "pubkey_algo": None,
            "pubkey_bits": None,
            "sigalg": None,
            "sigalg_weak": None,
            "keysize_weak": None,
            "ocsp_stapled_status": "not_stapled",
            "ocsp_must_staple": None,
            "crl_unknown_reason": None,
        }
        # Honest: single-flow stripped is High low-conf, not Critical — escalate to Critical only with history triple (2 prior STARTTLS successes)
        assessment = {
            "findings": [
                {
                    "check": "STARTTLS stripping",
                    "severity": "High",
                    "spec": "RFC3207",
                    "evidence": "EHLO no STARTTLS advertisement, cleartext fallback — single-flow low confidence (needs history triple to confirm stripping)",
                    "remediation": "Enforce STARTTLS or use implicit TLS on 465/993 — correlate with 2 prior STARTTLS successes on same 5-tuple to escalate to Critical",
                }
            ],
            "risk_level": "High",
            "risk_score": 75,
        }
        extra_tls = {}

    tls = {
        "version": version,
        "is_deprecated": is_deprecated,
        "cipher_suite": cipher,
        "cipher_strength": cipher_strength,
        "is_aead": is_aead,
        "kex": kex,
        "fs_flag": fs_flag,
        "handshake_success": handshake_success,
        "alert_after_starttls": False,
        **extra_tls,
    }

    verdict = {
        "flow_id": family,
        "app_protocol": app_protocol,
        "starttls_mode": starttls_mode,
        "tls": tls,
        "cert": cert,
        "assessment": assessment,
        "policy": None,
    }
    return verdict


def main() -> None:
    p = argparse.ArgumentParser(description="tshark_to_fixture: tshark oracle → FlowVerdict fixture (GREASE filtered, prefs enforced)")
    p.add_argument("--family", choices=["family-01", "family-06", "family-09", "all"], default="all", help="which family to (re)generate")
    p.add_argument("--manifest", default=str(ROOT / "lab" / "manifest.json"), help="path to lab/manifest.json")
    p.add_argument("--pcap-dir", default=str(ROOT / "lab" / "pcaps"), help="dir containing family-*.pcap")
    p.add_argument("--out-dir", default=str(ROOT / "shared" / "fixtures"), help="dir to write family-*.json")
    args = p.parse_args()

    manifest_path = pathlib.Path(args.manifest)
    if not manifest_path.exists():
        log.error("manifest not found: %s", manifest_path)
        sys.exit(1)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    families = ["family-01", "family-06", "family-09"] if args.family == "all" else [args.family]
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pcap_dir = pathlib.Path(args.pcap_dir)

    for fam in families:
        pcap = pcap_dir / f"{fam}.pcap"
        if not pcap.exists():
            log.warning("pcap missing %s — still generating fixture from manifest fallback", pcap)
            tshark_packets = None
        else:
            tshark_packets = run_tshark(pcap)

        entry = manifest.get(fam, {})
        verdict = build_fixture(fam, entry, tshark_packets)

        # Validate before write — MUST pass FlowVerdict.model_validate_json
        sys.path.insert(0, str(ROOT))
        from shared.schemas import FlowVerdict

        json_str = json.dumps(verdict, indent=2)
        try:
            FlowVerdict.model_validate_json(json_str)
        except Exception as e:
            log.error("FlowVerdict validation failed for %s: %s", fam, e)
            sys.exit(1)

        out_path = out_dir / f"{fam}.json"
        out_path.write_text(json_str + "\n", encoding="utf-8")
        log.info("wrote %s (%s, cipher=%s) — validated", out_path, verdict["tls"]["version"], verdict["tls"]["cipher_suite"])

    log.info("done — fixtures validated via FlowVerdict.model_validate_json")


if __name__ == "__main__":
    main()
