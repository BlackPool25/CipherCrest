"""Task 5 — Fixture schema only (NOT parity tautology).

Validates shared/fixtures/family-*.json via FlowVerdict.model_validate_json.
Checks TLS versions/ciphers per manifest, opaque invariant for family-06.

Parity F1 vs tshark is lab/reassembler/tests/test_reassembly.py (Todo7).
"""
from __future__ import annotations

import glob
import json
import pathlib
import shutil

import pytest

from shared.schemas import FlowVerdict


def test_fixtures_schema_exists():
    """Each family-01/06/09 fixture validates via FlowVerdict.model_validate_json — 3/3 Day1, 10 after Day7."""
    fixtures = sorted(glob.glob("shared/fixtures/family-*.json"))
    assert len(fixtures) >= 3, f"expected >=3 family fixtures, got {fixtures}"
    stems = {pathlib.Path(p).stem for p in fixtures}
    for req in ("family-01", "family-06", "family-09"):
        assert req in stems, f"missing {req}.json"
    for path in fixtures:
        raw = pathlib.Path(path).read_text(encoding="utf-8")
        v = FlowVerdict.model_validate_json(raw)
        assert v.flow_id in pathlib.Path(path).stem
        assert isinstance(v.model_dump(), dict)


def test_fixture_tls_versions_and_ciphers():
    """Per manifest: 01→TLS1.2 ECDHE-RSA-AES128-GCM-SHA256, 06→TLS1.3 TLS_AES_128_GCM_SHA256 opaque, 09→stripped unknown/none."""
    def load(fam: str) -> FlowVerdict:
        return FlowVerdict.model_validate_json(pathlib.Path(f"shared/fixtures/{fam}.json").read_text(encoding="utf-8"))

    v01 = load("family-01")
    assert v01.tls.version == "TLS1.2"
    assert v01.tls.cipher_suite == "ECDHE-RSA-AES128-GCM-SHA256"  # IANA only
    assert v01.app_protocol == "smtp"
    assert v01.starttls_mode == "upgrade"

    v06 = load("family-06")
    assert v06.tls.version == "TLS1.3"
    assert v06.tls.cipher_suite == "TLS_AES_128_GCM_SHA256"  # IANA TLS1.3 prefixed
    assert v06.app_protocol == "imap"
    assert v06.starttls_mode == "implicit"
    # opaque invariant
    assert v06.cert.is_tls13_opaque is True
    assert v06.cert.leaf_present is False
    assert v06.cert.ocsp_stapled_status == "opaque"
    assert v06.cert.pubkey_bits is None
    assert v06.cert.san_match is None

    v09 = load("family-09")
    assert v09.tls.version == "unknown"
    assert v09.tls.cipher_suite == "none"
    assert v09.tls.handshake_success is False
    assert v09.starttls_mode == "stripped"


def test_fixture_grease_and_prefs_documented():
    """GREASE filtering + tshark prefs must be documented in shared/scripts/tshark_to_fixture.py (not omitted)."""
    script = pathlib.Path("shared/scripts/tshark_to_fixture.py").read_text(encoding="utf-8")
    # Must NOT omit -o prefs
    assert "tcp.desegment_tcp_streams:TRUE" in script, "missing tcp.desegment_tcp_streams pref"
    assert "tcp.reassemble_out_of_order:TRUE" in script, "missing tcp.reassemble_out_of_order pref"
    assert "tls.desegment_ssl_records:TRUE" in script, "missing tls.desegment_ssl_records pref"
    assert "tls.desegment_ssl_application_data:TRUE" in script, "missing tls.desegment_ssl_application_data pref"
    assert "tcp.check_checksum:FALSE" in script, "missing tcp.check_checksum pref"
    # GREASE values
    assert "0x0A0A" in script or "0x0a0a" in script.lower(), "missing GREASE 0x0a0a"
    assert "GREASE" in script, "missing GREASE mention"

    # history-3flow exists and is valid JSON (synthetic triple)
    hist = pathlib.Path("shared/fixtures/adversarial/history-3flow.json")
    assert hist.exists(), "missing adversarial/history-3flow.json"
    data = json.loads(hist.read_text(encoding="utf-8"))
    assert isinstance(data, list) and len(data) == 3, f"history-3flow expected 3 flows, got {len(data) if isinstance(data, list) else type(data)}"
    for entry in data:
        FlowVerdict.model_validate(entry)

    # tshark install script exists
    assert pathlib.Path("lab/scripts/install_tshark.sh").exists()

    # weberblog early creep guard — must NOT exist Day1
    assert not list(pathlib.Path("lab/pcaps/real").glob("*.pcap")) if pathlib.Path("lab/pcaps/real").exists() else True, "weberblog early creep: lab/pcaps/real/*.pcap exists Day1"
