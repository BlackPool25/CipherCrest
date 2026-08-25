"""lab/reassembler coverage_ratio + pre_tls buffer tests — parity hardening 4 prefs."""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess

import pytest

PCAP_01 = pathlib.Path("lab/pcaps/family-01.pcap")
PCAP_JITTERED = pathlib.Path("lab/pcaps/jittered.pcap")
JITTER_DIR = pathlib.Path("lab/pcaps/jittered")
LEDGER = pathlib.Path("lab/LEDGER.md")
ALL_CLEAN = [pathlib.Path(f"lab/pcaps/family-{i:02d}.pcap") for i in range(1, 11)]


def test_family01_gt_095() -> None:
    from lab.reassembler.reassemble import reassemble

    res = reassemble(str(PCAP_01))
    assert res["coverage_ratio"] > 0.95, f"family-01 coverage {res['coverage_ratio']} <=0.95"
    assert res["pre_tls_buffer_len"] >= 0
    assert "pre_tls_buffer_injection_possible" in res
    assert "coverage_ratio" in res
    for pf in res["per_flow"]:
        assert "pre_tls_buffer_len" in pf
        assert "pre_tls_buffer_injection_possible" in pf
        assert "coverage_ratio" in pf
    result = subprocess.run(
        [shutil.which("python3") or "python3", "lab/reassembler/reassemble.py", str(PCAP_01), "--json"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["coverage_ratio"] > 0.95
    assert "pre_tls_buffer_len" in data
    assert data["coverage_ratio"] == 1.0


def test_jitter_logs_not_silent() -> None:
    from lab.reassembler.reassemble import reassemble

    assert PCAP_JITTERED.exists(), f"jittered pcap missing: {PCAP_JITTERED}"
    res = reassemble(str(PCAP_JITTERED))
    assert res["coverage_ratio"] < 1.0, f"jittered coverage {res['coverage_ratio']} should be <1.0"
    assert res["pre_tls_buffer_len"] >= 0
    assert LEDGER.exists()
    text = LEDGER.read_text()
    assert "coverage_ratio" in text, "LEDGER must contain coverage_ratio column"
    assert "0.897" in text or "jitter" in text.lower(), "LEDGER must log jittered 0.897 not silent"
    result = subprocess.run(
        [shutil.which("python3") or "python3", "lab/reassembler/reassemble.py", str(PCAP_JITTERED), "--json"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["coverage_ratio"] < 1.0


def test_pre_tls_buffer_computed() -> None:
    from lab.reassembler.reassemble import _compute_pre_tls_buffer, reassemble

    res = reassemble(str(PCAP_01))
    assert res["pre_tls_buffer_len"] > 0, "family-01 should have pre_tls_buffer_len >0"
    assert res["pre_tls_buffer_injection_possible"] is True
    res09 = reassemble("lab/pcaps/family-09.pcap")
    assert res09["pre_tls_buffer_len"] == 0
    assert res09["pre_tls_buffer_injection_possible"] is False
    payload = b"220 mail.lab.local ESMTP\r\nEHLO client\r\n250-STARTTLS\r\nSTARTTLS\r\n220 Ready to start TLS\r\n\x16\x03\x01 Hello"
    plen, possible = _compute_pre_tls_buffer(payload)
    assert plen > 0 and possible is True
    payload2 = b"220 mail.lab.local ESMTP\r\n\x16\x03\x01"
    plen2, _ = _compute_pre_tls_buffer(payload2)
    assert plen2 >= 0
    assert _compute_pre_tls_buffer(b"")[0] == 0
    assert _compute_pre_tls_buffer(b"220 only no tls")[1] is False


def test_3corpora_clean_jittered_weberblog() -> None:
    from lab.reassembler.reassemble import reassemble

    for p in ALL_CLEAN:
        res = reassemble(str(p))
        assert res["coverage_ratio"] == 1.0, f"{p} expected 1.0 got {res['coverage_ratio']}"
        assert "pre_tls_buffer_len" in res
        for pf in res["per_flow"]:
            assert "coverage_ratio" in pf and "pre_tls_buffer_len" in pf

    jittered_files = sorted(JITTER_DIR.glob("family-*-jitter-01.pcap"))
    assert len(jittered_files) == 7
    for p in jittered_files:
        res = reassemble(str(p))
        assert "coverage_ratio" in res
        assert "pre_tls_buffer_len" in res
    legacy = reassemble(str(PCAP_JITTERED))
    assert 0.8 < legacy["coverage_ratio"] < 1.0
    assert legacy["overlap_detected"] is True

    real = list(pathlib.Path("lab/pcaps/real").glob("*.pcap")) if pathlib.Path("lab/pcaps/real").exists() else []
    if real:
        assert len(real) >= 1
        for p in real[:20]:
            res = reassemble(str(p))
            assert "coverage_ratio" in res and "pre_tls_buffer_len" in res
    else:
        fixture = pathlib.Path("shared/fixtures/weberblog-01.json")
        assert fixture.exists(), "missing synthetic weberblog-01.json fallback"
        data = json.loads(fixture.read_text())
        flows = data if isinstance(data, list) else data.get("flows", [])
        assert len(flows) == 20, f"weberblog synthetic 20 flows expected got {len(flows)}"
        for entry in flows:
            assert "flow_id" in entry
            assert "coverage_ratio" in entry or "pre_tls_buffer_len" in entry


def test_coverage_ratio_every_flow_asserts() -> None:
    from lab.reassembler.reassemble import reassemble

    for p in [PCAP_01, PCAP_JITTERED, pathlib.Path("lab/pcaps/family-09.pcap")]:
        res = reassemble(str(p))
        assert "coverage_ratio" in res and "pre_tls_buffer_len" in res
        assert "pre_tls_buffer_injection_possible" in res
        for pf in res["per_flow"]:
            assert "coverage_ratio" in pf
            assert "pre_tls_buffer_len" in pf
            assert "pre_tls_buffer_injection_possible" in pf


def test_tshark_4prefs_not_3() -> None:
    from lab.reassembler.reassemble import TSHARK_REQUIRED_PREFS

    assert len(TSHARK_REQUIRED_PREFS) == 4
    assert TSHARK_REQUIRED_PREFS.count("tcp.desegment_tcp_streams:TRUE") == 1
    assert TSHARK_REQUIRED_PREFS.count("tcp.reassemble_out_of_order:TRUE") == 1
    joined = " ".join(TSHARK_REQUIRED_PREFS)
    assert joined.count("tcp.") == 2, "both tcp prefs required, not just one"


def test_stripping_flow3_no_clienthello() -> None:
    from lab.reassembler.reassemble import reassemble

    flow3 = pathlib.Path("lab/adversarial/stripping-history-3flow/flow3.pcap")
    if not flow3.exists():
        pytest.skip("flow3 pcap missing")
    res = reassemble(str(flow3))
    assert res["pre_tls_buffer_len"] == 0
    assert res["pre_tls_buffer_injection_possible"] is False
    raw = flow3.read_bytes()
    assert b"\x16\x03\x01" not in raw, "flow3 stripped must not contain 0x16 0x03 ClientHello"
    assert b"\x16\x03" not in raw or raw.count(b"\x16\x03") == 0, "flow3 no TLS record header"
