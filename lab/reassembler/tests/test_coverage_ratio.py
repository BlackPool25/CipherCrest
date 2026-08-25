"""lab/reassembler coverage_ratio + pre_tls buffer tests — Task 13."""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess

PCAP_01 = pathlib.Path("lab/pcaps/family-01.pcap")
PCAP_JITTERED = pathlib.Path("lab/pcaps/jittered.pcap")
LEDGER = pathlib.Path("lab/LEDGER.md")


def test_family01_gt_095() -> None:
    from lab.reassembler.reassemble import reassemble

    res = reassemble(str(PCAP_01))
    assert res["coverage_ratio"] > 0.95, f"family-01 coverage {res['coverage_ratio']} <=0.95"
    assert res["pre_tls_buffer_len"] >= 0
    assert "pre_tls_buffer_injection_possible" in res
    assert "coverage_ratio" in res
    # per_flow also has pre_tls fields
    for pf in res["per_flow"]:
        assert "pre_tls_buffer_len" in pf
        assert "pre_tls_buffer_injection_possible" in pf
        assert "coverage_ratio" in pf
    # CLI jq path
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
    # clean synthetic pcaps should be 1.0
    assert data["coverage_ratio"] == 1.0


def test_jitter_logs_not_silent() -> None:
    """Jittered pcap must have coverage <1 or logged not silent; LEDGER must contain coverage_ratio."""
    from lab.reassembler.reassemble import reassemble

    assert PCAP_JITTERED.exists(), f"jittered pcap missing: {PCAP_JITTERED}"
    res = reassemble(str(PCAP_JITTERED))
    assert res["coverage_ratio"] < 1.0, f"jittered coverage {res['coverage_ratio']} should be <1.0 (gap/overlap)"
    assert res["pre_tls_buffer_len"] >= 0
    # LEDGER must log coverage_ratio not silent
    assert LEDGER.exists()
    text = LEDGER.read_text()
    assert "coverage_ratio" in text, "LEDGER must contain coverage_ratio column"
    # jittered case logged: either LEDGER mentions jittered or coverage <1 indicator
    # At minimum coverage_ratio column exists; also verify CLI jq for jittered
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
    from lab.reassembler.reassemble import reassemble, _compute_pre_tls_buffer

    # family-01 STARTTLS has bytes between 220 and ClientHello -> injection possible
    res = reassemble(str(PCAP_01))
    assert res["pre_tls_buffer_len"] > 0, "family-01 should have pre_tls_buffer_len >0 (220 -> ClientHello gap)"
    assert res["pre_tls_buffer_injection_possible"] is True
    # family-09 stripped has no ClientHello -> no buffer
    res09 = reassemble("lab/pcaps/family-09.pcap")
    assert res09["pre_tls_buffer_len"] == 0
    assert res09["pre_tls_buffer_injection_possible"] is False
    # direct helper
    payload = b"220 mail.lab.local ESMTP\r\nEHLO client\r\n250-STARTTLS\r\nSTARTTLS\r\n220 Ready to start TLS\r\n\x16\x03\x01 Hello"
    plen, possible = _compute_pre_tls_buffer(payload)
    assert plen > 0 and possible is True
    payload2 = b"220 mail.lab.local ESMTP\r\n\x16\x03\x01"
    plen2, possible2 = _compute_pre_tls_buffer(payload2)
    assert plen2 >= 0
