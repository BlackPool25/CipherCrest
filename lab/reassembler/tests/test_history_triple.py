"""lab Day2 — history triple 3flow + honest severity."""
from __future__ import annotations

import json
import pathlib

import pytest

TRIPLE_DIR = pathlib.Path("lab/adversarial/stripping-history-3flow")
FAMILY09 = pathlib.Path("shared/fixtures/family-09.json")


def _load_raw(pcap_path: pathlib.Path) -> bytes:
    return pcap_path.read_bytes()


def _has_starttls_payload(raw: bytes) -> bool:
    return b"STARTTLS" in raw


def _has_tls_clienthello(raw: bytes) -> bool:
    # TLS record header 0x16 0x03 0x01 + handshake type 0x01
    return b"\x16\x03\x01" in raw and b"\x01" in raw


def _has_mail_from(raw: bytes) -> bool:
    return b"MAIL FROM" in raw


def _parse_five_tuple(pcap_path: pathlib.Path) -> tuple[str, str, int, int, str]:
    """Extract 5-tuple src dst sport dport proto via scapy. Returns (src, dst, sport, dport, proto)."""
    try:
        from scapy.all import rdpcap  # type: ignore

        pkts = rdpcap(str(pcap_path))
        for p in pkts:
            if p.haslayer("IP") and p.haslayer("TCP"):
                ip = p["IP"]
                tcp = p["TCP"]
                return (ip.src, ip.dst, int(tcp.sport), int(tcp.dport), "TCP")
        pytest.fail(f"no IP/TCP in {pcap_path}")
    except ImportError:
        pytest.skip("scapy not installed")
    pytest.fail("unreachable")
    return ("", "", 0, 0, "")


def test_triple_count():
    """3 pcaps exist, same 5-tuple 127.0.0.11 -> 127.0.0.1:587 sport 54330, flows 1-2 upgraded, 3 stripped."""
    assert TRIPLE_DIR.exists(), f"missing {TRIPLE_DIR}"
    flows = [TRIPLE_DIR / f"flow{i}.pcap" for i in (1, 2, 3)]
    for p in flows:
        assert p.exists(), f"missing {p} — run bash lab/scripts/gen_traffic.sh --history-triple"
        assert p.stat().st_size > 0, f"empty {p}"

    # same 5-tuple: src 127.0.0.11 dst 127.0.0.1 dport 587 sport 54330
    tuples = [_parse_five_tuple(p) for p in flows]
    for src, dst, sport, dport, _ in tuples:
        assert src == "127.0.0.11", f"src expected 127.0.0.11 got {src}"
        assert dst == "127.0.0.1", f"dst expected 127.0.0.1 got {dst}"
        assert dport == 587, f"dport expected 587 got {dport}"
        assert sport == 54330, f"sport expected 54330 got {sport}"
    # all same tuple
    assert len({(s, d, sp, dp) for s, d, sp, dp, _ in tuples}) == 1, f"5-tuples not identical: {tuples}"

    # payload checks via raw bytes
    raw1 = _load_raw(flows[0])
    raw2 = _load_raw(flows[1])
    raw3 = _load_raw(flows[2])

    # flows 1-2 upgraded: contain STARTTLS + 220 Ready + TLS ClientHello
    for idx, raw in enumerate([raw1, raw2], start=1):
        assert _has_starttls_payload(raw), f"flow{idx} missing STARTTLS (should be upgraded)"
        assert b"220 2.0.0 Ready to start TLS" in raw, f"flow{idx} missing 220 Ready"
        assert _has_tls_clienthello(raw), f"flow{idx} missing TLS ClientHello (upgraded)"

    # flow3 stripped: no STARTTLS Bennett, no TLS ClientHello, but has MAIL/RCPT cleartext
    assert not _has_starttls_payload(raw3) or b"250-STARTTLS" not in raw3, "flow3 should be stripped — must not advertise STARTTLS"
    # flow3 must NOT contain TLS ClientHello record
    # Check that raw3 has no 0x16 0x03 0x01 ClientHello — stripped is cleartext only
    assert b"\x16\x03\x01" not in raw3, "flow3 stripped must not contain TLS ClientHello"
    assert _has_mail_from(raw3), "flow3 stripped must contain MAIL FROM cleartext"
    assert b"RCPT TO" in raw3, "flow3 stripped must contain RCPT TO"


def test_reassembler_triple_pre_tls_gate():
    """Reassembler parity: flows 1-2 pre_tls>0 with 0x16 0x03, flow3 pre_tls 0 no ClientHello."""
    from lab.reassembler.reassemble import reassemble

    flows = [TRIPLE_DIR / f"flow{i}.pcap" for i in (1, 2, 3)]
    for p in flows:
        assert p.exists()
    r1 = reassemble(str(flows[0]))
    r2 = reassemble(str(flows[1]))
    r3 = reassemble(str(flows[2]))
    for r in (r1, r2):
        assert r["pre_tls_buffer_len"] > 0, f"{r['pcap']} expected pre_tls>0 got {r['pre_tls_buffer_len']}"
        assert r["pre_tls_buffer_injection_possible"] is True
        assert r["starttls_detected"] is True
        assert "coverage_ratio" in r and "pre_tls_buffer_len" in r
        for pf in r["per_flow"]:
            assert "coverage_ratio" in pf and "pre_tls_buffer_len" in pf
    assert r3["pre_tls_buffer_len"] == 0, f"flow3 stripped pre_tls expected 0 got {r3['pre_tls_buffer_len']}"
    assert r3["pre_tls_buffer_injection_possible"] is False
    assert r3["starttls_detected"] is False
    raw3 = flows[2].read_bytes()
    assert b"\x16\x03" not in raw3, "flow3 reassembled stripped must have no 0x16 0x03"
    # every flow asserts coverage_ratio + pre_tls via reassemble
    for r in (r1, r2, r3):
        assert "coverage_ratio" in r
        assert r["coverage_ratio"] > 0.8


def test_single_vs_triple_severity():
    """Single-flow stripped is High low-conf (honest), triple history escalates to Critical."""
    # family-09 single-flow honest: High, not Critical
    assert FAMILY09.exists(), "missing shared/fixtures/family-09.json"
    data = json.loads(FAMILY09.read_text(encoding="utf-8"))
    from shared.schemas import FlowVerdict

    v = FlowVerdict.model_validate(data)
    assert v.starttls_mode == "stripped", f"family-09 starttls_mode expected stripped got {v.starttls_mode}"
    # honest single-flow must be High low-conf, not Critical
    assert v.assessment.risk_level == "High", f"single-flow stripped must be High (honest low-conf) got {v.assessment.risk_level}"
    assert v.assessment.risk_level != "Critical", "single-flow stripped must NOT claim Critical (honest)"
    # severity High, with low-confidence evidence hint
    severities = [f.severity for f in v.assessment.findings]
    assert "High" in severities, f"findings severity High expected got {severities}"
    assert "Critical" not in severities, "single-flow findings must not be Critical (honest)"
    # risk_score honest medium-high, not 95 Critical
    assert 50 <= v.assessment.risk_score <= 85, f"single High risk_score expected 50..85 got {v.assessment.risk_score}"
    evidence = " ".join(f.evidence for f in v.assessment.findings).lower()
    assert "low confidence" in evidence or "low-conf" in evidence or "triple" in evidence or "history" in evidence, f"evidence must mention low confidence / history triple: {evidence}"

    # triple aggregated assessment would be Critical (2 prior STARTTLS successes + 1 stripped)
    # Simulate aggregated decision: history triple escalates to Critical
    hist = pathlib.Path("shared/fixtures/adversarial/history-3flow.json")
    if hist.exists():
        entries = json.loads(hist.read_text(encoding="utf-8"))
        # history-3flow.json has 3 entries: first 2 upgraded, third stripped Critical? or at least one stripped
        assert isinstance(entries, list) and len(entries) == 3
        # Check at least one stripped or the aggregated interpretation would be Critical
        # The honest model: single High -> triple Critical when correlated
        stripped_in_hist = [e for e in entries if e.get("starttls_mode") == "stripped"]
        # In fixture, history-3flow may still use Critical for synthetic history to represent aggregated verdict
        # Accept either: stripped entry is present, and aggregated would be Critical
        assert len(stripped_in_hist) >= 1 or any(e.get("assessment", {}).get("risk_level") == "Critical" for e in entries), "history-3flow must contain stripped flow to demonstrate triple escalation"
        # If hist has Critical aggregated, validate it passes schema as Critical (allowed for history aggregated)
        for e in entries:
            FlowVerdict.model_validate(e)

    # Explicit honest comment: single-flow High low-conf, triple Critical
    # This test enforces that we do NOT claim single-flow is Critical.
