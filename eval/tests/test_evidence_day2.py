"""Task 16 — eval/EVIDENCE_Day2.md handoff gate.

Must contain sha256 table 10 rows + coverage_ratio table + handoff marker.
Also validates progress.md next line and fallback replay POST /analyze.
"""
from __future__ import annotations

import hashlib
import re
import sys, pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

EVIDENCE = pathlib.Path("eval/EVIDENCE_Day2.md")
PROGRESS = pathlib.Path("shared/progress.md")
SCHEMAS = pathlib.Path("shared/schemas.json")


def test_sha256_table_10_rows() -> None:
    """EVIDENCE must contain 10 sha256 hashes (family-*.pcap) and coverage_ratio table."""
    assert EVIDENCE.exists(), "eval/EVIDENCE_Day2.md missing"
    text = EVIDENCE.read_text()
    assert len(text.splitlines()) >= 50, f"EVIDENCE too short {len(text.splitlines())} <50"

    # Count sha256 hashes (64 hex chars) — at least 10
    sha256s = re.findall(r"[0-9a-f]{64}", text)
    assert len(sha256s) >= 10, f"expected >=10 sha256 hashes, got {len(sha256s)}"

    # Must mention at least 10 family pcap names in sha256 section
    pcap_mentions = re.findall(r"family-\d{2}\.pcap", text)
    assert len(pcap_mentions) >= 10, f"expected >=10 pcap mentions, got {len(pcap_mentions)}: {pcap_mentions[:5]}"

    # coverage_ratio table: must contain coverage_ratio + per-family rows
    assert "coverage_ratio" in text, "missing coverage_ratio"
    assert "reassembly_coverage_ratio" in text or "coverage_ratio" in text
    # Count family rows in coverage table — look for lines with | 01 | or family-01.pcap
    coverage_rows = [ln for ln in text.splitlines() if "family-" in ln and ("1.0" in ln or "0.897" in ln)]
    assert len(coverage_rows) >= 10, f"expected >=10 coverage rows, got {len(coverage_rows)}"

    # jittered 0.897 row must exist (honest <1)
    assert "0.897" in text, "missing jittered 0.897 row"
    assert "jittered" in text.lower(), "missing jittered mention"

    # STARTTLS badge
    assert "STARTTLS" in text and "F1" in text, "missing STARTTLS F1 badge"
    assert "95%" in text or "F1>95" in text or "F1 100" in text, "missing F1>95% proof"

    # schemas hash
    assert "schemas.json" in text, "missing schemas.json hash"
    assert "FlowVerdict" in text, "missing FlowVerdict title"
    assert "$defs" in text or "defs" in text, "missing $defs"

    # bundle gz size
    assert "155503" in text or "gzip" in text.lower(), "missing bundle gz size"
    assert "3670016" in text or "3.5" in text, "missing bundle limit"

    # handoff marker inside EVIDENCE itself
    assert "Next: Day3 USE_STUB=False when reassembled/*.bin 🟢" in text, "missing handoff marker in EVIDENCE"

    # Cross-check real sha256 for family-01 matches evidence
    real = hashlib.sha256(pathlib.Path("lab/pcaps/family-01.pcap").read_bytes()).hexdigest()
    assert real in text, f"real family-01 sha256 {real} not in EVIDENCE"


def test_progress_handoff_line() -> None:
    """shared/progress.md must contain Day2 handoff line with Next: Day3 USE_STUB=False ..."""
    assert PROGRESS.exists()
    text = PROGRESS.read_text()
    assert "Next: Day3 USE_STUB=False when reassembled/*.bin 🟢" in text
    assert "Day2 handoff" in text
    assert "🟢 gated" in text


def test_replay_fallback_post_analyze() -> None:
    """POST /analyze fallback replay must return 200 without docker."""
    from fastapi.testclient import TestClient

    from api.app import app

    pcaps = list(pathlib.Path("lab/pcaps").glob("*.pcap"))
    assert pcaps, "no pcaps"
    c = TestClient(app)
    r = c.post("/analyze", files={"pcap": (pcaps[0].name, open(pcaps[0], "rb"), "application/vnd.tcpdump")})  # noqa: SIM115
    assert r.status_code == 200, f"/analyze failed {r.status_code} {r.text[:500]}"
    data = r.json()
    assert isinstance(data, list) and len(data) >= 1
    # validate via FlowVerdict shape
    assert "flow_id" in data[0]
    assert "tls" in data[0]
