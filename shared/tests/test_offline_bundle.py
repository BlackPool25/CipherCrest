"""Offline bundle Day1 slice — schemas.json exists + valid + no weberblog early."""
from __future__ import annotations

import glob
import json
import pathlib


def test_schemas_json_exists():
    """shared/schemas.json exists and jq empty valid (json.load succeeds)."""
    p = pathlib.Path("shared/schemas.json")
    assert p.exists(), "shared/schemas.json missing — run shared/scripts/gen_schemas_json.py"
    # jq empty equivalent: json.load must succeed without error
    data = json.loads(p.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert data.get("title") == "FlowVerdict"
    assert "$defs" in data
    # Also assert valid JSON via file size sanity
    assert p.stat().st_size > 100, "schemas.json suspiciously small"


def test_no_weberblog_early():
    """Day1 guard: no lab/pcaps/real/*.pcap — weberblog is Day10+, enforce ! test -f."""
    # Use glob to avoid pathlib Path with glob pattern false negative; check both forms
    matches = glob.glob("lab/pcaps/real/*.pcap")
    assert matches == [], f"weberblog early creep — found {matches} but Day1 must have none"
    # Also ensure path does not exist as literal file with asterisk (edge case from bash -c test)
    assert not pathlib.Path("lab/pcaps/real").exists() or matches == [], "lab/pcaps/real should not contain pcaps on Day1"
    # Offline bundle auxiliary: shared/data/censys_top_ja4.json may not exist yet Day1; don't hard fail but check if present then valid
    censys = pathlib.Path("shared/data/censys_top_ja4.json")
    if censys.exists():
        data = json.loads(censys.read_text(encoding="utf-8"))
        assert isinstance(data, dict)
        # If censys exists, jq empty already proven; count sanity
        assert len(str(data)) > 10

    # schemas.json must still be present even Wi-Fi-off (offline bundle core)
    assert pathlib.Path("shared/schemas.json").exists()


def test_schemas_json_jq_empty_valid():
    """Explicit jq empty check: file is valid JSON and not truncated."""
    import subprocess
    p = pathlib.Path("shared/schemas.json")
    assert p.exists()
    # Python json.load is the jq empty equivalent; also try jq if available
    try:
        result = subprocess.run(["jq", "empty", str(p)], capture_output=True, timeout=5, check=False)
        assert result.returncode == 0, f"jq empty failed: {result.stderr.decode()}"
    except FileNotFoundError:
        # jq not installed in minimal container — python validation suffices
        json.loads(p.read_text(encoding="utf-8"))
