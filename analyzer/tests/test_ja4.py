"""JA4 FoxIO GREASE harmonization + offline rarity tests."""
import json
import pathlib

import pytest

from analyzer.jas import analyze_pcap, ALLOWED_RISK_FEATURES
from shared.ja4_rarity import filter_grease, get_ja4_rarity


def test_grease_harmonization():
    """Issue #305: GREASE 0x0a0a filtered before hash → divergence 0 char."""
    from analyzer.jas import _compute_ja4

    base = {"ciphers": [0x1301, 0x1302], "extensions": [0x0000, 0x0010], "groups": [0x0017], "sigalgs": [0x0403], "legacy_ver": 0x0303}
    with_grease = {"ciphers": [0x0A0A, 0x1301, 0x1302], "extensions": [0x0A0A, 0x0000, 0x0010], "groups": [0x0A0A, 0x0017], "sigalgs": [0x0A0A, 0x0403], "legacy_ver": 0x0303}
    ja1 = _compute_ja4(base)
    ja2 = _compute_ja4(with_grease)
    assert ja1 == ja2, f"GREASE not filtered: {ja1} vs {ja2}"
    # direct filter_grease also
    assert filter_grease([0x0A0A, 0x1301]) == [0x1301]
    assert filter_grease([0x0A0A]) == []


def test_ja4_present_all_flows():
    for p in sorted(pathlib.Path("lab/pcaps").glob("family-*.pcap")):
        res = analyze_pcap(p)
        if "09" in p.name:
            assert res["ja4"] is None, f"{p} should have no JA4 (stripped)"
        else:
            assert res["ja4"] is not None, f"{p} JA4 missing"
            assert "_" in res["ja4"]
            assert res["ja4"].startswith("t")


def test_rarity_range_and_unknown():
    # unknown → None not 0
    assert get_ja4_rarity("t13d1516h2_deadbeefdead_ffffffffffff") is None
    assert get_ja4_rarity("") is None
    # known chrome JA4 from bundle
    data = json.loads(pathlib.Path("shared/data/censys_top_ja4.json").read_text())
    key = "t13d1516h2_8daaf6152771_e5627efa2ab1"
    assert key in data["ja4"]
    rarity = get_ja4_rarity(key)
    assert rarity is not None and 0 <= rarity <= 1
    assert abs(rarity - (1 - data["ja4"][key])) < 1e-9


def test_whitelist():
    assert "ja4" not in ALLOWED_RISK_FEATURES
    assert "ja4_rarity" in ALLOWED_RISK_FEATURES


def test_offline_rarity_via_pcap():
    res = analyze_pcap(pathlib.Path("lab/pcaps/family-01.pcap"))
    # rarity may be None for synthetic JA4, but if not None must be 0..1
    if res["ja4_rarity"] is not None:
        assert 0 <= res["ja4_rarity"] <= 1
    # raw ja4 should produce None rarity for synthetic
    assert get_ja4_rarity(res["ja4"]) is None or 0 <= get_ja4_rarity(res["ja4"]) <= 1  # type: ignore


def test_ja4s_emitted():
    res = analyze_pcap(pathlib.Path("lab/pcaps/family-01.pcap"))
    assert "ja4s" in res
    assert "ja4s" in res["tls"]

def test_early_data_ech_fields():
    import subprocess, sys, json
    out = subprocess.run([sys.executable, "-m", "analyzer.parse", "lab/pcaps/family-01.pcap", "--json"], capture_output=True, text=True, timeout=5)
    d = json.loads(out.stdout)
    assert "early_data_offered" in d["tls"]
    assert "ech_outer_present" in d["tls"]
    assert isinstance(d["tls"]["early_data_offered"], bool)
    assert isinstance(d["tls"]["ech_outer_present"], bool)

def test_rarity_span_fixtures():
    import json, glob
    from shared.schemas import FlowVerdict
    for p in glob.glob("shared/fixtures/family-*.json"):
        v = FlowVerdict.model_validate_json(open(p).read())
        if v.tls.ja4_rarity is not None:
            assert 0 <= v.tls.ja4_rarity <= 1, f"{p} rarity {v.tls.ja4_rarity}"
