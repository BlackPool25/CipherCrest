"""Task 4 — JA4 rarity offline lookup."""
from __future__ import annotations

import json
import pathlib


def test_known_returns_rarity():
    from shared.ja4_rarity import get_ja4_rarity

    # load actual freq from json to compute expected rarity = 1 - freq
    data = json.loads(pathlib.Path("shared/data/censys_top_ja4.json").read_text(encoding="utf-8"))
    key = "t13d1516h2_8daaf6152771_e5627efa2ab1"
    assert key in data["ja4"], "chrome JA4 must exist in offline bundle"
    freq = data["ja4"][key]
    v = get_ja4_rarity(key)
    assert v is not None
    assert 0 <= v <= 1
    assert abs(v - (1 - freq)) < 1e-9, f"rarity {v} != 1 - freq {1-freq}"


def test_unknown_returns_none():
    from shared.ja4_rarity import get_ja4_rarity

    v = get_ja4_rarity("t13d1516h2_deadbeefdead_ffffffffffff")
    assert v is None

    v2 = get_ja4_rarity("")
    assert v2 is None

    v3 = get_ja4_rarity("not-a-ja4")
    assert v3 is None


def test_rarity_range_all_known():
    import json
    import pathlib

    from shared.ja4_rarity import get_ja4_rarity

    data = json.loads(pathlib.Path("shared/data/censys_top_ja4.json").read_text(encoding="utf-8"))
    for k, freq in data["ja4"].items():
        v = get_ja4_rarity(k)
        assert v is not None
        assert 0 <= v <= 1, f"{k} rarity out of range {v}"
        assert abs(v - (1 - freq)) < 1e-9
