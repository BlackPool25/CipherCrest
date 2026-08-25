"""GREASE filter MUST strip 0x0a0a etc before JA4 hash — FoxIO harmonization."""

from shared.ja4_rarity import GREASE_VALUES, filter_grease


def test_grease_filter():
    # Single GREASE value must be stripped
    assert filter_grease([0x0A0A, 0x1301]) == [0x1301]
    assert filter_grease([0x0A0A]) == []
    assert filter_grease([0x1301, 0x1302]) == [0x1301, 0x1302]
    # All 16 GREASE values filtered
    all_grease = list(GREASE_VALUES)
    assert filter_grease(all_grease) == []
    # Mixed
    mixed = [0x0A0A, 0x1301, 0x1A1A, 0x1302, 0xFAFA, 0x1303]
    assert filter_grease(mixed) == [0x1301, 0x1302, 0x1303]
    # Empty
    assert filter_grease([]) == []
    # Named values per spec
    assert 0x0A0A in GREASE_VALUES
    assert 0xFAFA in GREASE_VALUES
    assert 0x1301 not in GREASE_VALUES
