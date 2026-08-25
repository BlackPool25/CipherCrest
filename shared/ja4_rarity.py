"""Offline JA4 rarity helper — Censys 1B top-1000 stub bundle.

MUST NOT call ja4db.com live. MUST NOT feed raw ja4 to risk model — only rarity.
JA4 table stores normalized JA4 after GREASE filtering; rarity = 1 - percentile (freq).
FoxIO technical_details §4 + issue #305: GREASE MUST be stripped before JA4 hash.
"""
from __future__ import annotations

import json
import pathlib
from functools import lru_cache

# GREASE values per RFC 8701: 0x0a0a, 0x1a1a, ..., 0xfafa — exactly 16 values.
# MUST NOT invent beyond RFC8701 — see RFC 8701 section 3.1
GREASE_VALUES: frozenset[int] = frozenset(
    {
        0x0A0A,
        0x1A1A,
        0x2A2A,
        0x3A3A,
        0x4A4A,
        0x5A5A,
        0x6A6A,
        0x7A7A,
        0x8A8A,
        0x9A9A,
        0xAAAA,
        0xBABA,
        0xCACA,
        0xDADA,
        0xEAEA,
        0xFAFA,
    }
)

# Whitelist guard: raw JA4 hash is spoofable (curl-cffi impersonate=chrome131)
# and MUST NEVER be an ML feature. Only numeric ja4_rarity (0..1) is allowed.
ALLOWED_RISK_FEATURES: frozenset[str] = frozenset(
    {
        "cipher_strength",
        "kex",
        "fs_flag",
        "pubkey_bits",
        "sigalg_weak",
        "days_to_expiry",
        "chain_valid",
        "ja4_rarity",
        "chain_depth",
        "san_match",
        "starttls_mode",
        "port",
        "cert_missing_reason",
        "miss_indicator_*",
    }
)

# Hard guard: fail fast if raw ja4 leaks into feature whitelist
assert "ja4" not in ALLOWED_RISK_FEATURES, "raw ja4 MUST NOT be in ALLOWED_RISK_FEATURES"
assert "ja4_rarity" in ALLOWED_RISK_FEATURES, "ja4_rarity must be whitelisted"

_TABLE_PATH = pathlib.Path(__file__).parent / "data" / "censys_top_ja4.json"


@lru_cache(maxsize=1)
def _load_table() -> dict:
    """Load offline bundle (cached). No network — offline violation if fetched live."""
    p = _TABLE_PATH
    if not p.exists():
        return {"ja4": {}, "meta": {}}
    data = json.loads(p.read_text(encoding="utf-8"))
    return data


def filter_grease(values: list[int]) -> list[int]:
    """Strip GREASE ciphers/extensions (0x0a0a etc) before JA4 hash — FoxIO harmonization."""
    return [v for v in values if v not in GREASE_VALUES]


def get_ja4_rarity(ja4: str) -> float | None:
    """Offline rarity lookup.

    Args:
        ja4: normalized JA4 string (already GREASE-filtered if produced via analyzer).

    Returns:
        float 0..1 rarity = 1 - percentile (freq) for known JA4, None for unknown.
        Never fetches live — returns None if not in offline table.
    """
    if not ja4 or not isinstance(ja4, str):
        return None
    table = _load_table()
    ja4_map: dict[str, float] = table.get("ja4", {})
    freq = ja4_map.get(ja4)
    if freq is None:
        return None
    # rarity = 1 - percentile (freq is percentile-like 0..1)
    rarity = 1.0 - float(freq)
    # clamp 0..1
    if rarity < 0:
        rarity = 0.0
    if rarity > 1:
        rarity = 1.0
    return rarity


def clear_cache() -> None:
    """Test helper to clear lru cache after fixture table regeneration."""
    _load_table.cache_clear()
