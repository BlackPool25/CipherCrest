"""shared/coldstorage.py — category formatter + normalizer extracted from assessment/features.py.

T2 8-col freeze: adds FEATURES_VERSION + build_miss_flags single definition.
"""
from __future__ import annotations

import hashlib

FEATURES_VERSION: str = "8-col-honest-v1"


def encode_categorical(name: str, value: object) -> int | float:
    """Deterministic categorical → int code (or -1 for missing).

    XGB with enable_categorical=True expects pandas category dtype;
    for vector build we use integer codes with -1 for missing (XGB missing branch).
    Stable mapping per known values, fallback hash sha256 mod 32.
    """
    if value is None:
        return -1
    s = str(value)
    table: dict[str, dict[str, int]] = {
        "version": {"TLS1.0": 0, "TLS1.1": 1, "TLS1.2": 2, "TLS1.3": 3, "unknown": 4, "none": 4},
        "cipher_strength": {"strong": 0, "medium": 1, "weak": 2, "unknown": 3},
        "kex": {"ECDHE": 0, "RSA": 1, "DHE": 2, "unknown": 3},
        "starttls_mode": {"upgrade": 0, "implicit": 1, "none": 2, "stripped": 3},
        "port": {"25": 0, "587": 1, "993": 2, "465": 3, "995": 4, "143": 5},
        "cert_missing_reason": {"none": 0, "opaque": 1, "missing": 2, "private": 3},
    }
    m = table.get(name)
    if m is not None and s in m:
        return m[s]
    return int(hashlib.sha256(s.encode()).hexdigest()[:8], 16) % 32


def normalize_categorical_code(code: float, mode: str = "xgb") -> float:
    """Normalize categorical code for AE mode 0..1, otherwise raw float."""
    if mode == "ae":
        return float(code) / 32.0 if code != -1 else 0.0
    return float(code)


def normalize_value(name: str, val: object, mode: str = "xgb") -> float:
    """Normalize numeric/bool value, NaN-free, handling ja4_rarity, days_to_expiry, pubkey_bits."""
    if val is None:
        return -1.0 if name not in ("ja4_rarity",) else 0.5
    if isinstance(val, bool):
        return 1.0 if val else 0.0
    if isinstance(val, (int, float)):
        if name == "ja4_rarity":
            return float(max(0.0, min(1.0, float(val))))
        if name == "days_to_expiry":
            if mode == "ae":
                return float(max(0, min(3650, int(val)))) / 3650.0
            return float(val)
        if name == "pubkey_bits":
            return float(val) / 4096.0 if mode == "ae" else float(val)
        return float(val)
    return float(val) if isinstance(val, (int, float)) else 0.0


def build_miss_flags(raw: dict, cert: dict) -> dict[str, int]:
    """Single definition for miss indicators — train/serve parity.

    Args:
        raw: dict with keys chain_valid, san_match, days_to_expiry, pubkey_bits,
             sigalg_weak, chain_length, ja4_rarity (values may be None)
        cert: cert dict for sigalg fallback (cert.get("sigalg"))

    Returns:
        dict of 7 miss_indicator_* -> 0/1
    """
    return {
        "miss_indicator_chain_valid": 1 if raw.get("chain_valid") is None else 0,
        "miss_indicator_san_match": 1 if raw.get("san_match") is None else 0,
        "miss_indicator_days_to_expiry": 1 if raw.get("days_to_expiry") is None else 0,
        "miss_indicator_pubkey_bits": 1 if raw.get("pubkey_bits") is None else 0,
        "miss_indicator_sigalg": 1 if raw.get("sigalg_weak") is None and cert.get("sigalg") is None else 0,
        "miss_indicator_chain_length": 1 if raw.get("chain_length") is None else 0,
        "miss_indicator_ja4_rarity": 1 if raw.get("ja4_rarity") is None else 0,
    }
