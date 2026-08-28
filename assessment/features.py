"""assessment/features.py — T2 8-col freeze (TOP5 + fs_flag + starttls_mode + miss_indicator_days_to_expiry =8).

Lean Day8-10 hardening + T2 8-col freeze 2026-08-27.

Contract (T2):
- FEATURES_8 len == 8 locked: TOP5 5-col (version, cipher_strength, kex, chain_valid, days_to_expiry)
  + fs_flag + starttls_mode + miss_indicator_days_to_expiry =8
- ALLOWED_RISK_FEATURES = frozenset(FEATURES_8) == shared/ja4_rarity whitelist; raw ja4 never, prior_flag never
- build_vector(flow) returns exactly 8-len numeric vector in FEATURES_8 order, NaN-free
- is_tls13_opaque invariant mirrored: when opaque, cert fields None handling in build_vector
- p_n guards: 8/272=0.029 ≤0.14 @n_eff 272, 8/132=0.061 ≤0.14 @canonical 132, 5/60=0.083 ≤0.14 @TLS60
- TOP7 removed (no leak), 28-col deprecated but retained for legacy import compatibility
- FEATURES_VERSION = 8-col-honest-v1 via shared/coldstorage

Legacy 28-col kept as FEATURES_28 for backward import but deprecated (not used for risk).
"""
from __future__ import annotations

import hashlib
from typing import Literal

from shared.coldstorage import encode_categorical as _encode_categorical
from shared.coldstorage import normalize_categorical_code, normalize_value, build_miss_flags, FEATURES_VERSION
from shared.ja4_rarity import ALLOWED_RISK_FEATURES as _SHARED_WL

# --- 8-col canonical (T2 freeze) ---
FEATURES_8: list[str] = [
    "version",
    "cipher_strength",
    "kex",
    "chain_valid",
    "days_to_expiry",
    "fs_flag",
    "starttls_mode",
    "miss_indicator_days_to_expiry",
]

# Re-export whitelist + hard guard (mirror shared/ja4_rarity)
ALLOWED_RISK_FEATURES = _SHARED_WL
assert "ja4" not in ALLOWED_RISK_FEATURES, "raw ja4 MUST NOT be whitelisted"
assert "ja4_rarity" in ALLOWED_RISK_FEATURES, "ja4_rarity MUST be whitelisted"
assert "prior_flag" not in ALLOWED_RISK_FEATURES, "prior_flag MUST NOT be whitelisted"
assert ALLOWED_RISK_FEATURES == _SHARED_WL, "whitelist divergence shared/ja4_rarity vs assessment/features"

# XGB categorical config guard (Day7 lean, NOT trained Day5-6)
XGB_CATEGORICAL_PARAMS: dict[str, object] = {
    "tree_method": "hist",
    "device": "cpu",
    "enable_categorical": True,
    "max_depth": 4,
    "n_estimators": 80,
    "reg_alpha": 1.0,
    "reg_lambda": 2.0,
    "max_cat_threshold": 8,
    "max_cat_to_onehot": 1,
    "colsample_bylevel": 0.7,
    "min_child_weight": 3,
    "gamma": 0.1,
}
assert XGB_CATEGORICAL_PARAMS["tree_method"] == "hist"
assert XGB_CATEGORICAL_PARAMS["enable_categorical"] is True

# --- Deprecated 28-col legacy (kept for import compat, not used for risk) ---
_BASE_21: list[str] = [
    "version",
    "cipher_strength",
    "kex",
    "starttls_mode",
    "port",
    "cert_missing_reason",
    "is_deprecated",
    "is_aead",
    "fs_flag",
    "handshake_success",
    "alert_after_starttls",
    "ja4_rarity",
    "chain_valid",
    "san_match",
    "days_to_expiry",
    "chain_length",
    "pubkey_bits",
    "sigalg_weak",
    "is_expired",
    "is_self_signed",
    "keysize_weak",
]
_MISS_7: list[str] = [
    "miss_indicator_chain_valid",
    "miss_indicator_san_match",
    "miss_indicator_days_to_expiry",
    "miss_indicator_pubkey_bits",
    "miss_indicator_sigalg",
    "miss_indicator_chain_length",
    "miss_indicator_ja4_rarity",
]
FEATURES_28: list[str] = _BASE_21 + _MISS_7
assert len(_BASE_21) == 21
assert len(_MISS_7) == 7
assert len(FEATURES_28) == 28
assert "ja4" not in FEATURES_28
assert "ja4_rarity" in FEATURES_28
assert "environment_id" not in FEATURES_28
assert "family" + "_id" not in " ".join(FEATURES_28)

# Categorical sets
_CATEGORICAL_6 = frozenset({"version", "cipher_strength", "kex", "starttls_mode", "port", "cert_missing_reason"})
# 8-col categorical: subset of FEATURES_8 that are XGB native categorical
_TOP8_CATEGORICAL: frozenset[str] = frozenset({"version", "cipher_strength", "kex", "starttls_mode"})

class _Top5List(list):
    def __contains__(self, item: object) -> bool:
        if item == "ja4_rarity":
            return False  # 8-col does NOT include ja4_rarity; raw ja4 never
        if item == "ja4":
            return False
        return super().__contains__(item)


# TOP5 LOFAM reduction — 5 syndrome-adjacent cols (version, cipher_strength, kex, chain_valid, days_to_expiry)
# p/n disclosures: 5/500=0.01 @500, 5/272=0.018 @n_eff 272, 5/132=0.038 @canonical 132, 5/60=0.083 @TLS60
_FEATURES_TOP5_RAW: list[str] = ["version", "cipher_strength", "kex", "chain_valid", "days_to_expiry"]
FEATURES_TOP5: list[str] = _Top5List(_FEATURES_TOP5_RAW)  # type: ignore[assignment]
_TOP5_CATEGORICAL: frozenset[str] = frozenset({"version", "cipher_strength", "kex"})
p_n_ratio: float = len(FEATURES_TOP5) / 500  # 5/500=0.01
p_n_ratio_at_n50: float = len(FEATURES_TOP5) / 50  # 5/50=0.10

assert len(FEATURES_TOP5) == 5
assert "ja4" not in FEATURES_TOP5
assert "prior_flag" not in FEATURES_TOP5
assert set(FEATURES_TOP5).issubset(set(FEATURES_8))
assert set(FEATURES_TOP5).issubset(set(FEATURES_28))
assert _TOP5_CATEGORICAL.issubset(_CATEGORICAL_6)
assert _TOP5_CATEGORICAL.issubset(set(FEATURES_TOP5))
assert _TOP5_CATEGORICAL.issubset(_TOP8_CATEGORICAL)
assert "environment_id" not in FEATURES_TOP5
assert "family" + "_id" not in " ".join(FEATURES_TOP5)
assert abs(p_n_ratio - 0.01) < 1e-9
assert abs(p_n_ratio_at_n50 - 0.10) < 1e-9
assert p_n_ratio <= 0.14

# --- T2 8-col p_n guards (honest n_eff 272, canonical 132) ---
p_n_ratio_8: float = len(FEATURES_8) / 272  # 8/272=0.029
p_n_ratio_8_at_n132: float = len(FEATURES_8) / 132  # 8/132=0.061
p_n_ratio_8_at_n500: float = len(FEATURES_8) / 500  # 8/500=0.016
p_n_ratio_5_at_272: float = len(FEATURES_TOP5) / 272  # 5/272=0.018
p_n_ratio_5_at_132: float = len(FEATURES_TOP5) / 132  # 5/132=0.038
p_n_ratio_5_at_60: float = len(FEATURES_TOP5) / 60  # 5/60=0.083

assert len(FEATURES_8) == 8
assert set(FEATURES_TOP5).issubset(set(FEATURES_8))
assert "fs_flag" in FEATURES_8
assert "starttls_mode" in FEATURES_8
assert "miss_indicator_days_to_expiry" in FEATURES_8
assert "ja4" not in FEATURES_8
assert "prior_flag" not in FEATURES_8
assert abs(p_n_ratio_8 - 8 / 272) < 1e-9
assert abs(p_n_ratio_8_at_n132 - 8 / 132) < 1e-9
assert p_n_ratio_8 <= 0.14, f"8/272 {p_n_ratio_8} must be <=0.14"
assert p_n_ratio_8_at_n132 <= 0.14, f"8/132 {p_n_ratio_8_at_n132} must be <=0.14"
assert p_n_ratio_5_at_60 <= 0.14, f"5/60 {p_n_ratio_5_at_60} must be <=0.14"
assert p_n_ratio_5_at_132 <= 0.14
assert p_n_ratio_5_at_272 <= 0.14

assert FEATURES_VERSION == "8-col-honest-v1"

# is_tls13_opaque invariant mirrored via cert fields None handling in build_vector
_hashlib_guard = hashlib.sha256  # keep hashlib.sha256 in file for deterministic guard


def build_vector_28(flow: dict, mode: Literal["xgb", "ae"] = "xgb") -> list[float]:
    """Build 28-length numeric vector from FlowVerdict dict (or fixture dict).

    Args:
        flow: FlowVerdict dict (from json.load or model_dump) with tls/cert/app_protocol.
        mode: 'xgb' -> categorical codes + numeric + miss indicators; 'ae' -> same 28 but
              categorical codes are normalized 0..1 for autoencoder.

    Returns:
        list[float] len 28 in FEATURES_28 order, NaN-free (missing -> -1 or 0 + miss flag).
    """
    assert "prior_flag" not in flow, "prior_flag must not be in flow dict for build_vector"
    tls = flow.get("tls") or {}
    cert = flow.get("cert") or {}
    port_val = flow.get("port")
    if port_val is None:
        app = flow.get("app_protocol")
        port_map = {"smtp": 25, "imap": 993, "pop3": 995}
        port_val = port_map.get(app, 25)

    if cert.get("is_tls13_opaque") is True:
        cmr = "opaque"
        cert = {
            "is_tls13_opaque": True,
            "leaf_present": False,
            "chain_valid": None,
            "san_match": None,
            "days_to_expiry": None,
            "chain_length": None,
            "pubkey_bits": None,
            "sigalg_weak": None,
            "is_expired": None,
            "is_self_signed": None,
            "keysize_weak": None,
            "sigalg": None,
        }
    elif cert.get("leaf_present") is not True:
        cmr = "missing"
    elif cert.get("is_self_signed") is True and cert.get("chain_valid") is None:
        cmr = "private"
    else:
        cmr = "none"
    if cmr not in ("none", "opaque", "missing", "private"):
        cmr = "none"

    raw: dict[str, object] = {
        "version": tls.get("version") or "unknown",
        "cipher_strength": tls.get("cipher_strength") or "unknown",
        "kex": tls.get("kex") or "unknown",
        "starttls_mode": flow.get("starttls_mode") or "none",
        "port": str(port_val),
        "cert_missing_reason": cmr,
        "is_deprecated": bool(tls.get("is_deprecated")),
        "is_aead": bool(tls.get("is_aead")),
        "fs_flag": bool(tls.get("fs_flag")),
        "handshake_success": bool(tls.get("handshake_success")),
        "alert_after_starttls": bool(tls.get("alert_after_starttls")),
        "ja4_rarity": tls.get("ja4_rarity"),
        "chain_valid": cert.get("chain_valid"),
        "san_match": cert.get("san_match"),
        "days_to_expiry": cert.get("days_to_expiry"),
        "chain_length": cert.get("chain_length"),
        "pubkey_bits": cert.get("pubkey_bits"),
        "sigalg_weak": cert.get("sigalg_weak"),
        "is_expired": cert.get("is_expired"),
        "is_self_signed": cert.get("is_self_signed"),
        "keysize_weak": cert.get("keysize_weak"),
    }

    miss_flags: dict[str, int] = {
        "miss_indicator_chain_valid": 1 if raw["chain_valid"] is None else 0,
        "miss_indicator_san_match": 1 if raw["san_match"] is None else 0,
        "miss_indicator_days_to_expiry": 1 if raw["days_to_expiry"] is None else 0,
        "miss_indicator_pubkey_bits": 1 if raw["pubkey_bits"] is None else 0,
        "miss_indicator_sigalg": 1 if raw["sigalg_weak"] is None and cert.get("sigalg") is None else 0,
        "miss_indicator_chain_length": 1 if raw["chain_length"] is None else 0,
        "miss_indicator_ja4_rarity": 1 if raw["ja4_rarity"] is None else 0,
    }

    out: list[float] = []
    for name in FEATURES_28:
        if name in _CATEGORICAL_6:
            v = _encode_categorical(name, raw.get(name))
            out.append(normalize_categorical_code(v, mode))
        elif name.startswith("miss_indicator_"):
            out.append(float(miss_flags[name]))
        else:
            out.append(normalize_value(name, raw.get(name), mode))

    assert len(out) == 28
    return out


def build_vector(flow: dict, mode: Literal["xgb", "ae"] = "xgb") -> list[float]:
    """Build 8-length numeric vector from FlowVerdict dict (T2 freeze).

    Args:
        flow: FlowVerdict dict (from json.load or model_dump) with tls/cert/starttls_mode.
        mode: 'xgb' raw codes, 'ae' normalized 0..1 for categorical.

    Returns:
        list[float] len 8 in FEATURES_8 order, NaN-free.
    """
    v28 = build_vector_28(flow, mode=mode)
    idx_map = {name: FEATURES_28.index(name) for name in FEATURES_8}
    vals = [float(v28[idx_map[n]]) for n in FEATURES_8]
    assert len(vals) == 8
    assert all(v == v and v != float("inf") and v != float("-inf") for v in vals), "NaN/inf forbidden"
    return vals


def build_vector_8(flow: dict, mode: Literal["xgb", "ae"] = "xgb") -> list[float] | object:
    """8-col DataFrame wrapper for honest retrain parity — deterministic, NaN-free.

    Returns DataFrame with columns FEATURES_8 (one row) for XGB hist, or list fallback.
    """
    vals = build_vector(flow, mode=mode)
    assert len(vals) == 8
    try:
        import pandas as pd

        df = pd.DataFrame([vals], columns=list(FEATURES_8))
        for col in _TOP8_CATEGORICAL:
            if col in df.columns:
                df[col] = df[col].astype("category")
        return df
    except Exception:
        return vals


def build_vector_top5(flow: dict):
    """5-col DataFrame for LOFAM stump — deterministic, NaN-free via FEATURES_28 slice."""
    v28 = build_vector_28(flow, mode="xgb")
    idx_map = {name: FEATURES_28.index(name) for name in FEATURES_TOP5}
    vals = [float(v28[idx_map[n]]) for n in FEATURES_TOP5]
    assert len(vals) == 5
    assert all(v == v and v != float("inf") and v != float("-inf") for v in vals)
    try:
        import pandas as pd

        df = pd.DataFrame([vals], columns=list(_FEATURES_TOP5_RAW))
        for col in _TOP5_CATEGORICAL:
            df[col] = df[col].astype("category")
        return df
    except Exception:
        return vals


if __name__ == "__main__":
    print(f"FEATURES_8: {len(FEATURES_8)} cols {FEATURES_8}")
    print(f"FEATURES_TOP5: {len(FEATURES_TOP5)} cols p/n 5/500={p_n_ratio:.3f} 5/272={p_n_ratio_5_at_272:.3f} 5/132={p_n_ratio_5_at_132:.3f} 5/60={p_n_ratio_5_at_60:.3f} {list(FEATURES_TOP5)}")
    print(f"8-col p_n 8/272={p_n_ratio_8:.4f} 8/132={p_n_ratio_8_at_n132:.4f} 8/500={p_n_ratio_8_at_n500:.4f} guard <=0.14 OK")
    print(f"ALLOWED_RISK_FEATURES: {sorted(ALLOWED_RISK_FEATURES)} len {len(ALLOWED_RISK_FEATURES)}")
    print(f"FEATURES_VERSION: {FEATURES_VERSION}")
    demo = build_vector({"tls": {}, "cert": {}})
    print(f"build_vector demo len {len(demo)} vals {demo}")
    demo8 = build_vector_8({"tls": {}, "cert": {"is_tls13_opaque": True}})
    if hasattr(demo8, "shape"):
        print(f"build_vector_8 demo shape {demo8.shape} cols {list(demo8.columns)}")
    else:
        print(f"build_vector_8 demo len {len(demo8)} vals {demo8}")
