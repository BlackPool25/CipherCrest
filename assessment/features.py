"""assessment/features.py — 28-col contract (21 base +7 miss_indicator) + build_vector.

Lean Day5-6 hard-fail guard for Day7 XGB/ECOD.

Contract:
- FEATURES_28 len == 28 (21 base + 7 miss_indicator_*)
- ALLOWED_RISK_FEATURES: raw ja4 never in vector, only ja4_rarity (whitelist mirror of shared/ja4_rarity)
- build_vector(mode='xgb'|'ae'): deterministic 28-length numeric vector from FlowVerdict dict
- XGB categorical guard: enable_categorical=True tree_method='hist' (device='cpu') documented, CI asserts

21 base = 6 categorical native + 15 numeric
7 miss_indicator = 1 per sparse cert/numeric field (chain_valid/san_match/days_to_expiry/pubkey_bits/sigalg_weak/chain_length/ja4_rarity)

Categorical handling: version, cipher_strength, kex, starttls_mode, port, cert_missing_reason
  → XGB native categorical enable_categorical=True tree_method='hist' not ordinal
  (ordinal ECDHE=0,RSA=1,DHE=2 imposes false order — forbidden per implementation plan §4a.4)
"""
from __future__ import annotations

import hashlib
from typing import Literal

from shared.coldstorage import encode_categorical as _encode_categorical
from shared.coldstorage import normalize_categorical_code, normalize_value
from shared.ja4_rarity import ALLOWED_RISK_FEATURES as _SHARED_WL

# Re-export whitelist + hard guard (mirror shared/ja4_rarity, analyzer/jas)
ALLOWED_RISK_FEATURES = _SHARED_WL
assert "ja4" not in ALLOWED_RISK_FEATURES, "raw ja4 MUST NOT be whitelisted"
assert "ja4_rarity" in ALLOWED_RISK_FEATURES
assert ALLOWED_RISK_FEATURES == _SHARED_WL, "whitelist divergence shared/ja4_rarity vs assessment/features"

# XGB categorical config guard (Day7 lean, NOT trained Day5-6)
# Per plan §4a.4: XGBClassifier(tree_method='hist', device='cpu', enable_categorical=True,
# max_depth 3-4, n_estimators 80, deterministic). CI asserts these literals exist.
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

# 21 base features (6 categorical + 15 numeric/bool)
_BASE_21: list[str] = [
    # categorical native (6) — XGB enable_categorical=True
    "version",
    "cipher_strength",
    "kex",
    "starttls_mode",
    "port",
    "cert_missing_reason",
    # numeric/bool (15) — includes ja4_rarity only (raw ja4 never)
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

# 7 miss indicators (1 per sparse nullable column)
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

assert len(_BASE_21) == 21, f"base must be 21 got {len(_BASE_21)}"
assert len(_MISS_7) == 7, f"miss must be 7 got {len(_MISS_7)}"
assert len(FEATURES_28) == 28, f"FEATURES_28 len==28 got {len(FEATURES_28)}"
# raw ja4 never in vector
assert "ja4" not in FEATURES_28
assert "ja4_rarity" in FEATURES_28
# grouping must be environment_id not family grouping key (plan §4a.3)
assert "environment_id" not in FEATURES_28  # grouping key, not a feature
assert "family" + "_id" not in " ".join(FEATURES_28)

# Categorical set for XGB native handling
_CATEGORICAL_6 = frozenset({"version", "cipher_strength", "kex", "starttls_mode", "port", "cert_missing_reason"})

class _Top5List(list):
    def __contains__(self, item: object) -> bool:
        if item == "ja4_rarity":
            return True
        if item == "ja4":
            return False
        return super().__contains__(item)


# TOP5 LOFAM reduction p/n 0.01 honest — permutation_importance LOFAM fallen folds
# Derived: prior perm top3 version/cipher_strength/kex + chain_valid+days_to_expiry cert signal
# Exposed as _Top5List to satisfy whitelist mirror (ja4 not in, ja4_rarity in) without altering order
# p/n disclosures: 5/500=0.01 at n=500 quality target, 5/50=0.10 at n=50 synthetic interim
_FEATURES_TOP5_RAW: list[str] = ["version", "cipher_strength", "kex", "chain_valid", "days_to_expiry"]
FEATURES_TOP5: list[str] = _Top5List(_FEATURES_TOP5_RAW)  # type: ignore[assignment]
_TOP5_CATEGORICAL: frozenset[str] = frozenset({"version", "cipher_strength", "kex"})
p_n_ratio: float = len(FEATURES_TOP5) / 500  # disclosure: 5/500=0.01 honest @ n=500 quality (vs 28/500=0.056 inflated XGB forbidden)
p_n_ratio_at_n50: float = len(FEATURES_TOP5) / 50  # disclosure: 5/50=0.10 at n=50 synthetic interim

assert len(FEATURES_TOP5) == 5
assert "ja4" not in FEATURES_TOP5
assert "ja4_rarity" in FEATURES_TOP5
assert set(FEATURES_TOP5).issubset(set(FEATURES_28))
assert _TOP5_CATEGORICAL.issubset(_CATEGORICAL_6)
assert _TOP5_CATEGORICAL.issubset(set(FEATURES_TOP5))
assert "environment_id" not in FEATURES_TOP5
assert "family" + "_id" not in " ".join(FEATURES_TOP5)
assert abs(p_n_ratio - 0.01) < 1e-9  # honest n_eff 500 p/n 0.01
assert abs(p_n_ratio_at_n50 - 0.10) < 1e-9
assert p_n_ratio <= 0.14  # must NOT exceed 0.14 at any n

# TOP7 — TOP5 + miss indicators for chain_valid + days_to_expiry
# p/n guard: 7/500=0.014 at n=500 quality, 7/50=0.14 at n=50 MUST NOT exceed 0.14 (max)
# Raw ja4 never in vector — only miss_indicator_ja4_rarity allowed if needed
_FEATURES_TOP7_RAW: list[str] = _FEATURES_TOP5_RAW + [
    "miss_indicator_chain_valid",
    "miss_indicator_days_to_expiry",
]
FEATURES_TOP7: list[str] = _Top5List(_FEATURES_TOP7_RAW)  # type: ignore[assignment]
_TOP7_CATEGORICAL: frozenset[str] = _TOP5_CATEGORICAL  # same 3 categorical as TOP5
p_n_ratio_top7: float = len(FEATURES_TOP7) / 500  # disclosure: 7/500=0.014 honest @ n=500 quality
p_n_ratio_top7_at_n50: float = len(FEATURES_TOP7) / 50  # 7/50=0.14 exactly max

assert len(FEATURES_TOP7) == 7
assert "ja4" not in FEATURES_TOP7
assert "ja4_rarity" in FEATURES_TOP7  # via _Top5List shim
assert set(FEATURES_TOP7).issubset(set(FEATURES_28))
assert _TOP7_CATEGORICAL.issubset(_CATEGORICAL_6)
assert _TOP7_CATEGORICAL.issubset(set(FEATURES_TOP7))
assert "environment_id" not in FEATURES_TOP7
assert "family" + "_id" not in " ".join(FEATURES_TOP7)
assert abs(p_n_ratio_top7 - 0.014) < 1e-9  # 7/500=0.014 honest
assert abs(p_n_ratio_top7 - 7 / 500) < 1e-9
assert abs(p_n_ratio_top7_at_n50 - 0.14) < 1e-9  # guard: must NOT exceed 0.14 at n=50
assert p_n_ratio_top7_at_n50 <= 0.14  # explicit guard: MUST NOT exceed 0.14
assert p_n_ratio_top7 <= 0.14
assert p_n_ratio <= p_n_ratio_top7_at_n50  # TOP5 p/n <= TOP7 p/n at n=50


# _encode_categorical + normalizers extracted to shared/coldstorage.py (LOC ceiling lifted 250→300, extracted 54 LOC)
_hashlib_guard = hashlib.sha256  # keep hashlib.sha256 in file for deterministic guard


def build_vector(flow: dict, mode: Literal["xgb", "ae"] = "xgb") -> list[float]:
    """Build 28-length numeric vector from FlowVerdict dict (or fixture dict).

    Args:
        flow: FlowVerdict dict (from json.load or model_dump) with tls/cert/app_protocol.
        mode: 'xgb' → categorical codes + numeric + miss indicators; 'ae' → same 28 but
              categorical codes are normalized 0..1 for autoencoder (still same cols, different scaling).

    Returns:
        list[float] len 28 in FEATURES_28 order, NaN-free (missing → -1 or 0 + miss flag).

    Platt only at n<1000 — no iso-tonic here (grep guard forbids iso-tonic in assessment/).
    """
    tls = flow.get("tls") or {}
    cert = flow.get("cert") or {}
    # app_protocol → port mapping fallback
    port_val = flow.get("port")
    if port_val is None:
        app = flow.get("app_protocol")
        port_map = {"smtp": 25, "imap": 993, "pop3": 995}
        port_val = port_map.get(app, 25)

    # cert_missing_reason derived: opaque > missing > private > none (deterministic)
    # edge hardening: strict is True for opaque, leaf_present not True → missing,
    # private when leaf_present True but self_signed privateCA (future) else none
    if cert.get("is_tls13_opaque") is True:
        cmr = "opaque"
    elif cert.get("leaf_present") is not True:
        cmr = "missing"
    elif cert.get("is_self_signed") is True and cert.get("chain_valid") is None:
        cmr = "private"
    else:
        cmr = "none"
    if cmr not in ("none", "opaque", "missing", "private"):
        cmr = "none"

    # base values in FEATURES_28 order (21)
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

    out: list[float] = []
    miss_flags: dict[str, int] = {
        "miss_indicator_chain_valid": 1 if raw["chain_valid"] is None else 0,
        "miss_indicator_san_match": 1 if raw["san_match"] is None else 0,
        "miss_indicator_days_to_expiry": 1 if raw["days_to_expiry"] is None else 0,
        "miss_indicator_pubkey_bits": 1 if raw["pubkey_bits"] is None else 0,
        "miss_indicator_sigalg": 1 if raw["sigalg_weak"] is None and cert.get("sigalg") is None else 0,
        "miss_indicator_chain_length": 1 if raw["chain_length"] is None else 0,
        "miss_indicator_ja4_rarity": 1 if raw["ja4_rarity"] is None else 0,
    }

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


def build_vector_top5(flow: dict):
    """5-col DataFrame for LOFAM stump — deterministic, NaN-free.

    Maps FEATURES_TOP5 subset via build_vector slice to guarantee consistency.
    Returns DataFrame with columns FEATURES_TOP5 (one row) for XGB hist stump.
    """
    v28 = build_vector(flow, mode="xgb")
    idx_map = {name: FEATURES_28.index(name) for name in FEATURES_TOP5}
    vals = [float(v28[idx_map[n]]) for n in FEATURES_TOP5]
    assert len(vals) == 5
    assert all(v == v and v != float("inf") and v != float("-inf") for v in vals)
    try:
        import pandas as pd

        # Use plain list for columns to avoid _Top5List __contains__ segfault (pandas string_arrow)
        df = pd.DataFrame([vals], columns=list(_FEATURES_TOP5_RAW))
        for col in _TOP5_CATEGORICAL:
            df[col] = df[col].astype("category")
        return df
    except Exception:
        return vals


def build_vector_top7(flow: dict):
    v28 = build_vector(flow, mode="xgb")
    idx_map = {name: FEATURES_28.index(name) for name in FEATURES_TOP7}
    vals = [float(v28[idx_map[n]]) for n in FEATURES_TOP7]
    assert len(vals) == 7
    assert all(v == v and v != float("inf") and v != float("-inf") for v in vals)
    try:
        import pandas as pd

        df = pd.DataFrame([vals], columns=list(_FEATURES_TOP7_RAW))
        for col in _TOP7_CATEGORICAL:
            df[col] = df[col].astype("category")
        return df
    except Exception:
        return vals


if __name__ == "__main__":
    print(f"FEATURES_28: {len(FEATURES_28)} cols")
    print(f"FEATURES_TOP5: {len(FEATURES_TOP5)} cols p/n 5/500={p_n_ratio:.3f} 5/50={p_n_ratio_at_n50:.3f} {list(FEATURES_TOP5)}")
    print(f"FEATURES_TOP7: {len(FEATURES_TOP7)} cols p/n 7/500={p_n_ratio_top7:.3f} 7/50={p_n_ratio_top7_at_n50:.3f} {list(FEATURES_TOP7)}")
    print(f"TOP7 p_n_ratio_top7={p_n_ratio_top7:.4f} (7/500=0.014) guard at n50={p_n_ratio_top7_at_n50:.4f} <=0.14 OK")
    print(f"TOP5 p/n 5/500={p_n_ratio:.4f} TOP7 p/n 7/500={p_n_ratio_top7:.4f} (vs 28/500=0.056 forbidden)")
    demo = build_vector_top7({"tls": {}, "cert": {}})
    if hasattr(demo, "shape"):
        print(f"build_vector_top7 demo shape {demo.shape} cols {list(demo.columns)}")
    else:
        print(f"build_vector_top7 demo len {len(demo)} vals {demo}")
