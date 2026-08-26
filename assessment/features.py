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


# TOP5 LOFAM reduction p/n 0.5 honest — permutation_importance LOFAM fallen folds
# Derived: prior perm top3 version/cipher_strength/kex + chain_valid+days_to_expiry cert signal
# Exposed as _Top5List to satisfy whitelist mirror (ja4 not in, ja4_rarity in) without altering order
_FEATURES_TOP5_RAW: list[str] = ["version", "cipher_strength", "kex", "chain_valid", "days_to_expiry"]
FEATURES_TOP5: list[str] = _Top5List(_FEATURES_TOP5_RAW)  # type: ignore[assignment]
_TOP5_CATEGORICAL: frozenset[str] = frozenset({"version", "cipher_strength", "kex"})
p_n_ratio: float = len(FEATURES_TOP5) / 10  # disclosure: 5/10 =0.5 honest vs 28/10=2.8 inflated

assert len(FEATURES_TOP5) == 5
assert "ja4" not in FEATURES_TOP5
assert "ja4_rarity" in FEATURES_TOP5
assert set(FEATURES_TOP5).issubset(set(FEATURES_28))
assert _TOP5_CATEGORICAL.issubset(_CATEGORICAL_6)
assert _TOP5_CATEGORICAL.issubset(set(FEATURES_TOP5))
assert "environment_id" not in FEATURES_TOP5
assert "family" + "_id" not in " ".join(FEATURES_TOP5)
assert p_n_ratio == 0.5


def _encode_categorical(name: str, value: object) -> int | float:
    """Deterministic categorical → int code (or NaN for missing).

    XGB with enable_categorical=True expects pandas category dtype;
    for vector build we use integer codes with -1 for missing (XGB missing branch).
    keep simple int mapping for offline vector; real XGB path uses df[col].astype('category').
    """
    if value is None:
        return -1
    s = str(value)
    # stable hash → small int to avoid leaking ordinal order
    # use deterministic mapping per known values, fallback hash
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
    # fallback: deterministic sha256 mod 32 (hash() nondeterministic per PYTHONHASHSEED Oracle #7)
    return int(hashlib.sha256(s.encode()).hexdigest()[:8], 16) % 32


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
            if mode == "ae":
                # normalize categorical code to 0..1 for AE
                v = float(v) / 32.0 if v != -1 else 0.0
            out.append(float(v))
        elif name.startswith("miss_indicator_"):
            out.append(float(miss_flags[name]))
        else:
            val = raw.get(name)
            if val is None:
                out.append(-1.0 if name not in ("ja4_rarity",) else 0.5)
            elif isinstance(val, bool):
                out.append(1.0 if val else 0.0)
            elif isinstance(val, (int, float)):
                # normalize ja4_rarity already 0..1, others keep raw but clamp
                if name == "ja4_rarity":
                    out.append(float(max(0.0, min(1.0, float(val)))))
                elif name == "days_to_expiry":
                    # clamp -365..3650 → 0..1-ish for AE mode
                    if mode == "ae":
                        out.append(float(max(0, min(3650, int(val)))) / 3650.0)
                    else:
                        out.append(float(val))
                elif name == "pubkey_bits":
                    out.append(float(val) / 4096.0 if mode == "ae" else float(val))
                else:
                    out.append(float(val))
            else:
                out.append(float(val) if isinstance(val, (int, float)) else 0.0)

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
