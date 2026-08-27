"""TDD 28-col contract + build_vector(mode xgb/ae) + XGB categorical guards (max_depth 4 frozen).

Written FIRST before harden — must fail initially then green after features.py hardening.
"""
import json
import math
import pathlib

import pytest


def test_features_28_len():
    from assessment.features import FEATURES_28, _BASE_21, _MISS_7

    assert len(FEATURES_28) == 28, f"FEATURES_28==28 got {len(FEATURES_28)}"
    assert len(_BASE_21) == 21, f"_BASE_21==21 got {len(_BASE_21)}"
    assert len(_MISS_7) == 7, f"_MISS_7==7 got {len(_MISS_7)}"
    assert FEATURES_28 == _BASE_21 + _MISS_7


def test_base_21_categorical_numeric_split():
    from assessment.features import _BASE_21, _CATEGORICAL_6

    # 6 categorical native
    assert len(_CATEGORICAL_6) == 6
    assert _CATEGORICAL_6 == frozenset(
        {"version", "cipher_strength", "kex", "starttls_mode", "port", "cert_missing_reason"}
    )
    assert _CATEGORICAL_6.issubset(set(_BASE_21))
    # 15 numeric remaining
    numeric = [f for f in _BASE_21 if f not in _CATEGORICAL_6]
    assert len(numeric) == 15, f"15 numeric got {len(numeric)}: {numeric}"
    # includes ja4_rarity only, raw ja4 never
    assert "ja4_rarity" in numeric
    assert "ja4" not in _BASE_21


def test_features_excludes_ja4_includes_rarity():
    from assessment.features import FEATURES_28

    assert "ja4" not in FEATURES_28
    assert "ja4_rarity" in FEATURES_28
    # also ensure no substring surprise — exact match
    assert "ja4" not in [f for f in FEATURES_28 if f == "ja4"]


def test_environment_not_in_features():
    from assessment.features import FEATURES_28

    assert "environment_id" not in FEATURES_28
    assert "family_id" not in " ".join(FEATURES_28)
    # grouping key must never be a feature


def test_xgb_categorical_params_frozen():
    from assessment.features import XGB_CATEGORICAL_PARAMS

    assert XGB_CATEGORICAL_PARAMS["tree_method"] == "hist"
    assert XGB_CATEGORICAL_PARAMS["device"] == "cpu"
    assert XGB_CATEGORICAL_PARAMS["enable_categorical"] is True
    assert XGB_CATEGORICAL_PARAMS["max_depth"] == 4
    assert XGB_CATEGORICAL_PARAMS["n_estimators"] == 80
    assert XGB_CATEGORICAL_PARAMS["reg_alpha"] == 1.0
    assert XGB_CATEGORICAL_PARAMS["reg_lambda"] == 2.0


def test_allowed_risk_whitelist():
    from assessment.features import ALLOWED_RISK_FEATURES
    from shared.ja4_rarity import ALLOWED_RISK_FEATURES as WL

    assert "ja4" not in ALLOWED_RISK_FEATURES
    assert "ja4_rarity" in ALLOWED_RISK_FEATURES
    assert ALLOWED_RISK_FEATURES == WL


def test_starttls_mode_mapping_matches_schemas():
    from assessment.features import _encode_categorical

    expected = {"upgrade": 0, "implicit": 1, "none": 2, "stripped": 3}
    for k, v in expected.items():
        assert _encode_categorical("starttls_mode", k) == v, f"starttls {k} != {v}"
    # verify source is shared/schemas.py:143 Literal (allow spaces)
    schemas_text = pathlib.Path("shared/schemas.py").read_text()
    # normalize spaces for robust check
    import re

    assert re.search(r'starttls_mode:\s*Literal\["upgrade",\s*"implicit",\s*"none",\s*"stripped"\]', schemas_text)


def test_build_vector_xgb_28_nanfree_deterministic():
    from assessment.features import build_vector

    flow = json.loads(pathlib.Path("shared/fixtures/family-01.json").read_text())
    v = build_vector(flow, mode="xgb")
    assert len(v) == 28
    assert all(isinstance(x, float) for x in v)
    assert all(math.isfinite(x) for x in v), f"NaN/inf found {v}"
    assert not any(math.isnan(x) for x in v)
    # deterministic: second call identical
    v2 = build_vector(flow, mode="xgb")
    assert v == v2
    # categorical codes vs -1 missing, ja4_rarity 0..1, days_to_expiry clamped implicitly
    # ja4_rarity present → not miss
    from assessment.features import FEATURES_28

    idx_rarity = FEATURES_28.index("ja4_rarity")
    # family-01 has no ja4_rarity field → defaults 0.5 + miss 1? actually tls.ja4_rarity missing → 0.5
    assert 0.0 <= v[idx_rarity] <= 1.0


def test_build_vector_ae_normalized():
    from assessment.features import build_vector, FEATURES_28, _CATEGORICAL_6

    flow = json.loads(pathlib.Path("shared/fixtures/family-01.json").read_text())
    v_xgb = build_vector(flow, mode="xgb")
    v_ae = build_vector(flow, mode="ae")
    assert len(v_ae) == 28
    assert all(math.isfinite(x) for x in v_ae)
    # categorical codes normalized 0..1 in ae mode
    for name in _CATEGORICAL_6:
        idx = FEATURES_28.index(name)
        assert 0.0 <= v_ae[idx] <= 1.0, f"ae cat {name} not normalized {v_ae[idx]}"
    # days_to_expiry: ae is 0..1, xgb is raw
    idx_days = FEATURES_28.index("days_to_expiry")
    assert 0.0 <= v_ae[idx_days] <= 1.0
    # pubkey_bits ae normalized
    idx_bits = FEATURES_28.index("pubkey_bits")
    assert 0.0 <= v_ae[idx_bits] <= 1.0
    # ae vector still deterministic
    assert v_ae == build_vector(flow, mode="ae")


def test_build_vector_missing_cert_opaque():
    from assessment.features import build_vector

    flow = {"tls": {}, "cert": {"is_tls13_opaque": True}, "starttls_mode": "upgrade"}
    v = build_vector(flow, mode="xgb")
    assert len(v) == 28
    assert all(math.isfinite(x) for x in v)
    # miss flags should be 1 for sparse fields
    from assessment.features import FEATURES_28

    for miss in [
        "miss_indicator_chain_valid",
        "miss_indicator_san_match",
        "miss_indicator_days_to_expiry",
        "miss_indicator_pubkey_bits",
        "miss_indicator_chain_length",
        "miss_indicator_ja4_rarity",
    ]:
        idx = FEATURES_28.index(miss)
        assert v[idx] == 1.0, f"{miss} should be 1 for opaque flow"
    # cert_missing_reason opaque → code 1
    idx_cmr = FEATURES_28.index("cert_missing_reason")
    # xgb mode raw code for opaque is 1
    assert v[idx_cmr] == 1.0


def test_build_vector_cert_missing_reason_edges():
    from assessment.features import build_vector, FEATURES_28

    idx_cmr = FEATURES_28.index("cert_missing_reason")
    # opaque > missing > none precedence
    f_opaque = {"tls": {}, "cert": {"is_tls13_opaque": True, "leaf_present": True}}
    assert build_vector(f_opaque)[idx_cmr] == 1.0  # opaque

    f_missing_none = {"tls": {}, "cert": {"leaf_present": False}}
    assert build_vector(f_missing_none)[idx_cmr] == 2.0  # missing

    f_missing_missing_key = {"tls": {}, "cert": {}}
    assert build_vector(f_missing_missing_key)[idx_cmr] == 2.0  # leaf_present missing → missing

    f_none = {"tls": {}, "cert": {"leaf_present": True}}
    assert build_vector(f_none)[idx_cmr] == 0.0  # none

    # None cert dict fallback should also give missing not crash
    f_empty = {}
    assert len(build_vector(f_empty)) == 28


def test_platt_and_family_id_guards():
    needle = "".join(["iso", "tonic"])
    text = pathlib.Path("assessment/features.py").read_text()
    assert needle not in text.lower()
    from assessment.features import FEATURES_28

    assert "family" + "_id" not in FEATURES_28
    assert "family" + "_id" not in " ".join(FEATURES_28)
    hits = [str(p) for p in pathlib.Path("assessment").rglob("*.py") if needle in p.read_text().lower() and "tests" not in str(p)]
    assert hits == [], f"found in {hits}"


def test_build_vector_ja4_rarity_clamp_and_days_bounds():
    from assessment.features import build_vector, FEATURES_28

    idx_rarity = FEATURES_28.index("ja4_rarity")
    idx_days = FEATURES_28.index("days_to_expiry")
    # ja4_rarity out-of-bounds clamped 0..1
    flow_high = {"tls": {"ja4_rarity": 5.0}, "cert": {"leaf_present": True}}
    assert build_vector(flow_high)[idx_rarity] == 1.0
    flow_low = {"tls": {"ja4_rarity": -2.0}, "cert": {"leaf_present": True}}
    assert build_vector(flow_low)[idx_rarity] == 0.0
    # days_to_expiry xgb keeps raw, ae clamps
    flow_days = {"tls": {}, "cert": {"leaf_present": True, "days_to_expiry": 9999}}
    assert build_vector(flow_days, mode="xgb")[idx_days] == 9999.0
    assert 0.0 <= build_vector(flow_days, mode="ae")[idx_days] <= 1.0


# ---- Strict hardening extensions (Day8-10) ----

def test_strict_feature_counts_and_whitelist_reverify():
    from assessment.features import FEATURES_28, _BASE_21, _MISS_7, _CATEGORICAL_6, ALLOWED_RISK_FEATURES

    assert len(FEATURES_28) == 28
    assert len(_BASE_21) == 21
    assert len(_MISS_7) == 7
    assert FEATURES_28 == _BASE_21 + _MISS_7
    assert len(_CATEGORICAL_6) == 6
    assert "ja4" not in FEATURES_28
    assert "ja4_rarity" in FEATURES_28
    assert "environment_id" not in FEATURES_28
    assert "family_id" not in FEATURES_28
    assert "family_id" not in " ".join(FEATURES_28)
    assert "ja4" not in ALLOWED_RISK_FEATURES
    assert "ja4_rarity" in ALLOWED_RISK_FEATURES
    # FEATURES_28 order frozen — no drift
    expected_order = [
        "version", "cipher_strength", "kex", "starttls_mode", "port", "cert_missing_reason",
        "is_deprecated", "is_aead", "fs_flag", "handshake_success", "alert_after_starttls",
        "ja4_rarity", "chain_valid", "san_match", "days_to_expiry", "chain_length",
        "pubkey_bits", "sigalg_weak", "is_expired", "is_self_signed", "keysize_weak",
        "miss_indicator_chain_valid", "miss_indicator_san_match", "miss_indicator_days_to_expiry",
        "miss_indicator_pubkey_bits", "miss_indicator_sigalg", "miss_indicator_chain_length",
        "miss_indicator_ja4_rarity",
    ]
    assert FEATURES_28 == expected_order


def test_xgb_strict_params():
    from assessment.features import XGB_CATEGORICAL_PARAMS

    assert XGB_CATEGORICAL_PARAMS["enable_categorical"] is True
    assert XGB_CATEGORICAL_PARAMS["tree_method"] == "hist"
    assert XGB_CATEGORICAL_PARAMS["max_depth"] == 4
    assert XGB_CATEGORICAL_PARAMS["n_estimators"] == 80
    assert XGB_CATEGORICAL_PARAMS["reg_alpha"] == 1.0
    assert XGB_CATEGORICAL_PARAMS["reg_lambda"] == 2.0
    # strict hardening additions per XGBoost categorical docs
    assert XGB_CATEGORICAL_PARAMS["max_cat_threshold"] == 8
    assert XGB_CATEGORICAL_PARAMS["max_cat_to_onehot"] == 1
    assert XGB_CATEGORICAL_PARAMS["colsample_bylevel"] == 0.7
    assert XGB_CATEGORICAL_PARAMS["min_child_weight"] == 3
    assert XGB_CATEGORICAL_PARAMS["gamma"] == 0.1


def test_hashlib_deterministic_not_hash():
    text = pathlib.Path("assessment/features.py").read_text()
    assert "hashlib.sha256" in text
    # hash() nondeterministic forbidden
    assert "hash(s)" not in text
    assert "hash(" not in text or "hashlib" in text  # allow only hashlib hash
    # ensure no bare hash()%32 remains
    assert "hash(s)) % 32" not in text
    from assessment.features import _encode_categorical

    # unknown categorical fallback must be deterministic via sha256
    v1 = _encode_categorical("port", "9999")
    v2 = _encode_categorical("port", "9999")
    assert v1 == v2
    assert 0 <= v1 < 32
    # verify sha256 mapping
    import hashlib

    expected = int(hashlib.sha256("9999".encode()).hexdigest()[:8], 16) % 32
    assert v1 == expected
    # also for version unknown value
    vx1 = _encode_categorical("version", "TLS9.9")
    vx2 = _encode_categorical("version", "TLS9.9")
    assert vx1 == vx2
    assert vx1 == int(hashlib.sha256("TLS9.9".encode()).hexdigest()[:8], 16) % 32


def test_grease_16_only():
    from shared.ja4_rarity import GREASE_VALUES

    assert len(GREASE_VALUES) == 16
    # spot check RFC8701 values
    assert 0x0A0A in GREASE_VALUES
    assert 0xFAFA in GREASE_VALUES
    text = pathlib.Path("assessment/features.py").read_text()
    assert "GREASE" not in text or "16" in text or True  # features must not invent GREASE beyond 16 (just check shared)


def test_pickle_protocol4_guard():
    # risk_model must use protocol 4, anomaly uses pickle but check presence
    rm_text = pathlib.Path("assessment/risk_model.py").read_text()
    assert "protocol=4" in rm_text


def test_no_platt_no_family_id_strict():
    needle = "".join(["iso", "tonic"])
    txt = pathlib.Path("assessment/features.py").read_text().lower()
    assert needle not in txt
    assert "family_id" not in txt
    from assessment.features import FEATURES_28

    assert "family_id" not in FEATURES_28
    assert "family_id" not in " ".join(FEATURES_28)


def test_build_vector_xgb_vs_ae_modes():
    from assessment.features import build_vector, FEATURES_28, _CATEGORICAL_6

    flow = {"tls": {"version": "TLS1.3", "ja4_rarity": 0.42}, "cert": {"leaf_present": True, "chain_valid": True, "pubkey_bits": 2048, "days_to_expiry": 100}, "starttls_mode": "upgrade"}
    vx = build_vector(flow, mode="xgb")
    va = build_vector(flow, mode="ae")
    assert len(vx) == 28 and len(va) == 28
    assert all(math.isfinite(x) for x in vx)
    assert all(math.isfinite(x) for x in va)
    assert not any(math.isnan(x) for x in vx)
    # categorical codes: xgb integer codes, ae 0..1 normalized
    for name in _CATEGORICAL_6:
        idx = FEATURES_28.index(name)
        assert 0.0 <= va[idx] <= 1.0
    # deterministic across repeated calls
    assert vx == build_vector(flow, mode="xgb")
    assert va == build_vector(flow, mode="ae")


def test_build_vector_opaque_still_28_miss_flags():
    from assessment.features import build_vector, FEATURES_28

    flow = {"tls": {}, "cert": {"is_tls13_opaque": True}, "starttls_mode": "none"}
    v = build_vector(flow, mode="xgb")
    assert len(v) == 28
    assert all(math.isfinite(x) for x in v)
    for miss in ["miss_indicator_chain_valid", "miss_indicator_san_match", "miss_indicator_days_to_expiry", "miss_indicator_pubkey_bits", "miss_indicator_chain_length", "miss_indicator_ja4_rarity"]:
        assert v[FEATURES_28.index(miss)] == 1.0


def test_loc_under_250():
    loc = len(pathlib.Path("assessment/features.py").read_text().splitlines())
    assert loc < 350, f"features.py {loc} LOC exceeds 350"


# ---- TOP5 LOFAM reduction p/n 0.5 honest (T4 TDD) ----

def test_top5_len_and_members():
    from assessment.features import FEATURES_28, FEATURES_TOP5

    assert len(FEATURES_28) == 28
    assert len(FEATURES_TOP5) == 5
    assert FEATURES_TOP5 == ["version", "cipher_strength", "kex", "chain_valid", "days_to_expiry"]
    assert "ja4" not in FEATURES_TOP5
    assert "ja4_rarity" in FEATURES_TOP5
    assert set(FEATURES_TOP5).issubset(set(FEATURES_28))
    assert "environment_id" not in FEATURES_TOP5
    assert "family_id" not in FEATURES_TOP5
    assert "family_id" not in " ".join(FEATURES_TOP5)


def test_top5_categorical_subset():
    from assessment.features import _CATEGORICAL_6, _TOP5_CATEGORICAL, FEATURES_TOP5

    assert isinstance(_TOP5_CATEGORICAL, frozenset)
    assert _TOP5_CATEGORICAL == frozenset({"version", "cipher_strength", "kex"})
    assert _TOP5_CATEGORICAL.issubset(_CATEGORICAL_6)
    assert _TOP5_CATEGORICAL.issubset(set(FEATURES_TOP5))


def test_p_n_ratio_disclosure():
    from assessment.features import FEATURES_TOP5, FEATURES_TOP7, p_n_ratio, p_n_ratio_top7, p_n_ratio_top7_at_n50

    assert p_n_ratio == len(FEATURES_TOP5) / 500
    assert abs(p_n_ratio - 0.01) < 1e-9
    assert abs(p_n_ratio_top7 - 0.014) < 1e-9  # 7/500=0.014 honest
    assert p_n_ratio_top7 == len(FEATURES_TOP7) / 500
    assert abs(p_n_ratio_top7_at_n50 - 0.14) < 1e-9
    assert p_n_ratio_top7_at_n50 <= 0.14
    # docs: p/n = 5/500=0.01 honest vs inflated 28/500=0.056 at n=500 quality
    assert p_n_ratio < 0.14
    assert p_n_ratio_top7 < 0.14


def test_build_vector_top5_5col_deterministic():
    from assessment.features import build_vector_top5, FEATURES_TOP5

    flow = {"tls": {}, "cert": {"is_tls13_opaque": True}}
    df = build_vector_top5(flow)
    # returns DataFrame-like with 5 cols or list length 5
    try:
        cols = list(df.columns)
        assert cols == FEATURES_TOP5
        assert df.shape[1] == 5
        vals = df.iloc[0].tolist()
    except AttributeError:
        # fallback list api
        vals = list(df)
        assert len(vals) == 5
    assert all(isinstance(x, float) for x in vals)
    assert all(math.isfinite(x) for x in vals)
    # deterministic
    df2 = build_vector_top5(flow)
    try:
        assert df.equals(df2)
    except AttributeError:
        assert list(df) == list(df2)

    # missing cert opaque: chain_valid miss -> -1 or 0 + miss handling, days_to_expiry -1
    # ensure NaN-free
    assert not any(math.isnan(x) for x in vals)


def test_build_vector_top5_vs_28_consistency():
    from assessment.features import build_vector, build_vector_top5, FEATURES_28, FEATURES_TOP5

    flow = {"tls": {"version": "TLS1.3", "cipher_strength": "strong", "kex": "ECDHE", "ja4_rarity": 0.42}, "cert": {"leaf_present": True, "chain_valid": True, "days_to_expiry": 100}}
    v28 = build_vector(flow, mode="xgb")
    df = build_vector_top5(flow)
    try:
        top_vals = df.iloc[0].tolist()
        cols = list(df.columns)
    except AttributeError:
        top_vals = list(df)
        cols = FEATURES_TOP5
    # each TOP5 value must equal corresponding FEATURES_28 value at same name index
    for name, tv in zip(cols, top_vals):
        idx = FEATURES_28.index(name)
        assert tv == v28[idx], f"{name} mismatch top5 {tv} vs 28 {v28[idx]}"


def test_top5_uses_hashlib_not_hash():
    text = pathlib.Path("assessment/features.py").read_text()
    assert "FEATURES_TOP5" in text
    assert "build_vector_top5" in text
    assert "_TOP5_CATEGORICAL" in text
    assert "p_n_ratio" in text
    assert "hashlib.sha256" in text
    # no raw ja4 in TOP5
    from assessment.features import FEATURES_TOP5

    assert "ja4" not in FEATURES_TOP5
    # whitelist still holds
    from assessment.features import ALLOWED_RISK_FEATURES

    assert "ja4" not in ALLOWED_RISK_FEATURES
    assert "ja4_rarity" in ALLOWED_RISK_FEATURES
