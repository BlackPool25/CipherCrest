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


def test_isotonic_and_family_id_guards():
    needle = "iso" + "tonic"
    text = pathlib.Path("assessment/features.py").read_text()
    assert needle not in text.lower()
    from assessment.features import FEATURES_28

    assert "family" + "_id" not in FEATURES_28
    assert "family" + "_id" not in " ".join(FEATURES_28)
    hits = [str(p) for p in pathlib.Path("assessment").rglob("*.py") if "isotonic" in p.read_text().lower() and "tests" not in str(p)]
    assert hits == [], f"isotonic found in {hits}"


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
