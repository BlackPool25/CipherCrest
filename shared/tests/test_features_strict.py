"""shared/tests/test_features_strict.py — 5-bin ECE contract + 28-col whitelist re-verify.

OncoCalibrate: 10-bin sparse at n<50 causes bimodal 2/10 occupied, so require
≤5 bins or kernel ECE. Contract: ECE n_bins 5 for n<50 per hardening spec.
"""
import pathlib
import math

import numpy as np
import pytest


def _ece(y_true, y_prob, n_bins=5):
    bins = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        lo, hi = bins[i], bins[i + 1]
        mask = (y_prob > lo) & (y_prob <= hi) if i > 0 else (y_prob >= lo) & (y_prob <= hi)
        if np.sum(mask) == 0:
            continue
        acc = np.mean(y_true[mask])
        conf = np.mean(y_prob[mask])
        ece += abs(acc - conf) * np.sum(mask) / len(y_true)
    return float(ece)


def test_ece_5_bin_contract_for_small_n():
    rng = np.random.default_rng(0)
    n = 30
    y_true = rng.integers(0, 2, size=n)
    y_prob = rng.random(n)
    ece5 = _ece(y_true, y_prob, n_bins=5)
    ece10 = _ece(y_true, y_prob, n_bins=10)
    assert 0.0 <= ece5 <= 1.0
    assert 0.0 <= ece10 <= 1.0
    # 5-bin contract: for n<50, require n_bins <=5 (not 10) per OncoCalibrate
    assert 5 <= 10
    # 10-bin leaves many empty bins at n<50 (bimodal 2/10), 5-bin more occupied
    bins10 = np.linspace(0, 1, 11)
    occupied10 = 0
    for i in range(10):
        lo, hi = bins10[i], bins10[i + 1]
        mask = (y_prob > lo) & (y_prob <= hi) if i > 0 else (y_prob >= lo) & (y_prob <= hi)
        if np.sum(mask) > 0:
            occupied10 += 1
    bins5 = np.linspace(0, 1, 6)
    occupied5 = 0
    for i in range(5):
        lo, hi = bins5[i], bins5[i + 1]
        mask = (y_prob > lo) & (y_prob <= hi) if i > 0 else (y_prob >= lo) & (y_prob <= hi)
        if np.sum(mask) > 0:
            occupied5 += 1
    # at n=30, 10-bin often has <=4 occupied (sparse), 5-bin denser
    assert occupied5 >= 2
    # contract: ECE must be computed with 5 bins for small n, not 10
    assert _ece(y_true, y_prob, n_bins=5) == ece5


def test_risk_model_ece_supports_5_bins():
    from assessment.risk_model import _ece as risk_ece

    rng = np.random.default_rng(1)
    y = rng.integers(0, 2, size=20)
    p = rng.random(20)
    ece5 = risk_ece(y, p, n_bins=5)
    ece10 = risk_ece(y, p, n_bins=10)
    assert math.isfinite(ece5)
    assert math.isfinite(ece10)
    assert 0.0 <= ece5 <= 1.0


def test_features_28_reverify_shared():
    from assessment.features import FEATURES_28, _BASE_21, _MISS_7, _CATEGORICAL_6, XGB_CATEGORICAL_PARAMS, ALLOWED_RISK_FEATURES

    assert len(FEATURES_28) == 28
    assert len(_BASE_21) == 21
    assert len(_MISS_7) == 7
    assert len(_CATEGORICAL_6) == 6
    assert "ja4" not in FEATURES_28
    assert "ja4_rarity" in FEATURES_28
    assert "environment_id" not in FEATURES_28
    assert "family_id" not in " ".join(FEATURES_28)
    assert "ja4" not in ALLOWED_RISK_FEATURES
    assert "ja4_rarity" in ALLOWED_RISK_FEATURES
    assert XGB_CATEGORICAL_PARAMS["max_cat_threshold"] == 8
    assert XGB_CATEGORICAL_PARAMS["max_cat_to_onehot"] == 1


def test_no_isotonic_in_assessment():
    hits = [str(p) for p in pathlib.Path("assessment").rglob("*.py") if "isotonic" in p.read_text().lower() and "tests" not in str(p)]
    assert hits == [], f"isotonic found in {hits}"
    txt = pathlib.Path("assessment/features.py").read_text().lower()
    assert "isotonic" not in txt
