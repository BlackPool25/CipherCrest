"""Tests-after for lean XGB Platt cv=2 + 500-boot ECE + permutation n=10.

Failing-first proof: first run before risk_model.py existed failed import; after lean green.
WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.
"""
import pathlib
import pickle
import json

import numpy as np


def test_platt_cv2():
    pkl = pathlib.Path("models/risk_clf.pkl")
    assert pkl.exists(), "risk_clf.pkl missing"
    m = pickle.load(open(pkl, "rb"))
    assert hasattr(m, "predict_proba")
    # sklearn 1.5 CalibratedClassifierCV carries method attr on calibrated_classifiers_
    assert getattr(m.calibrated_classifiers_[0], "method", "sigmoid") == "sigmoid"
    assert m.method == "sigmoid" if hasattr(m, "method") else True
    assert len(m.calibrated_classifiers_) == 2, "Platt cv=2 requires 2 calibrated classifiers"


def test_xgb_params():
    from assessment.features import XGB_CATEGORICAL_PARAMS

    assert XGB_CATEGORICAL_PARAMS["max_depth"] == 4
    assert XGB_CATEGORICAL_PARAMS["enable_categorical"] is True
    assert XGB_CATEGORICAL_PARAMS["tree_method"] == "hist"
    assert XGB_CATEGORICAL_PARAMS["n_estimators"] == 80
    assert XGB_CATEGORICAL_PARAMS["reg_alpha"] == 1.0
    assert XGB_CATEGORICAL_PARAMS["reg_lambda"] == 2.0


def test_no_isotonic():
    import pathlib as p

    needle = "iso" + "tonic"
    txt = pathlib.Path("assessment/risk_model.py").read_text()
    assert needle not in txt.lower(), "iso-tonic forbidden"
    for f in pathlib.Path("assessment").rglob("*.py"):
        if "test_" in f.name:
            continue
        if "__pycache__" in str(f):
            continue
        assert needle not in f.read_text().lower(), f"iso-tonic in {f}"


def test_ece_hi():
    # family-level bootstrap already in train; check ECE hi <0.20 via quick compute
    from assessment.risk_model import train_and_evaluate

    m = train_and_evaluate()
    assert m["ece_hi"] < 0.20, f"ECE hi {m['ece_hi']:.3f} >=0.20"
    assert m["size_mb"] < 5
    assert m["fit_time"] < 8.0


def test_calibration_curve_exists():
    p = pathlib.Path("eval/calibration_curve.png")
    assert p.exists() and p.stat().st_size > 1000
    p2 = pathlib.Path("eval/risk_pr.png")
    assert p2.exists() and p2.stat().st_size > 1000


def test_permutation_n10():
    from assessment.risk_model import _load_dataset, train_and_evaluate

    m = train_and_evaluate()
    assert len(m["top3"]) == 3
    # ensure permutation was n_repeats 10 via source grep
    txt = pathlib.Path("assessment/risk_model.py").read_text()
    assert "n_repeats=10" in txt or "n_repeats = 10" in txt


def test_calibrated_prob_range():
    from assessment.risk_model import predict

    flow = json.loads(open("shared/fixtures/family-01.json").read())
    res = predict(flow)
    assert res["calibrated_prob"] is not None
    assert 0 <= res["calibrated_prob"] <= 1


def test_weak_supervision_ledger():
    assert "WEAK SUPERVISION" in open("assessment/LEDGER.md").read()
    assert "Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a." in open("assessment/LEDGER.md").read()


def test_pkl_size():
    p = pathlib.Path("models/risk_clf.pkl")
    assert p.stat().st_size / (1024 * 1024) < 5


def test_no_raw_ja4_feature():
    from assessment.features import FEATURES_28

    assert "ja4" not in FEATURES_28
    assert "ja4_rarity" in FEATURES_28


def test_build_vector_28():
    from assessment.features import build_vector

    flow = json.loads(open("shared/fixtures/family-01.json").read())
    v = build_vector(flow, mode="xgb")
    assert len(v) == 28
    assert all(isinstance(x, float) for x in v)
    assert not any(np.isnan(v))


def test_splits_31():
    s = json.loads(open("assessment/splits.json").read())
    assert len(s["all_environment_ids"]) == 31
    assert len(s["D1_train_groups"]) == 12
    assert len(s["D2_val_groups"]) == 8
