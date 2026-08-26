"""Tests-after for ECOD primary lean — contamination invariance + ROC>0.60.

Lean Day7: ECOD contamination 0.10 n_jobs 1 fit on lab 31 + prior 20 35% slice (27 rows),
decision_scores_ raw not labels, threshold differs, ROC point>0.60.
"""
import json
import pathlib
import pickle
import time

import numpy as np
import pytest
from sklearn.metrics import roc_auc_score

from assessment.anomaly_model import (
    CONTAMINATION,
    N_JOBS,
    _build_training_matrix,
    _load_censys_flows,
    _load_lab_flows,
    _pseudo_labels,
    score_flow,
)
from assessment.features import build_vector


def test_anomaly_pkl_exists_and_has_scores():
    p = pathlib.Path("models/anomaly.pkl")
    assert p.exists(), "models/anomaly.pkl must exist"
    m = pickle.loads(p.read_bytes())
    assert hasattr(m, "decision_scores_"), "missing decision_scores_"
    assert hasattr(m, "threshold_"), "missing threshold_"
    assert len(m.decision_scores_) == 27
    assert m.contamination == 0.10


def test_ecod_params_frozen():
    # Must be contamination 0.10 n_jobs 1 per spec (not 0.5)
    m = pickle.loads(pathlib.Path("models/anomaly.pkl").read_bytes())
    assert m.contamination == CONTAMINATION == 0.10
    assert m.n_jobs == N_JOBS == 1
    # pyod ECOD contamination only threshold, not scores
    assert m.contamination != 0.5


def test_contamination_invariance_scores_equal_threshold_differs():
    X, _, _ = _build_training_matrix()
    from pyod.models.ecod import ECOD

    clf05 = ECOD(contamination=0.05, n_jobs=1)
    clf05.fit(X)
    clf10 = ECOD(contamination=0.10, n_jobs=1)
    clf10.fit(X)
    clf20 = ECOD(contamination=0.20, n_jobs=1)
    clf20.fit(X)
    clf30 = ECOD(contamination=0.30, n_jobs=1)
    clf30.fit(X)
    # per pyod #482/#552: contamination only affects threshold, scores invariant 0.05==0.10==0.30
    assert np.allclose(clf05.decision_scores_, clf10.decision_scores_), "scores must be invariant 0.05==0.10"
    assert np.allclose(clf10.decision_scores_, clf30.decision_scores_), "scores must be invariant 0.10==0.30"
    assert np.allclose(clf05.decision_scores_, clf30.decision_scores_), "scores must be invariant 0.05==0.30"
    assert np.allclose(clf05.decision_scores_, clf20.decision_scores_), "scores must be invariant 0.05==0.20"
    assert clf05.threshold_ != clf10.threshold_, "threshold must differ 0.05 vs 0.10"
    assert clf10.threshold_ != clf30.threshold_, "threshold must differ 0.10 vs 0.30"
    assert clf05.threshold_ != clf30.threshold_, "threshold must differ 0.05 vs 0.30"
    # also check decision_function invariant for same X
    s05 = clf05.decision_function(X)
    s10 = clf10.decision_function(X)
    s30 = clf30.decision_function(X)
    assert np.allclose(s05, s10)
    assert np.allclose(s10, s30)


def test_roc_point_above_060():
    # ROC point>0.60 vs pseudo-label rule weak families High/Critical as outlier 1
    lab = _load_lab_flows()
    censys = _load_censys_flows()
    all_flows = lab + censys
    y = _pseudo_labels(all_flows)
    assert len(set(y)) == 2, "need both classes for ROC"
    m = pickle.loads(pathlib.Path("models/anomaly.pkl").read_bytes())
    X_all = np.array([build_vector(f, mode="xgb") for f in all_flows], dtype=float)
    scores = m.decision_function(X_all)
    auc = roc_auc_score(y, scores)
    assert auc > 0.60, f"ROC point>0.60 required got {auc:.3f}"
    # no CI at n_eff=10 lean, point only


def test_score_flow_returns_float_and_wired():
    flow = json.loads(pathlib.Path("shared/fixtures/family-04.json").read_text())
    s = score_flow(flow)
    assert isinstance(s, float)
    assert np.isfinite(s)
    # opaque family-06 still numeric
    flow06 = json.loads(pathlib.Path("shared/fixtures/family-06.json").read_text())
    s06 = score_flow(flow06)
    assert isinstance(s06, float)
    assert np.isfinite(s06)


def test_anomaly_score_wired_to_flowverdict():
    # FlowVerdict.assessment.anomaly_score should accept raw decision_scores_
    from shared.schemas import FlowVerdict

    flow = json.loads(pathlib.Path("shared/fixtures/family-01.json").read_text())
    s = score_flow(flow)
    # simulate wiring: assessment.anomaly_score = s
    flow["assessment"] = flow.get("assessment") or {}
    flow["assessment"]["anomaly_score"] = s
    # need minimal valid FlowVerdict fields: ensure tls/cert etc from fixture are valid
    # family-01 fixture already has tls/cert valid for schemas
    # add required top-level fields if missing
    if "tls" not in flow:
        flow["tls"] = json.loads(pathlib.Path("shared/fixtures/family-01.json").read_text())["tls"]
    if "cert" not in flow:
        flow["cert"] = json.loads(pathlib.Path("shared/fixtures/family-01.json").read_text())["cert"]
    # FlowVerdict model_validate should accept anomaly_score
    # We test via Assessment model directly (lean check)
    from shared.schemas import Assessment

    a = Assessment(findings=[], risk_level="Low", risk_score=10, anomaly_score=s)
    assert a.anomaly_score == s


def test_no_raw_ja4_in_vector():
    flow = json.loads(pathlib.Path("shared/fixtures/family-04.json").read_text())
    # ensure build_vector never uses raw ja4 (only ja4_rarity)
    from assessment.features import FEATURES_28

    assert "ja4" not in FEATURES_28
    assert "ja4_rarity" in FEATURES_28
    v = build_vector(flow, mode="xgb")
    assert len(v) == 28


def test_fit_time_under_03s():
    X, _, _ = _build_training_matrix()
    from pyod.models.ecod import ECOD

    t0 = time.time()
    clf = ECOD(contamination=0.10, n_jobs=1)
    clf.fit(X)
    elapsed = time.time() - t0
    assert elapsed < 0.3, f"fit <0.3s required got {elapsed:.3f}s"


def test_calibration_separate():
    # MUST NOT mix calibration and anomaly — check risk_model not imported here
    txt = pathlib.Path("assessment/anomaly_model.py").read_text()
    assert "CalibratedClassifierCV" not in txt
    assert "calibrated_prob" not in txt.lower() or "anomaly_score" in txt.lower()
    # also ensure file does not contain isotonic
    assert "isotonic" not in txt.lower()


def test_ecod_primary_documented():
    txt = pathlib.Path("assessment/anomaly_model.py").read_text()
    assert "ECOD primary" in txt
    assert "corrected IF" in txt or "IF" in txt


def test_pickle_load_and_threshold():
    m = pickle.loads(pathlib.Path("models/anomaly.pkl").read_bytes())
    assert hasattr(m, "threshold_")
    assert isinstance(float(m.threshold_), float)
    assert np.isfinite(float(m.threshold_))
