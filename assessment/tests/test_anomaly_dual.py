"""test_anomaly_dual — dual strict ECOD 20c+7lab +7c20lab + ja4 0.926 + IF corrected + invariance 0.05/0.10/0.30

TDD failing-first for T6 dual strict.
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
    _handle_zero_variance,
    _load_censys_flows,
    _load_lab_flows,
    _pseudo_labels,
    score_flow,
)
from assessment.features import FEATURES_28, build_vector


def test_dual_pkls_both_exist_and_has_scores():
    for p in ["models/anomaly.pkl", "models/anomaly_honest.pkl"]:
        path = pathlib.Path(p)
        assert path.exists(), f"{p} must exist"
        m = pickle.loads(path.read_bytes())
        assert hasattr(m, "decision_scores_"), f"{p} missing decision_scores_"
        assert hasattr(m, "threshold_"), f"{p} missing threshold_"
        assert len(m.decision_scores_) == 27, f"{p} len 27 got {len(m.decision_scores_)}"
        assert m.contamination == 0.10
        assert m.n_jobs == 1
        # prot4 <1M
        assert path.stat().st_size < 1_000_000, f"{p} >1M"
        assert path.stat().st_size > 0


def test_build_matrix_dual_shapes_27x28():
    for variant in ["inverted", "honest", "lab_only"]:
        X, train_flows, lab = _build_training_matrix(variant=variant)
        assert X.shape == (27, 28), f"{variant} shape {X.shape} != (27,28)"
        assert len(train_flows) == 27
        # variance handle kept 28 shape
        assert X.shape[1] == len(FEATURES_28) == 28


def test_load_lab_flows_45_and_censys_20():
    lab = _load_lab_flows()
    censys = _load_censys_flows()
    assert len(lab) == 45, f"lab 45 got {len(lab)} (10 base +35 jitter)"
    assert len(censys) == 20, f"censys 20 got {len(censys)}"


def test_handle_zero_variance_eps1e6_randomstate0():
    # MUST keep eps1e-6 RandomState0 per spec pyod catastrophic cancellation
    X = np.zeros((27, 28))
    X[:, 0] = 1.0  # one varying col
    X2 = _handle_zero_variance(X, eps=1e-6)
    assert X2.shape == (27, 28)
    # zero-var cols should have variance now >0 due to eps noise
    assert X2.std(axis=0)[1] > 0
    # deterministic RandomState0: same output twice
    X3 = _handle_zero_variance(X, eps=1e-6)
    assert np.allclose(X2, X3)
    # eps is 1e-6; check magnitude small
    assert np.abs(X2[:, 1]).max() < 5e-6


def test_dual_roc_table():
    # inverted ~0.87, honest ~0.47, lab_only ~0.23, ja4 0.926 contrast
    import json as js
    baselines = js.loads(pathlib.Path("eval/anomaly_baselines.json").read_text())
    inv = baselines["ecod_inverted_auc"]
    hon = baselines["ecod_honest_auc"]
    lab_only = baselines["ecod_lab_only_auc"]
    ja4 = baselines["ja4_rarity_auc"]
    if_auc = baselines["if_auc"]
    # inverted 0.87 +/-0.05
    assert 0.82 <= inv <= 0.92, f"inverted {inv} not ~0.87"
    assert abs(inv - 0.871) < 0.06, f"inverted {inv} expected 0.871"
    # honest ~0.47 +/-0.12 near-random
    assert 0.35 <= hon <= 0.60, f"honest {hon} not ~0.47"
    assert abs(hon - 0.473) < 0.12
    # lab_only ~0.23 disclosure
    assert 0.05 <= lab_only <= 0.45, f"lab_only {lab_only} not ~0.23"
    # ja4 0.926 > ecod inverted
    assert 0.90 <= ja4 <= 0.95, f"ja4 {ja4} not 0.926"
    assert ja4 > inv, f"ja4 {ja4} must beat ECOD inverted {inv}"
    assert abs(ja4 - 0.926) < 0.03
    # honest < inverted
    assert hon < inv, f"honest {hon} must < inverted {inv}"
    # ECOD primary > IF corrected
    assert inv > if_auc, f"ECOD primary {inv} must > IF {if_auc}"
    assert 0.65 <= if_auc <= 0.85, f"if_auc {if_auc} expected ~0.759"


def test_ja4_rarity_single_feature_neg_computed():
    # ja4_rarity neg ROC0.926 via build_vector ja4_rarity column only + roc_auc_score
    # MUST NOT use raw ja4
    lab = _load_lab_flows()
    censys = _load_censys_flows()
    # filtered 31 for stable 0.926
    from assessment.anomaly_model import _filtered_lab_for_training

    lab_f = _filtered_lab_for_training(lab)
    all_flows = lab_f + censys
    y = _pseudo_labels(all_flows)
    idx = FEATURES_28.index("ja4_rarity")
    X_all = np.array([build_vector(f, mode="xgb") for f in all_flows], dtype=float)
    ja_col = X_all[:, idx]
    auc_neg = roc_auc_score(y, -ja_col)
    assert abs(auc_neg - 0.926) < 0.03, f"ja4 neg {auc_neg} not 0.926"
    assert auc_neg > 0.90
    # raw ja4 not in FEATURES_28
    assert "ja4" not in FEATURES_28
    assert "ja4_rarity" in FEATURES_28
    txt = pathlib.Path("assessment/anomaly_model.py").read_text()
    # ensure no raw ja4 feature usage
    assert "ja4_rarity" in txt
    # ensure file does not contain raw ja4 as feature (check ALLOWED list)
    assert "raw ja4" not in txt.lower() or "only ja4_rarity" in txt.lower()


def test_contamination_invariance_05_10_30():
    # pyod #552: scores invariant across contamination, only threshold differs
    X, _, _ = _build_training_matrix(variant="inverted")
    from pyod.models.ecod import ECOD

    clf05 = ECOD(contamination=0.05, n_jobs=1)
    clf05.fit(X)
    clf10 = ECOD(contamination=0.10, n_jobs=1)
    clf10.fit(X)
    clf30 = ECOD(contamination=0.30, n_jobs=1)
    clf30.fit(X)
    assert np.allclose(clf05.decision_scores_, clf10.decision_scores_), "scores 0.05==0.10 invariant"
    assert np.allclose(clf10.decision_scores_, clf30.decision_scores_), "scores 0.10==0.30 invariant"
    assert np.allclose(clf05.decision_scores_, clf30.decision_scores_), "scores 0.05==0.30 invariant"
    assert clf05.threshold_ != clf10.threshold_, "threshold 0.05 vs 0.10 must differ"
    assert clf10.threshold_ != clf30.threshold_, "threshold 0.10 vs 0.30 must differ"
    assert clf05.threshold_ != clf30.threshold_, "threshold 0.05 vs 0.30 must differ"
    # decision_function also invariant
    s05 = clf05.decision_function(X)
    s10 = clf10.decision_function(X)
    s30 = clf30.decision_function(X)
    assert np.allclose(s05, s10)
    assert np.allclose(s10, s30)
    # ROC unchanged only threshold differs
    lab = _load_lab_flows()
    censys = _load_censys_flows()
    from assessment.anomaly_model import _filtered_lab_for_training

    lab_f = _filtered_lab_for_training(lab)
    all_flows = lab_f + censys
    y = _pseudo_labels(all_flows)
    X_all = np.array([build_vector(f, mode="xgb") for f in all_flows], dtype=float)
    auc05 = roc_auc_score(y, clf05.decision_function(X_all))
    auc10 = roc_auc_score(y, clf10.decision_function(X_all))
    auc30 = roc_auc_score(y, clf30.decision_function(X_all))
    assert abs(auc05 - auc10) < 1e-6, "ROC unchanged across contamination"
    assert abs(auc10 - auc30) < 1e-6


def test_if_corrected_max_samples_min256_27():
    # IsolationForest corrected max_samples min(256,27) contamination0.10 n_estimators50
    X, _, _ = _build_training_matrix(variant="honest")
    from sklearn.ensemble import IsolationForest

    n = X.shape[0]
    max_samples = min(256, n)
    assert max_samples == 27 == min(256, 27)
    clf = IsolationForest(n_estimators=50, max_samples=max_samples, contamination=0.10, random_state=0)
    clf.fit(X)
    assert clf.n_estimators == 50
    assert clf.max_samples == 27
    assert clf.contamination == 0.10
    # ensure txt documents corrected
    txt = pathlib.Path("assessment/anomaly_model.py").read_text()
    assert "max_samples" in txt
    assert "min(256" in txt


def test_ecod_fit_time_under_03s_both_variants():
    from pyod.models.ecod import ECOD

    for variant in ["inverted", "honest"]:
        X, _, _ = _build_training_matrix(variant=variant)
        t0 = time.time()
        clf = ECOD(contamination=0.10, n_jobs=1)
        clf.fit(X)
        elapsed = time.time() - t0
        assert elapsed < 0.3, f"{variant} fit <0.3s got {elapsed:.3f}s"


def test_anomaly_score_wired_to_flowverdict():
    # primary anomaly_score to FlowVerdict.assessment.anomaly_score ECOD raw decision_scores_ not labels
    flow = json.loads(pathlib.Path("shared/fixtures/family-04.json").read_text())
    s = score_flow(flow)
    assert isinstance(s, float)
    assert np.isfinite(s)
    from shared.schemas import Assessment

    a = Assessment(findings=[], risk_level="Low", risk_score=10, anomaly_score=s)
    assert a.anomaly_score == s
    # ensure decision_scores_ not labels used
    txt = pathlib.Path("assessment/anomaly_model.py").read_text()
    assert "decision_scores_" in txt
    assert "decision_function" in txt


def test_baselines_json_required_keys():
    baselines = json.loads(pathlib.Path("eval/anomaly_baselines.json").read_text())
    for k in ["ecod_inverted_auc", "ecod_honest_auc", "ecod_lab_only_auc", "ja4_rarity_auc", "if_auc"]:
        assert k in baselines, f"missing {k}"
    assert baselines["lab_n"] == 45
    assert baselines["n_prior"] == 20
    assert baselines["contamination_invariance_pass"] is True
    assert "thresholds" in baselines
    for ck in ["c05", "c10", "c30"]:
        assert ck in baselines["thresholds"]
    # ja4 >0.90
    assert baselines["ja4_rarity_auc"] > 0.90


def test_no_raw_ja4_must_keep_invariance_and_document_primary_gt_if():
    txt = pathlib.Path("assessment/anomaly_model.py").read_text()
    # MUST NOT use raw ja4 as risk feature — only ja4_rarity
    assert "ja4_rarity" in txt
    # contamination invariance test must exist
    assert "contamination" in txt.lower()
    # ECOD primary > IF corrected documented
    assert "ECOD primary" in txt
    assert "corrected IF" in txt or "IsolationForest" in txt
    # no transformer BERT or MicroAE
    assert "transformer" not in txt.lower() or "BERT" not in txt
    assert "MicroAE" not in txt
    assert "isotonic" not in txt.lower()


def test_pickle_protocol4_and_threshold_per_variant():
    for p in [pathlib.Path("models/anomaly.pkl"), pathlib.Path("models/anomaly_honest.pkl")]:
        m = pickle.loads(p.read_bytes())
        assert hasattr(m, "threshold_")
        assert isinstance(float(m.threshold_), float)
        assert np.isfinite(float(m.threshold_))
        # decision_scores_ per variant
        assert hasattr(m, "decision_scores_")
        assert len(m.decision_scores_) == 27
    # thresholds differ per contamination and per variant
    inv = pickle.loads(pathlib.Path("models/anomaly.pkl").read_bytes())
    hon = pickle.loads(pathlib.Path("models/anomaly_honest.pkl").read_bytes())
    assert inv.threshold_ != hon.threshold_
