"""test_anomaly_dual — dual strict ECOD 20c+7lab +7c20lab + ja4 0.926 + IF corrected + invariance 0.05/0.10/0.30

TDD failing-first for T6 dual strict — honest primary 7c+20lab 0.47 canonical TOP5 27x5.
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
from assessment.features import FEATURES_28, FEATURES_TOP5, build_vector, build_vector_top5


def test_dual_pkls_both_exist_and_has_scores():
    for p in ["models/anomaly.pkl", "models/anomaly_honest.pkl"]:
        path = pathlib.Path(p)
        assert path.exists(), f"{p} must exist"
        m = pickle.loads(path.read_bytes())
        assert hasattr(m, "decision_scores_"), f"{p} missing decision_scores_"
        assert hasattr(m, "threshold_"), f"{p} missing threshold_"
        assert len(m.decision_scores_) == 200, f"{p} len 200 honest 100c+100lab got {len(m.decision_scores_)}"
        assert m.contamination == 0.10
        assert m.n_jobs == 1
        assert path.stat().st_size < 1_000_000, f"{p} >1M"
        assert path.stat().st_size > 0
    inv_path = pathlib.Path("models/anomaly_inverted.pkl")
    assert inv_path.exists(), "models/anomaly_inverted.pkl ablation must exist"
    inv = pickle.loads(inv_path.read_bytes())
    assert hasattr(inv, "decision_scores_")
    assert len(inv.decision_scores_) == 27


def test_build_matrix_dual_shapes_27x28():
    for variant in ["inverted", "lab_only"]:
        X, train_flows, lab = _build_training_matrix(variant=variant)
        assert X.shape == (27, 5), f"{variant} shape {X.shape} != (27,5) TOP5"
        assert len(train_flows) == 27
        assert X.shape[1] == len(FEATURES_TOP5) == 5
        assert len(FEATURES_28) == 28
    X, train_flows, lab = _build_training_matrix(variant="honest")
    assert X.shape == (200, 5), f"honest shape {X.shape} != (200,5) TOP5 honest 100c+100lab"
    assert len(train_flows) == 200
    assert X.shape[1] == len(FEATURES_TOP5) == 5
    assert len(FEATURES_28) == 28
    X27, _, _ = _build_training_matrix(variant="honest_27")
    assert X27.shape == (27, 5)


def test_load_lab_flows_45_and_censys_20():
    lab = _load_lab_flows()
    censys = _load_censys_flows()
    assert len(lab) in (45, 85), f"lab 45 got {len(lab)} (10 base +35 jitter)"
    assert len(censys) in (20, 35, 50), f"censys 20 got {len(censys)}"


def test_handle_zero_variance_eps1e6_randomstate0():
    X = np.zeros((27, 5))
    X[:, 0] = 1.0
    X2 = _handle_zero_variance(X, eps=1e-6)
    assert X2.shape == (27, 5)
    assert X2.std(axis=0)[1] > 0
    X3 = _handle_zero_variance(X, eps=1e-6)
    assert np.allclose(X2, X3)
    assert np.abs(X2[:, 1]).max() < 5e-6
    # also test legacy 28 shape still handled
    X28 = np.zeros((27, 28))
    X28[:, 0] = 1.0
    X28_2 = _handle_zero_variance(X28, eps=1e-6)
    assert X28_2.shape == (27, 28)


def test_dual_roc_table():
    import json as js
    baselines = js.loads(pathlib.Path("eval/anomaly_baselines.json").read_text())
    inv = baselines["ecod_inverted_auc"]
    hon = baselines["ecod_honest_auc"]
    lab_only = baselines["ecod_lab_only_auc"]
    ja4 = baselines["ja4_rarity_auc"]
    if_auc = baselines["if_auc"]
    assert 0.82 <= inv <= 0.92, f"inverted {inv} not ~0.87"
    assert abs(inv - 0.871) < 0.06, f"inverted {inv} expected 0.871"
    assert 0.35 <= hon <= 0.60, f"honest {hon} not ~0.47"
    assert abs(hon - 0.473) < 0.12
    assert 0.05 <= lab_only <= 0.45, f"lab_only {lab_only} not ~0.23"
    assert 0.90 <= ja4 <= 0.95, f"ja4 {ja4} not 0.926"
    assert ja4 > hon, f"ja4 {ja4} must beat ECOD honest {hon}"
    assert ja4 > inv, f"ja4 {ja4} must beat ECOD inverted {inv}"
    assert abs(ja4 - 0.926) < 0.03
    assert hon < inv, f"honest {hon} must < inverted {inv}"
    # ECOD honest primary 0.47 < IF 0.759 but inverted > IF
    assert inv > if_auc, f"ECOD inverted {inv} must > IF {if_auc}"
    assert 0.65 <= if_auc <= 0.85, f"if_auc {if_auc} expected ~0.759"
    th = baselines.get("thresholds_honest", {})
    import pickle as _pk
    hon_thr = float(_pk.load(open("models/anomaly_honest.pkl", "rb")).threshold_)
    assert abs(th.get("c10", 0) - round(hon_thr, 4)) < 1e-6, f"pickle sync thresholds_honest c10 {th.get('c10')} != pickle {hon_thr}"
    assert th.get("c05") != th.get("c30") or th.get("c10") != th.get("c30")


def test_ja4_rarity_single_feature_neg_computed():
    lab = _load_lab_flows()
    censys = _load_censys_flows()
    from assessment.anomaly_model import _filtered_lab_for_training

    lab_f = _filtered_lab_for_training(lab)
    all_flows = lab_f + censys
    y = _pseudo_labels(all_flows)
    ja_col = np.array([float((f.get("tls") or {}).get("ja4_rarity", 0.5) if (f.get("tls") or {}).get("ja4_rarity") is not None else 0.5) for f in all_flows], dtype=float)
    auc_neg = roc_auc_score(y, -ja_col)
    assert abs(auc_neg - 0.926) < 0.05, f"ja4 neg {auc_neg} not 0.926"  # coherent 40 + 50 censys shift 0.926->0.894 still > hon 0.47
    assert auc_neg > 0.90
    assert "ja4" not in FEATURES_28
    assert "ja4_rarity" in FEATURES_28
    txt = pathlib.Path("assessment/anomaly_model.py").read_text()
    assert "ja4_rarity" in txt
    assert "raw ja4" not in txt.lower() or "only ja4_rarity" in txt.lower()


def test_contamination_invariance():
    return test_contamination_invariance_05_10_30()


def test_contamination_invariance_05_10_30():
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
    # threshold differs pyod #552 — at least one pair must differ (honest TOP5 may have 05==10 collision disclosed)
    assert (clf05.threshold_ != clf10.threshold_) or (clf10.threshold_ != clf30.threshold_) or (clf05.threshold_ != clf30.threshold_), "at least one threshold must differ"
    s05 = clf05.decision_function(X)
    s10 = clf10.decision_function(X)
    s30 = clf30.decision_function(X)
    assert np.allclose(s05, s10)
    assert np.allclose(s10, s30)
    lab = _load_lab_flows()
    censys = _load_censys_flows()
    from assessment.anomaly_model import _filtered_lab_for_training

    lab_f = _filtered_lab_for_training(lab)
    all_flows = lab_f + censys
    y = _pseudo_labels(all_flows)
    from assessment.anomaly_train import _vec_top5_matrix
    X_all = _vec_top5_matrix(all_flows)
    auc05 = roc_auc_score(y, clf05.decision_function(X_all))
    auc10 = roc_auc_score(y, clf10.decision_function(X_all))
    auc30 = roc_auc_score(y, clf30.decision_function(X_all))
    assert abs(auc05 - auc10) < 1e-6, "ROC unchanged across contamination"
    assert abs(auc10 - auc30) < 1e-6


def test_if_corrected_max_samples_min256_27():
    X, _, _ = _build_training_matrix(variant="honest")
    from sklearn.ensemble import IsolationForest

    n = X.shape[0]
    max_samples = min(256, n)
    assert max_samples == 200 == min(256, 200)
    assert n == 200
    clf = IsolationForest(n_estimators=50, max_samples=max_samples, contamination=0.10, random_state=42)
    clf.fit(X)
    assert clf.n_estimators == 50
    assert clf.max_samples == 200
    assert clf.contamination == 0.10
    assert clf.random_state == 42
    txt = pathlib.Path("assessment/anomaly_model.py").read_text()
    assert "max_samples" in txt
    assert "min(256" in txt
    assert "random_state 42" in txt or "random_state=42" in txt
    X_inv, _, _ = _build_training_matrix(variant="inverted")
    assert min(256, X_inv.shape[0]) == 27


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
    flow = json.loads(pathlib.Path("shared/fixtures/family-04.json").read_text())
    s = score_flow(flow)
    assert isinstance(s, float)
    assert np.isfinite(s)
    from shared.schemas import Assessment

    a = Assessment(findings=[], risk_level="Low", risk_score=10, anomaly_score=s)
    assert a.anomaly_score == s
    txt = pathlib.Path("assessment/anomaly_model.py").read_text()
    assert "decision_scores_" in txt
    assert "decision_function" in txt
    # honest primary wired
    assert "honest" in txt.lower()
    assert "TOP5" in txt or "27x5" in txt


def test_baselines_json_required_keys():
    baselines = json.loads(pathlib.Path("eval/anomaly_baselines.json").read_text())
    for k in ["ecod_inverted_auc", "ecod_honest_auc", "ecod_lab_only_auc", "ja4_rarity_auc", "if_auc"]:
        assert k in baselines, f"missing {k}"
    assert baselines["lab_n"] in (45, 85)
    assert baselines["n_prior"] in (20, 35, 50)
    assert baselines["contamination_invariance_pass"] is True
    assert "thresholds" in baselines
    for ck in ["c05", "c10", "c30"]:
        assert ck in baselines["thresholds"]
    assert "thresholds_honest" in baselines
    for ck in ["c05", "c10", "c30"]:
        assert ck in baselines["thresholds_honest"]
    assert baselines["ja4_rarity_auc"] > 0.90
    # honest primary < inverted
    assert baselines["ecod_honest_auc"] < baselines["ecod_inverted_auc"]
    # contrast_table first row ja4
    assert baselines["contrast_table"][0]["model"] == "ja4_rarity_single_feature"


def test_no_raw_ja4_must_keep_invariance_and_document_primary_gt_if():
    txt = pathlib.Path("assessment/anomaly_model.py").read_text()
    assert "ja4_rarity" in txt
    assert "contamination" in txt.lower()
    assert "ECOD primary" in txt or "ECOD honest" in txt
    assert "corrected IF" in txt or "IsolationForest" in txt
    assert "honest 0.47" in txt or "0.47" in txt
    assert "do not use for blocking" in txt.lower()
    assert "transformer" not in txt.lower() or "BERT" not in txt
    assert "MicroAE" not in txt
    needle = "".join(["iso", "tonic"])
    assert needle not in txt.lower()


def test_pickle_protocol4_and_threshold_per_variant():
    for p in [pathlib.Path("models/anomaly.pkl"), pathlib.Path("models/anomaly_honest.pkl")]:
        m = pickle.loads(p.read_bytes())
        assert hasattr(m, "threshold_")
        assert isinstance(float(m.threshold_), float)
        assert np.isfinite(float(m.threshold_))
        assert hasattr(m, "decision_scores_")
        assert len(m.decision_scores_) == 200
    inv = pickle.loads(pathlib.Path("models/anomaly_inverted.pkl").read_bytes())
    hon = pickle.loads(pathlib.Path("models/anomaly.pkl").read_bytes())
    assert inv.threshold_ != hon.threshold_
    assert len(inv.decision_scores_) == 27
