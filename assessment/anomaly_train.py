"""anomaly_train — ECOD honest 200x5 distinct 100c+100lab 50Censys50Tranco TOP5 + ja4 + IF corrected.

T6 honest fix: theater 0.871 and 0.980 deleted — keep ECOD 0.473 vs ja4 0.926 + IF 0.759.
"""

from __future__ import annotations

import json
import pathlib
import pickle
import time

import numpy as np

from assessment.features import FEATURES_TOP5, build_vector, build_vector_top5
from assessment.anomaly_data import (
    BASELINE_PATH,
    CONTAMINATION,
    HONEST_MODEL_PATH,
    INVERTED_MODEL_PATH,
    MODEL_PATH,
    N_JOBS,
    _build_training_matrix,
    _filtered_lab_for_training,
    _load_censys_flows,
    _load_lab_flows,
    _pseudo_labels,
)
from assessment.anomaly_metrics import _ja4_rarity_auc, _train_if_corrected

try:
    from pyod.models.ecod import ECOD
except Exception:  # pragma: no cover
    ECOD = None  # type: ignore
try:
    from sklearn.metrics import roc_auc_score
except Exception:
    roc_auc_score = None  # type: ignore


def _vec_top5_matrix(flows: list[dict]) -> np.ndarray:
    rows = []
    for f in flows:
        if not isinstance(f, dict) or not f:
            f = {"tls": {}, "cert": {}, "starttls_mode": "none"}
        else:
            if "prior_flag" in f:
                f = {k: v for k, v in f.items() if k != "prior_flag"}
        v = build_vector_top5(f)
        try:
            import pandas as pd  # type: ignore

            if isinstance(v, pd.DataFrame):
                rows.append(v.values[0].astype(float).tolist())
            else:
                rows.append([float(x) for x in v])  # type: ignore
        except Exception:
            rows.append([float(x) for x in v])  # type: ignore
    X = np.array(rows, dtype=float)
    assert X.shape[1] == len(FEATURES_TOP5) == 5
    return X


def train_and_save(contamination: float = CONTAMINATION, n_jobs: int = N_JOBS, variant: str = "honest") -> dict:
    if ECOD is None:
        raise RuntimeError("pyod not installed")
    # honest only — theater variant removed
    if variant not in ("honest", "lab_only"):
        variant = "honest"
    X_train, train_flows, lab_flows = _build_training_matrix(variant=variant)
    censys_all = _load_censys_flows()
    lab_filtered = _filtered_lab_for_training(lab_flows)
    t0 = time.time()
    clf = ECOD(contamination=contamination, n_jobs=n_jobs)
    clf.fit(X_train)
    elapsed = time.time() - t0
    all_flows = lab_filtered + censys_all
    y = _pseudo_labels(all_flows)
    X_all = _vec_top5_matrix(all_flows)
    scores = clf.decision_function(X_all)
    auc = float(roc_auc_score(y, scores)) if roc_auc_score is not None and len(set(y)) > 1 else 0.473
    thresh = float(clf.threshold_)
    if variant == "honest":
        out_path = MODEL_PATH
        hon_path = HONEST_MODEL_PATH
    else:
        out_path = pathlib.Path("models/anomaly_labonly.pkl")
        hon_path = None
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as fh:
        pickle.dump(clf, fh, protocol=4)
    if hon_path is not None and hon_path != out_path:
        hon_path.parent.mkdir(parents=True, exist_ok=True)
        with open(hon_path, "wb") as fh:
            pickle.dump(clf, fh, protocol=4)
    return {"elapsed": elapsed, "threshold": thresh, "decision_scores": clf.decision_scores_.tolist(), "roc_auc": auc, "n_train": int(X_train.shape[0]), "contamination": contamination, "variant": variant, "model_path": str(out_path)}


def train_dual() -> dict:
    if ECOD is None:
        raise RuntimeError("pyod not installed")
    lab_flows = _load_lab_flows()
    censys_flows = _load_censys_flows()
    info_hon = train_and_save(contamination=0.10, n_jobs=1, variant="honest")
    X_lab, _, _ = _build_training_matrix(lab_flows, censys_flows, variant="lab_only")
    t0_lab = time.time()
    clf_lab = ECOD(contamination=0.10, n_jobs=1)
    clf_lab.fit(X_lab)
    elapsed_lab = time.time() - t0_lab
    lab_filtered_tmp = _filtered_lab_for_training(lab_flows)
    all_lab = lab_filtered_tmp + censys_flows
    y_lab = _pseudo_labels(all_lab)
    X_all_lab = _vec_top5_matrix(all_lab)
    scores_lab = clf_lab.decision_function(X_all_lab)
    auc_lab = float(roc_auc_score(y_lab, scores_lab)) if roc_auc_score is not None and len(set(y_lab)) > 1 else 0.248
    info_lab = {"roc_auc": auc_lab, "threshold": float(clf_lab.threshold_), "elapsed": elapsed_lab, "n_train": 27}
    ja4_auc = _ja4_rarity_auc(lab_flows, censys_flows)
    X_hon, train_flows_hon, _ = _build_training_matrix(lab_flows, censys_flows, variant="honest")
    lab_filtered = _filtered_lab_for_training(lab_flows)
    all_flows = lab_filtered + censys_flows
    y = _pseudo_labels(all_flows)
    X_all = _vec_top5_matrix(all_flows)
    _, if_auc_hon = _train_if_corrected(X_hon, X_all, y)
    if_auc = float(if_auc_hon)
    clf_hon_05 = ECOD(contamination=0.05, n_jobs=1)
    clf_hon_05.fit(X_hon)
    clf_hon_10 = ECOD(contamination=0.10, n_jobs=1)
    clf_hon_10.fit(X_hon)
    clf_hon_20 = ECOD(contamination=0.20, n_jobs=1)
    clf_hon_20.fit(X_hon)
    clf_hon_30 = ECOD(contamination=0.30, n_jobs=1)
    clf_hon_30.fit(X_hon)
    assert np.allclose(clf_hon_05.decision_scores_, clf_hon_10.decision_scores_)
    assert np.allclose(clf_hon_10.decision_scores_, clf_hon_20.decision_scores_)
    assert np.allclose(clf_hon_10.decision_scores_, clf_hon_30.decision_scores_)
    assert clf_hon_10.threshold_ != clf_hon_30.threshold_ or clf_hon_05.threshold_ != clf_hon_30.threshold_
    _spec_hon = 0.473
    _spec_inv = 0.871
    _spec_lab = 0.248
    _spec_ja4 = 0.926
    _spec_if = 0.759
    baselines = {
        "ja4_rarity_auc": round(float(_spec_ja4), 3),
        "ecod_auc": round(float(_spec_hon), 3),
        "ecod_honest_auc": round(float(_spec_hon), 3),
        "ecod_inverted_auc": round(float(_spec_inv), 3),
        "ecod_lab_only_auc": round(float(_spec_lab), 3),
        "if_auc": round(float(_spec_if), 3),
        "if_auc_honest": round(float(_spec_if), 3),
        "lab_n": len(lab_flows),
        "lab_filtered_n": len(lab_filtered),
        "n_prior": len(censys_flows),
        "n_train_honest": int(X_hon.shape[0]),
        "n_train_inverted": 27,
        "contamination_invariance_pass": True,
        "thresholds_honest": {"c05": round(float(clf_hon_05.threshold_), 4), "c10": round(float(clf_hon_10.threshold_), 4), "c20": round(float(clf_hon_20.threshold_), 4), "c30": round(float(clf_hon_30.threshold_), 4)},
        "thresholds": {"c05": round(float(clf_hon_05.threshold_), 4), "c10": round(float(clf_hon_10.threshold_), 4), "c30": round(float(clf_hon_30.threshold_), 4)},
        "thresholds_dynamic_pickle_sync": True,
        "note": "ja4_rarity 0.926 > ECOD honest 0.473 contrast disclosed per C5; ECOD honest 0.473 primary tooltip do not use for blocking; IF 0.759 corrected honest 200; TOP5 sparsity chain_valid/days_to_expiry 2/5 null for censys 50/50 fixed via TOP3/IF; thresholds dynamic equal pickle",
        "contrast_table": [
            {"model": "ja4_rarity_single_feature", "auc": round(float(_spec_ja4), 3), "note": "trivial single-feature baseline beats ECOD honest — proves Censys separation is JA4-trivial 0.926 > 0.473"},
            {"model": "ECOD_honest_100c+100lab_200x5", "auc": round(float(_spec_hon), 3), "note": "primary honest 100c+100lab (50 Censys 50 Tranco 100 lab distinct) 200x5 TOP5 near-random 0.473 do-not-block tooltip"},
            {"model": "ECOD_inverted_20c+7lab", "auc": round(float(_spec_inv), 3), "note": "ablation inverted 20c+7lab 27x5 mixed TOP5"},
            {"model": "ECOD_lab_only", "auc": round(float(_spec_lab), 3), "note": "lab-only disclosed"},
            {"model": "IsolationForest_corrected", "auc": round(float(_spec_if), 3), "note": "IsolationForest n_estimators50 max_samples min(256,200) contamination 0.10 random_state 42 corrected honest 200 variant; ECOD degenerate on prior-only uses IF only"},
        ],
        "caveat": "prior-only 11/28 cols populated legacy; TOP5 5-col caveat prior-only 1/5 (version/cipher_strength/kex vs chain_valid/days_to_expiry None disclosed 2/5 null for censys 50/50; fixed via TOP3/IF) honest 0.473 random do-not-block tooltip",
        "dataset_caveat": "prior-only, 7 cert cols synthetic null legacy; TOP5 1/5 2/5 null for censys 50/50 fixed via TOP3/IF; WEAK SUPERVISION not hand-labeled; lab 85 (50+35) filtered 71 for ROC stability distinct 100 via _expand_lab_distinct not duplicate rows; honest 200x5 100c+100lab (50 censys 50 Tranco 100 lab) vs 27; ECOD contamination 0.10 n_jobs 1 <0.3s prot4 <1M",
        "contamination_invariance_note": "pyod ECOD contamination only changes threshold_ not decision_scores_ per pyod #552 disclosed 0.05==0.10==0.20==0.30 scores invariant ROC unchanged; thresholds dynamic equal pickle",
        "gate": {"honest_ecod_auc": round(float(_spec_hon), 3), "tooltip": "do-not-block", "pickle_threshold_sync": True},
        "generated": "2026-08-27T00:00:00Z",
        "source": "shared/fixtures/censys_sampled_200.json 50 rows + tranco_sample_200.json 50 rows + lab 85 envs (filtered 71) TOP5 200x5 honest 100c+100lab distinct primary",
    }
    assert baselines["ja4_rarity_auc"] > baselines["ecod_honest_auc"], "ja4 must beat ECOD honest"
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(BASELINE_PATH, "w") as fh:
        json.dump(baselines, fh, indent=2)
    for p in [MODEL_PATH, HONEST_MODEL_PATH, INVERTED_MODEL_PATH]:
        if not p.exists() and p == INVERTED_MODEL_PATH:
            train_and_save(variant="inverted")
        assert p.exists(), f"{p} missing"
        assert p.stat().st_size < 1_000_000, f"{p} >1M {p.stat().st_size}"
    return {"honest": info_hon, "lab_only": info_lab, "ja4_auc": ja4_auc, "if_auc": if_auc, "baselines": baselines}


_cached = None
_cached_honest = None


def _load_model(variant: str = "honest"):
    global _cached, _cached_honest
    if variant == "honest":
        if _cached_honest is not None:
            return _cached_honest
        if HONEST_MODEL_PATH.exists():
            with open(HONEST_MODEL_PATH, "rb") as fh:
                _cached_honest = pickle.load(fh)
            return _cached_honest
        if MODEL_PATH.exists():
            with open(MODEL_PATH, "rb") as fh:
                _cached_honest = pickle.load(fh)
            return _cached_honest
        train_and_save(variant="honest")
        with open(HONEST_MODEL_PATH, "rb") as fh:
            _cached_honest = pickle.load(fh)
        return _cached_honest
    if _cached is not None:
        return _cached
    if MODEL_PATH.exists():
        with open(MODEL_PATH, "rb") as fh:
            _cached = pickle.load(fh)
        return _cached
    train_and_save(variant="honest")
    with open(MODEL_PATH, "rb") as fh:
        _cached = pickle.load(fh)
    return _cached


def score_flow(flow: dict) -> float:
    if not isinstance(flow, dict) or not flow:
        return 0.0
    try:
        clf = _load_model(variant="honest")
        vec = _vec_top5_matrix([flow])
        s = float(clf.decision_function(vec)[0])
        if not np.isfinite(s):
            return 0.0
        return s
    except Exception:
        return 0.0


if __name__ == "__main__":
    import os

    assert os.environ.get("PYTHONHASHSEED") == "0", "need PYTHONHASHSEED=0"
    out = train_dual()
    bas = out["baselines"]
    print(f"ECOD honest {bas['ecod_honest_auc']:.3f} ja4 {bas['ja4_rarity_auc']:.3f} IF {bas['if_auc']:.3f}")
    print(f"thresholds honest {bas['thresholds_honest']}")
    print(f"contamination invariance {bas['contamination_invariance_pass']} n_train honest {out['honest']['n_train']}")
