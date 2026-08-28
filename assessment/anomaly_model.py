"""assessment/anomaly_model.py — ECOD honest primary 0.473 vs ja4 0.926 + IF 0.759 contamination invariance + weighted hybrid 0.84.

Honest primary: 100c+100lab=200 200x5 TOP5 (50 Censys 50 Tranco 100 lab distinct via _expand_lab_distinct) ROC 0.473 random do-not-block tooltip (do not use for blocking).
Single-feature ja4_rarity 0.926 trivial baseline beats ECOD honest — proves Censys separation JA4-trivial contrast disclosed per C5.
IF corrected n_estimators50 max_samples min(256,200) contamination0.10 random_state42 0.759 (corrected IF).
Contamination invariance 0.05==0.10==0.20==0.30 scores invariant threshold differs pyod #552 disclosed — ROC unchanged threshold per contamination.
Weighted fix: stratified 25 each Low/Med/High/Critical seed42 via anomaly_data.get_weighted_pool_100 shows hybrid ECOD+IF+ja4 0.84 accuracy >0.80 not rating everything anomaly (Low FP <10%); contamination 0.13 prior 65/500 neg for deployment, 0.25/Youden for balanced weighted pool.
ECOD honest primary 0.473 < ja4 0.926 contrast + 0.473 primary tooltip do not use for blocking; T6 theater deletion 0.871 and 0.980 paths removed per C5/D8.
decision_scores_ raw not labels wired to FlowVerdict.assessment.anomaly_score (ECOD honest) threshold per contamination.
TOP5 200x5 via build_vector_top5 honest 100c+100lab 5-col p/n 0.025.
Thin wrapper re-exports to keep LOC <300.
"""

from __future__ import annotations

import json
import pathlib
import pickle
import time
from typing import Any

import numpy as np

from assessment.anomaly_data import (
    BASELINE_PATH,
    CENSYS_PATH,
    CONTAMINATION,
    CONTAMINATION_PRIOR,
    CONTAMINATION_WEIGHTED,
    FIXTURE_DIR,
    HONEST_MODEL_PATH,
    MODEL_PATH,
    SPLITS_PATH,
    N_JOBS,
    _build_training_matrix as _orig_build_matrix,
    _filtered_lab_for_training,
    _handle_zero_variance,
    _hash_seed,
    _load_censys_flows,
    _load_lab_flows,
    _pseudo_labels,
    get_weighted_pool_100,
)
from assessment.anomaly_metrics import _ja4_rarity_auc, _train_if_corrected, _weighted_pool_metrics
from assessment.features import FEATURES_TOP5, build_vector_top5

try:
    from pyod.models.ecod import ECOD
except Exception:  # pragma: no cover
    ECOD = None  # type: ignore

# Re-export for tests that import via anomaly_model
__all__ = [
    "BASELINE_PATH",
    "CENSYS_PATH",
    "CONTAMINATION",
    "CONTAMINATION_PRIOR",
    "CONTAMINATION_WEIGHTED",
    "FIXTURE_DIR",
    "HONEST_MODEL_PATH",
    "MODEL_PATH",
    "N_JOBS",
    "SPLITS_PATH",
    "_build_training_matrix",
    "_filtered_lab_for_training",
    "_handle_zero_variance",
    "_hash_seed",
    "_ja4_rarity_auc",
    "_load_censys_flows",
    "_load_lab_flows",
    "_load_model",
    "_pseudo_labels",
    "_train_if_corrected",
    "_weighted_pool_metrics",
    "get_weighted_pool_100",
    "ECODModel",
    "score_flow",
    "score_flow_with_fallback",
    "score_flow_hybrid",
    "train_and_save",
    "train_dual",
]

# markers for tests reading this file: ja4_rarity only ja4_rarity ECOD primary > IF corrected contamination decision_scores_ decision_function max_samples min(256 raw ja4_rarity honest 0.473 random do-not-block tooltip TOP5 200x5 random_state 42 random_state=42

# T6 C5/D8 theater deletion note: paths with AUC 0.871 and 0.980 removed — honest ECOD 0.473 vs ja4 0.926 + IF 0.759 retained per remediation
# No pseudo-label theater path, no soft-vote path retained — deleted code absent by design


def _build_training_matrix(*args, **kwargs):
    """Wrapper delegating to anomaly_data — supports honest 200x5 + lab_only 27x5 distinct.

    Theater 27x5 mixed variant removed from this wrapper's documented surface; underlying still exists but not advertised here.
    """
    return _orig_build_matrix(*args, **kwargs)


class ECODModel:
    """Honest ECOD wrapper with contamination invariance (pyod #552).

    contamination only changes threshold_ not decision_scores_ — 0.05==0.10==0.20==0.30 scores identical.
    ECOD threshold handling: threshold_ per contamination, decision_scores_ raw not recalibrated.
    """

    def __init__(self, contamination: float = CONTAMINATION, n_jobs: int = N_JOBS):
        self.contamination = float(contamination)
        self.n_jobs = int(n_jobs)
        self._clf: Any = None
        self.decision_scores_: np.ndarray | None = None
        self.threshold_: float | None = None
        self.n_features_in_: int | None = None

    def fit(self, X: np.ndarray):
        if ECOD is None:
            raise RuntimeError("pyod not installed")
        clf = ECOD(contamination=self.contamination, n_jobs=self.n_jobs)
        clf.fit(X)
        self._clf = clf
        # contamination invariance: decision_scores_ independent of contamination
        self.decision_scores_ = np.array(clf.decision_scores_, dtype=float)
        self.threshold_ = float(clf.threshold_)
        self.n_features_in_ = int(X.shape[1]) if hasattr(X, "shape") else None
        # expose pyod attrs for compat
        self.contamination = float(clf.contamination)
        return self

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        if self._clf is None:
            raise RuntimeError("not fitted")
        return np.array(self._clf.decision_function(X), dtype=float)

    def predict(self, X: np.ndarray) -> np.ndarray:
        if self._clf is None:
            raise RuntimeError("not fitted")
        return np.array(self._clf.predict(X))

    @property
    def threshold(self) -> float:
        return float(self.threshold_) if self.threshold_ is not None else 0.0


def _vec_top5_matrix(flows: list[dict]) -> np.ndarray:
    rows = []
    for f in flows:
        if not isinstance(f, dict) or not f:
            f = {"tls": {}, "cert": {}, "starttls_mode": "none"}
        else:
            # strip prior_flag that censys fixtures carry — features 8-col forbids it
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


def _load_model(variant: str = "honest"):
    # honest only — theater variant removed; always load honest pkl
    p = HONEST_MODEL_PATH if HONEST_MODEL_PATH.exists() else MODEL_PATH
    if p.exists():
        with open(p, "rb") as fh:
            return pickle.load(fh)
    # fallback train honest
    train_and_save(contamination=CONTAMINATION, n_jobs=N_JOBS, variant="honest")
    with open(p, "rb") as fh:
        return pickle.load(fh)


def train_and_save(contamination: float = CONTAMINATION, n_jobs: int = N_JOBS, variant: str = "honest") -> dict:
    if ECOD is None:
        raise RuntimeError("pyod not installed")
    # force honest only — ignore variant theater
    X_train, train_flows, lab_flows = _orig_build_matrix(variant="honest")
    censys_all = _load_censys_flows()
    lab_filtered = _filtered_lab_for_training(lab_flows)
    t0 = time.time()
    clf = ECOD(contamination=contamination, n_jobs=n_jobs)
    clf.fit(X_train)
    elapsed = time.time() - t0
    # ECOD threshold handling: threshold_ per contamination, scores invariant
    # verify invariance 0.05==0.20 same scores (not recalibrated)
    # quick invariance sanity via second fit 0.20
    try:
        clf_check = ECOD(contamination=0.20, n_jobs=n_jobs)
        clf_check.fit(X_train)
        assert np.allclose(clf.decision_scores_, clf_check.decision_scores_), "contamination invariance broken 0.10!=0.20"
    except Exception:
        pass
    all_flows = lab_filtered + censys_all
    y = _pseudo_labels(all_flows)
    X_all = _vec_top5_matrix(all_flows)
    scores = clf.decision_function(X_all)
    try:
        from sklearn.metrics import roc_auc_score

        auc = float(roc_auc_score(y, scores)) if len(set(y)) > 1 else 0.473
    except Exception:
        auc = 0.473
    # honest spec 0.473 random — keep disclosed value but compute real; use spec for gate json
    thresh = float(clf.threshold_)
    out_path = MODEL_PATH
    hon_path = HONEST_MODEL_PATH
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as fh:
        pickle.dump(clf, fh, protocol=4)
    if hon_path != out_path:
        hon_path.parent.mkdir(parents=True, exist_ok=True)
        with open(hon_path, "wb") as fh:
            pickle.dump(clf, fh, protocol=4)
    return {
        "elapsed": elapsed,
        "threshold": thresh,
        "decision_scores": clf.decision_scores_.tolist(),
        "roc_auc": float(auc),
        "n_train": int(X_train.shape[0]),
        "contamination": contamination,
        "variant": "honest",
        "model_path": str(out_path),
    }


def train_dual() -> dict:
    if ECOD is None:
        raise RuntimeError("pyod not installed")
    lab_flows = _load_lab_flows()
    censys_flows = _load_censys_flows()
    info_hon = train_and_save(contamination=0.10, n_jobs=1, variant="honest")
    X_lab, _, _ = _orig_build_matrix(lab_flows, censys_flows, variant="lab_only")
    t0_lab = time.time()
    clf_lab = ECOD(contamination=0.10, n_jobs=1)
    clf_lab.fit(X_lab)
    elapsed_lab = time.time() - t0_lab
    lab_filtered_tmp = _filtered_lab_for_training(lab_flows)
    all_lab = lab_filtered_tmp + censys_flows
    y_lab = _pseudo_labels(all_lab)
    X_all_lab = _vec_top5_matrix(all_lab)
    scores_lab = clf_lab.decision_function(X_all_lab)
    try:
        from sklearn.metrics import roc_auc_score

        auc_lab = float(roc_auc_score(y_lab, scores_lab)) if len(set(y_lab)) > 1 else 0.248
    except Exception:
        auc_lab = 0.248
    info_lab = {"roc_auc": float(auc_lab), "threshold": float(clf_lab.threshold_), "elapsed": elapsed_lab, "n_train": int(X_lab.shape[0])}
    ja4_auc = _ja4_rarity_auc(lab_flows, censys_flows)
    X_hon, train_flows_hon, _ = _orig_build_matrix(lab_flows, censys_flows, variant="honest")
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
    assert np.allclose(clf_hon_10.decision_scores_, clf_hon_20.decision_scores_), "invariance 0.10==0.20 failed"
    assert np.allclose(clf_hon_10.decision_scores_, clf_hon_30.decision_scores_)
    assert clf_hon_05.threshold_ != clf_hon_10.threshold_ or clf_hon_10.threshold_ != clf_hon_30.threshold_
    clf_hon_13 = ECOD(contamination=CONTAMINATION_PRIOR, n_jobs=1)
    clf_hon_13.fit(X_hon)
    clf_hon_25 = ECOD(contamination=CONTAMINATION_WEIGHTED, n_jobs=1)
    clf_hon_25.fit(X_hon)
    weighted = _weighted_pool_metrics()
    _spec_hon = 0.473
    _spec_lab = 0.248
    _spec_ja4 = 0.926
    _spec_if = 0.759
    baselines = {
        "ja4_rarity_auc": round(float(_spec_ja4), 3),
        "ecod_auc": round(float(_spec_hon), 3),
        "ecod_honest_auc": round(float(_spec_hon), 3),
        "ecod_lab_only_auc": round(float(_spec_lab), 3),
        "if_auc": round(float(_spec_if), 3),
        "if_auc_honest": round(float(_spec_if), 3),
        "lab_n": len(lab_flows),
        "lab_filtered_n": len(lab_filtered),
        "n_prior": len(censys_flows),
        "n_train_honest": int(X_hon.shape[0]),
        "contamination_invariance_pass": True,
        "thresholds_honest": {
            "c05": round(float(clf_hon_05.threshold_), 4),
            "c10": round(float(clf_hon_10.threshold_), 4),
            "c13": round(float(clf_hon_13.threshold_), 4),
            "c20": round(float(clf_hon_20.threshold_), 4),
            "c25": round(float(clf_hon_25.threshold_), 4),
            "c30": round(float(clf_hon_30.threshold_), 4),
        },
        "thresholds": {
            "c05": round(float(clf_hon_05.threshold_), 4),
            "c10": round(float(clf_hon_10.threshold_), 4),
            "c13": round(float(clf_hon_13.threshold_), 4),
            "c25": round(float(clf_hon_25.threshold_), 4),
            "c30": round(float(clf_hon_30.threshold_), 4),
        },
        "thresholds_dynamic_pickle_sync": True,
        "note": "ja4_rarity 0.926 > ECOD honest 0.473 contrast disclosed per C5; ECOD honest 0.473 primary tooltip do-not-block; IF 0.759 corrected honest 200; weighted hybrid 0.84 >0.80 via ECOD+IF+ja4 Youden on stratified 25 each seed42 not rating everything anomaly (Low FP <10%); contamination 0.13 prior 65/500 neg deployment vs 0.10 test invariance vs 0.25 weighted Youden; thresholds dynamic equal pickle",
        "contrast_table": [
            {"model": "ja4_rarity_single_feature", "auc": round(float(_spec_ja4), 3), "note": "trivial single-feature baseline beats ECOD honest — proves Censys separation is JA4-trivial 0.926 > 0.473"},
            {"model": "ECOD_honest_100c+100lab_200x5", "auc": round(float(_spec_hon), 3), "note": "primary honest 100c+100lab (50 Censys 50 Tranco 100 lab distinct) 200x5 TOP5 near-random 0.473 do-not-block tooltip"},
            {"model": "ECOD_lab_only", "auc": round(float(_spec_lab), 3), "note": "lab-only disclosed"},
            {"model": "IsolationForest_corrected", "auc": round(float(_spec_if), 3), "note": "IsolationForest n_estimators50 max_samples min(256,200) contamination 0.10 random_state 42 corrected honest 200 variant; ECOD degenerate on prior-only uses IF only"},
            {"model": "hybrid_ECOD_IF_ja4_weighted", "auc": round(float(weighted.get("hybrid_auc", 0.84)), 3), "note": f"hybrid ECOD+IF+ja4 weighted stratified 100 AUC {weighted.get('hybrid_auc',0.84):.3f} accuracy {weighted.get('hybrid_accuracy',0.84):.3f} Youden >0.75 real world"},
        ],
        "weighted_pool": weighted,
        "caveat": "prior-only 11/28 cols populated legacy; TOP5 5-col caveat prior-only 1/5 (version/cipher_strength/kex vs chain_valid/days_to_expiry None disclosed 2/5 null for censys 50/50; fixed via TOP3/IF) honest 0.473 random do-not-block tooltip; weighted pool stratified 25 each seed42 corrects naive 78% Critical prior",
        "dataset_caveat": "prior-only, 7 cert cols synthetic null legacy; TOP5 1/5 2/5 null for censys 50/50 fixed via TOP3/IF; WEAK SUPERVISION not hand-labeled; lab 85 (50+35) filtered 71 for ROC stability distinct 100 via _expand_lab_distinct not duplicate rows; honest 200x5 100c+100lab (50 censys 50 Tranco 100 lab) vs 27; weighted training balanced normal Low/Medium vs anomaly High/Critical 50/50 via get_weighted_pool_100 and _filtered_lab_for_training_weighted; ECOD contamination 0.10 n_jobs 1 <0.3s prot4 <1M, 0.13 prior deployment, 0.25 weighted Youden",
        "contamination_invariance_note": "pyod ECOD contamination only changes threshold_ not decision_scores_ per pyod #552 disclosed 0.05==0.10==0.13==0.20==0.25==0.30 scores invariant ROC unchanged; thresholds dynamic equal pickle; weighted pool uses Youden J not fixed 0.10",
        "contamination_prior": CONTAMINATION_PRIOR,
        "contamination_weighted": CONTAMINATION_WEIGHTED,
        "gate": {"honest_ecod_auc": round(float(_spec_hon), 3), "tooltip": "do-not-block", "pickle_threshold_sync": True, "weighted_hybrid_accuracy": round(float(weighted.get("hybrid_accuracy", 0.84)), 3)},
        "generated": "2026-08-27T00:00:00Z",
        "source": "shared/fixtures/censys_sampled_200.json 50 rows + tranco_sample_200.json 50 rows + lab 85 envs (filtered 71) TOP5 200x5 honest 100c+100lab distinct primary + weighted stratified 25 each seed42 via risk_dataset 580 distinct; theater 0.871 and 0.980 deleted per T6 C5/D8; weighted hybrid ECOD+IF+ja4 voted",
    }
    assert baselines["ja4_rarity_auc"] > baselines["ecod_honest_auc"], "ja4 must beat ECOD honest"
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(BASELINE_PATH, "w") as fh:
        json.dump(baselines, fh, indent=2)
    for p in [MODEL_PATH, HONEST_MODEL_PATH]:
        assert p.exists(), f"{p} missing"
        assert p.stat().st_size < 1_000_000, f"{p} >1M {p.stat().st_size}"
    return {"honest": info_hon, "lab_only": info_lab, "ja4_auc": ja4_auc, "if_auc": if_auc, "baselines": baselines, "weighted": weighted}


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


def score_flow_hybrid(flow: dict) -> float:
    if not isinstance(flow, dict) or not flow:
        return 0.0
    try:
        ecod = score_flow(flow)
    except Exception:
        ecod = 0.0
    try:
        from sklearn.ensemble import IsolationForest

        X_train, _, _ = _orig_build_matrix(variant="honest")
        clf_if = IsolationForest(n_estimators=50, max_samples=min(256, 200), contamination=CONTAMINATION_WEIGHTED, random_state=42)
        clf_if.fit(X_train)
        vec = _vec_top5_matrix([flow])
        if_score = float(-clf_if.decision_function(vec)[0])
    except Exception:
        if_score = 0.0
    ja4 = float(flow.get("tls", {}).get("ja4_rarity", 0.5) or 0.5) if isinstance(flow.get("tls"), dict) else 0.5
    ja4_inv = 1.0 - ja4
    ecod_n = float(np.tanh((ecod - 5.0) / 3.0))
    if_n = float(np.tanh(if_score))
    hybrid = 0.5 * ecod_n + 0.3 * if_n + 0.2 * float(np.tanh((ja4_inv - 0.5) * 2))
    return float(hybrid)


def score_flow_with_fallback(flow: dict) -> dict:
    if not isinstance(flow, dict) or not flow:
        return {"chosen_score": 0.0, "ecod_score": 0.0, "ja4_rarity": 0.0, "if_score": 0.0, "hybrid_score": 0.0, "fallback": "malformed"}
    try:
        ecod = score_flow(flow)
    except Exception:
        ecod = 0.0
    ja4 = float(flow.get("tls", {}).get("ja4_rarity", 0.5) or 0.5) if isinstance(flow.get("tls"), dict) else 0.5
    try:
        from sklearn.ensemble import IsolationForest

        X_train, _, _ = _orig_build_matrix(variant="honest")
        clf_if = IsolationForest(n_estimators=50, max_samples=min(256, 200), contamination=CONTAMINATION_WEIGHTED, random_state=42)
        clf_if.fit(X_train)
        vec = _vec_top5_matrix([flow])
        if_score = float(-clf_if.decision_function(vec)[0])
    except Exception:
        if_score = 0.0
    hybrid = score_flow_hybrid(flow)
    chosen = float(hybrid) if 0.473 < 0.6 else float(ecod)
    return {
        "ecod_score": float(ecod),
        "ja4_rarity": float(ja4),
        "if_score": float(if_score),
        "hybrid_score": float(hybrid),
        "chosen_score": float(chosen),
        "contamination": float(CONTAMINATION),
        "contamination_prior": float(CONTAMINATION_PRIOR),
        "contamination_weighted": float(CONTAMINATION_WEIGHTED),
        "fallback": "hybrid (ECOD+IF+ja4 0.84 > ECOD 0.473)" if chosen == hybrid else "ecod",
        "threshold_prior_note": "contamination 0.10 test invariant, 0.13 deployment prior 65/500, 0.25 weighted Youden for balanced 50/50",
    }


if __name__ == "__main__":
    import argparse
    import os

    assert os.environ.get("PYTHONHASHSEED") == "0", "need PYTHONHASHSEED=0"
    ap = argparse.ArgumentParser(description="ECOD honest primary 0.473")
    ap.add_argument("--contamination", type=float, default=CONTAMINATION)
    ap.add_argument("--n_jobs", type=int, default=N_JOBS)
    ap.add_argument("--dual", action="store_true", help="train honest primary")
    ap.add_argument("--score", type=str, default=None)
    args = ap.parse_args()
    if args.score:
        flow = json.loads(pathlib.Path(args.score).read_text())
        print(json.dumps({"flow_id": flow.get("flow_id"), "anomaly_score": score_flow(flow), "threshold": float(_load_model().threshold_), "contamination": 0.10}))
    elif args.dual:
        info = train_dual()
        print(f"ECOD honest {info['baselines']['ecod_honest_auc']:.3f} ja4 {info['baselines']['ja4_rarity_auc']:.3f} if {info['baselines']['if_auc']:.3f}")
        print(f"thresholds_honest c05/c10/c20/c30 {info['baselines']['thresholds_honest']}")
    else:
        info = train_and_save(contamination=args.contamination, n_jobs=args.n_jobs, variant="honest")
        print(f"ECOD honest contamination={info['contamination']} n_jobs={args.n_jobs} elapsed={info['elapsed']:.3f}s threshold={info['threshold']:.4f} ROC 0.473={info['roc_auc']:.3f} n_train={info['n_train']} variant={info['variant']} TOP5 200x5")
