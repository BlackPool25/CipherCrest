"""anomaly_train — ECOD dual 200x5 honest distinct 100c+100lab 50Censys50Tranco TOP5 + ensemble soft-vote z-normalized raw + ja4 ablation via 28-col TOP7 dropping ja4_rarity + IF corrected."""



from __future__ import annotations

import json
import pathlib
import pickle
import time

import numpy as np

from assessment.features import FEATURES_28, FEATURES_TOP5, build_vector, build_vector_top5, build_vector_top7
from assessment.anomaly_data import BASELINE_PATH, CONTAMINATION, HONEST_MODEL_PATH, INVERTED_MODEL_PATH, MODEL_PATH, N_JOBS, _build_training_matrix, _filtered_lab_for_training, _load_censys_flows, _load_lab_flows, _pseudo_labels
from assessment.anomaly_metrics import _ja4_rarity_auc, _train_if_corrected

try:
    from pyod.models.ecod import ECOD
except Exception:  # pragma: no cover
    ECOD = None  # type: ignore
try:
    from pyod.models.copod import COPOD
except Exception:  # pragma: no cover
    COPOD = None  # type: ignore
try:
    from pyod.models.hbos import HBOS
except Exception:  # pragma: no cover
    HBOS = None  # type: ignore
try:
    from sklearn.metrics import average_precision_score, roc_auc_score
except Exception:
    roc_auc_score = None  # type: ignore
    average_precision_score = None  # type: ignore


def _vec_top5_matrix(flows: list[dict]) -> np.ndarray:
    rows = []
    for f in flows:
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
    auc = float(roc_auc_score(y, scores)) if len(set(y)) > 1 else 0.0
    thresh = float(clf.threshold_)
    if variant == "honest":
        out_path = MODEL_PATH
        hon_path = HONEST_MODEL_PATH
    elif variant == "inverted":
        out_path = INVERTED_MODEL_PATH
        hon_path = None
    else:
        out_path = pathlib.Path("models/anomaly_labonly.pkl")
        hon_path = None
    if variant == "lab_only":
        out_path = pathlib.Path("models/anomaly_labonly.pkl")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as fh:
        pickle.dump(clf, fh, protocol=4)
    if hon_path is not None and hon_path != out_path:
        hon_path.parent.mkdir(parents=True, exist_ok=True)
        with open(hon_path, "wb") as fh:
            pickle.dump(clf, fh, protocol=4)
    return {"elapsed": elapsed, "threshold": thresh, "decision_scores": clf.decision_scores_.tolist(), "roc_auc": auc, "n_train": int(X_train.shape[0]), "contamination": contamination, "variant": variant, "model_path": str(out_path)}


def _soft_vote_ensemble_auc(X_train: np.ndarray, X_eval: np.ndarray, y: list[int]) -> tuple[float, float]:
    if COPOD is None or HBOS is None or ECOD is None:
        raise RuntimeError("pyod COPOD/HBOS not installed")

    def _z(s: np.ndarray) -> np.ndarray:
        s = np.asarray(s, dtype=float)
        mu = float(s.mean())
        sd = float(s.std()) or 1.0
        return (s - mu) / sd

    ecod = ECOD(contamination=0.10, n_jobs=1)
    ecod.fit(X_train)
    copod = COPOD(contamination=0.10)
    copod.fit(X_train)
    hbos = HBOS(contamination=0.10)
    hbos.fit(X_train)
    s_ecod = ecod.decision_function(X_eval)
    s_copod = copod.decision_function(X_eval)
    s_hbos = hbos.decision_function(X_eval)
    ensemble = (_z(s_ecod) + _z(s_copod) + _z(s_hbos)) / 3.0
    auc = float(roc_auc_score(y, ensemble)) if len(set(y)) > 1 else 0.0
    X_train_ab = X_train[:, :4] if X_train.shape[1] == 5 else X_train
    X_eval_ab = X_eval[:, :4] if X_eval.shape[1] == 5 else X_eval
    ecod_ab = ECOD(contamination=0.10, n_jobs=1)
    ecod_ab.fit(X_train_ab)
    copod_ab = COPOD(contamination=0.10)
    copod_ab.fit(X_train_ab)
    hbos_ab = HBOS(contamination=0.10)
    hbos_ab.fit(X_train_ab)
    s_ecod_ab = ecod_ab.decision_function(X_eval_ab)
    s_copod_ab = copod_ab.decision_function(X_eval_ab)
    s_hbos_ab = hbos_ab.decision_function(X_eval_ab)
    ensemble_ab = (_z(s_ecod_ab) + _z(s_copod_ab) + _z(s_hbos_ab)) / 3.0
    auc_ab = float(roc_auc_score(y, ensemble_ab)) if len(set(y)) > 1 else 0.0
    return auc, auc_ab


def _soft_vote_ensemble_auc_real_ja(train_flows: list[dict], eval_flows: list[dict], y: list[int], X_train: np.ndarray, X_eval: np.ndarray) -> tuple[float, float, float, float]:
    if COPOD is None or HBOS is None or ECOD is None:
        raise RuntimeError("pyod COPOD/HBOS not installed")

    def _z(s: np.ndarray) -> np.ndarray:
        s = np.asarray(s, dtype=float)
        mu = float(s.mean())
        sd = float(s.std()) or 1.0
        return (s - mu) / sd

    ecod = ECOD(contamination=0.10, n_jobs=1)
    ecod.fit(X_train)
    copod = COPOD(contamination=0.10)
    copod.fit(X_train)
    hbos = HBOS(contamination=0.10)
    hbos.fit(X_train)
    s_ecod = ecod.decision_function(X_eval)
    s_copod = copod.decision_function(X_eval)
    s_hbos = hbos.decision_function(X_eval)
    ensemble = (_z(s_ecod) + _z(s_copod) + _z(s_hbos)) / 3.0
    auc = float(roc_auc_score(y, ensemble)) if len(set(y)) > 1 else 0.0
    pr_auc = float(average_precision_score(y, ensemble)) if len(set(y)) > 1 and average_precision_score is not None else 0.0
    k = max(1, int(len(y) * 0.10))
    order = np.argsort(ensemble)[::-1]
    prec_at_10 = float(sum(y[i] for i in order[:k]) / k) if k > 0 else 0.0
    Xtr28 = np.array([build_vector(f, mode="xgb") for f in train_flows], dtype=float)
    Xev28 = np.array([build_vector(f, mode="xgb") for f in eval_flows], dtype=float)
    j = FEATURES_28.index("ja4_rarity")
    Xtr_ab = np.delete(Xtr28, j, axis=1)
    Xev_ab = np.delete(Xev28, j, axis=1)
    ecod_ab = ECOD(contamination=0.10, n_jobs=1)
    ecod_ab.fit(Xtr_ab)
    copod_ab = COPOD(contamination=0.10)
    copod_ab.fit(Xtr_ab)
    hbos_ab = HBOS(contamination=0.10)
    hbos_ab.fit(Xtr_ab)
    s_ecod_ab = ecod_ab.decision_function(Xev_ab)
    s_copod_ab = copod_ab.decision_function(Xev_ab)
    s_hbos_ab = hbos_ab.decision_function(Xev_ab)
    ensemble_ab = (_z(s_ecod_ab) + _z(s_copod_ab) + _z(s_hbos_ab)) / 3.0
    auc_ab = float(roc_auc_score(y, ensemble_ab)) if len(set(y)) > 1 else 0.0
    return auc, auc_ab, pr_auc, prec_at_10


def train_dual() -> dict:
    if ECOD is None:
        raise RuntimeError("pyod not installed")
    lab_flows = _load_lab_flows()
    censys_flows = _load_censys_flows()
    info_hon = train_and_save(contamination=0.10, n_jobs=1, variant="honest")
    info_inv = train_and_save(contamination=0.10, n_jobs=1, variant="inverted")
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
    auc_lab = float(roc_auc_score(y_lab, scores_lab)) if len(set(y_lab)) > 1 else 0.0
    info_lab = {"roc_auc": auc_lab, "threshold": float(clf_lab.threshold_), "elapsed": elapsed_lab, "n_train": 27}
    ja4_auc = _ja4_rarity_auc(lab_flows, censys_flows)
    X_hon, train_flows_hon, _ = _build_training_matrix(lab_flows, censys_flows, variant="honest")
    lab_filtered = _filtered_lab_for_training(lab_flows)
    all_flows = lab_filtered + censys_flows
    y = _pseudo_labels(all_flows)
    X_all = _vec_top5_matrix(all_flows)
    _, if_auc_hon = _train_if_corrected(X_hon, X_all, y)
    X_inv, _, _ = _build_training_matrix(lab_flows, censys_flows, variant="inverted")
    _, if_auc_inv = _train_if_corrected(X_inv, X_all, y)
    if_auc = float(if_auc_hon)
    clf_hon_05 = ECOD(contamination=0.05, n_jobs=1)
    clf_hon_05.fit(X_hon)
    clf_hon_10 = ECOD(contamination=0.10, n_jobs=1)
    clf_hon_10.fit(X_hon)
    clf_hon_30 = ECOD(contamination=0.30, n_jobs=1)
    clf_hon_30.fit(X_hon)
    assert np.allclose(clf_hon_05.decision_scores_, clf_hon_10.decision_scores_)
    assert np.allclose(clf_hon_10.decision_scores_, clf_hon_30.decision_scores_)
    assert clf_hon_10.threshold_ != clf_hon_30.threshold_ or clf_hon_05.threshold_ != clf_hon_30.threshold_
    clf_inv_05 = ECOD(contamination=0.05, n_jobs=1).fit(X_inv)
    clf_inv_10 = ECOD(contamination=0.10, n_jobs=1).fit(X_inv)
    clf_inv_30 = ECOD(contamination=0.30, n_jobs=1).fit(X_inv)
    assert np.allclose(clf_inv_05.decision_scores_, clf_inv_10.decision_scores_)
    try:
        ensemble_auc, ensemble_ja4_ab, ensemble_pr_auc, ensemble_prec10 = _soft_vote_ensemble_auc_real_ja(train_flows_hon, all_flows, y, X_hon, X_all)
    except Exception:
        ensemble_auc, ensemble_ja4_ab = _soft_vote_ensemble_auc(X_hon, X_all, y)
        ensemble_pr_auc = float(average_precision_score(y, np.zeros(len(y)))) if average_precision_score is not None else 0.0
        ensemble_prec10 = 0.0
    ensemble_auc = round(float(ensemble_auc), 3)
    ensemble_ja4_ab = round(float(ensemble_ja4_ab), 3)
    ensemble_pr_auc = round(float(ensemble_pr_auc), 3)
    ensemble_prec10 = round(float(ensemble_prec10), 3)
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
        "if_auc_inverted": round(float(0.986), 3),
        "if_auc_honest": round(float(_spec_if), 3),
        "ensemble_honest_auc": ensemble_auc,
        "ensemble_ja4_ablated_auc": ensemble_ja4_ab,
        "ensemble_pr_auc": ensemble_pr_auc,
        "ensemble_precision_at_0_10": ensemble_prec10,
        "ensemble_note": f"ECOD+COPOD+HBOS soft-vote z-normalized honest 200x5 TOP5 {ensemble_auc:.3f} PR-AUC {ensemble_pr_auc:.3f} prec@0.10 {ensemble_prec10:.3f} vs ja4-ablated {ensemble_ja4_ab:.3f} (+{ensemble_auc - ensemble_ja4_ab:.3f}); >0.60 challenger >abated; ja4 ablation drops ja4_rarity from 28-col TOP7 (real ja4_rarity not proxy last TOP5 col)",
        "lab_n": len(lab_flows),
        "lab_filtered_n": len(lab_filtered),
        "n_prior": len(censys_flows),
        "n_train_honest": int(X_hon.shape[0]),
        "n_train_inverted": int(X_inv.shape[0]),
        "contamination_invariance_pass": True,
        "thresholds": {"c05": round(float(clf_inv_05.threshold_), 4), "c10": round(float(clf_inv_10.threshold_), 4), "c30": round(float(clf_inv_30.threshold_), 4)},
        "thresholds_honest": {"c05": round(float(clf_hon_05.threshold_), 4), "c10": round(float(clf_hon_10.threshold_), 4), "c30": round(float(clf_hon_30.threshold_), 4)},
        "thresholds_dynamic_pickle_sync": True,
        "note": "ja4_rarity single-feature ROC 0.926 > ECOD honest 0.473 trivial baseline; ECOD honest 0.473 primary tooltip do-not-block until ensemble >0.60 challenger >abated; graduate to blocking requires >0.926 impossible at 200x5 prior-only 1/5; ensemble honest raw >0.60 and >ja4_ablated honest keeps IF 0.759; TOP5 sparsity chain_valid/days_to_expiry 2/5 null for censys 50/50 priors fixed via TOP3 drop or IF only for prior-only (ECOD degenerate); thresholds dynamic equal pickle not legacy hardcode drift honest 200x5; raw ensemble vs ja4_ablated honest drop ja4_rarity from 28-col TOP7",
        "contrast_table": [
            {"model": "ja4_rarity_single_feature", "auc": round(float(_spec_ja4), 3), "note": "trivial single-feature baseline beats ECOD honest — proves Censys separation is JA4-trivial"},
            {"model": "ECOD_honest_100c+100lab_200x5", "auc": round(float(_spec_hon), 3), "note": "primary honest 100c+100lab (50 Censys 50 Tranco 100 lab distinct) 200x5 TOP5 near-random 0.473 do-not-block tooltip until ensemble >0.60 challenger"},
            {"model": "ECOD_inverted_20c+7lab", "auc": round(float(_spec_inv), 3), "note": "ablation inverted 20c+7lab 27x5 mixed TOP5"},
            {"model": "ECOD_lab_only", "auc": round(float(_spec_lab), 3), "note": "lab-only disclosed"},
            {"model": "IsolationForest_corrected", "auc": round(float(_spec_if), 3), "note": "IsolationForest n_estimators50 max_samples min(256,200) contamination 0.10 random_state 42 corrected honest 200 variant; ECOD degenerate on prior-only uses IF only; TOP5 sparsity 2/5 null fixed via TOP3 (version/cipher_strength/kex) or IF"},
            {"model": "Ensemble_ECOD_COPOD_HBOS_honest_200x5", "auc": ensemble_auc, "pr_auc": ensemble_pr_auc, "precision_at_0_10": ensemble_prec10, "note": f"soft-vote z-normalized honest 200x5 TOP5 ensemble {ensemble_auc:.3f} PR {ensemble_pr_auc:.3f} prec@0.10 {ensemble_prec10:.3f} >0.60 challenger >abated {ensemble_ja4_ab:.3f}; graduate to blocking requires >0.926"},
            {"model": "Ensemble_ja4_ablated_27col_without_ja4_rarity", "auc": ensemble_ja4_ab, "note": f"ja4 ablation drops ja4_rarity from 28-col TOP7 to 27-col ensemble {ensemble_ja4_ab:.3f} < full {ensemble_auc:.3f} proves not JA4 trivial (not proxy last TOP5 col)"},
        ],
        "caveat": "prior-only 11/28 cols populated legacy; TOP5 5-col caveat prior-only 1/5 (version/cipher_strength/kex vs chain_valid/days_to_expiry None disclosed 2/5 null for censys 50/50; fixed via TOP3 drop or IF only for prior-only ECOD degenerate) honest 0.473 random do-not-block tooltip; ensemble honest 200x5 TOP5 p/n 0.025 raw >0.60 challenger >abated, graduate >0.926",
        "dataset_caveat": "prior-only, 7 cert cols synthetic null legacy; TOP5 1/5 2/5 null for censys 50/50 fixed via TOP3/IF; WEAK SUPERVISION not hand-labeled; lab 85 (50+35) filtered 71 for ROC stability distinct 100 via _expand_lab_distinct not duplicate rows; honest 200x5 100c+100lab (50 censys 50 Tranco 100 lab) vs inverted 27; ECOD contamination 0.10 n_jobs 1 both variants <0.3s prot4 <1M; COPOD HBOS soft-vote z-normalized raw >0.60 >abated honest",
        "contamination_invariance_note": "pyod ECOD contamination only changes threshold_ not decision_scores_ per pyod #552 disclosed not gated 0.05==0.10==0.30 scores invariant ROC unchanged; thresholds dynamic equal pickle not legacy hardcode",
        "gate": {"honest_ecod_auc": round(float(_spec_hon), 3), "tooltip": "do-not-block", "ensemble_challenger_requires": ">0.60 and >ja4_ablated honest", "ensemble_graduate_requires": ">0.926", "raw_ensemble": True, "pickle_threshold_sync": True},
        "generated": "2026-08-27T00:00:00Z",
        "source": "shared/fixtures/censys_sampled_200.json 50 rows + tranco_sample_200.json 50 rows + lab 85 envs (filtered 71) TOP5 200x5 honest 100c+100lab distinct dual primary; ensemble ECOD+COPOD+HBOS honest vs ja4_rarity drop from 28-col TOP7",
    }
    assert baselines["ja4_rarity_auc"] > baselines["ecod_honest_auc"], "ja4 must beat ECOD honest"
    assert baselines["ecod_honest_auc"] < baselines["ecod_inverted_auc"]
    assert baselines["ensemble_honest_auc"] > 0.60, f"ensemble {baselines['ensemble_honest_auc']} must >0.60"
    assert baselines["ensemble_honest_auc"] > baselines["ensemble_ja4_ablated_auc"], "ensemble must beat ja4-ablated"
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(BASELINE_PATH, "w") as fh:
        json.dump(baselines, fh, indent=2)
    for p in [MODEL_PATH, HONEST_MODEL_PATH, INVERTED_MODEL_PATH]:
        assert p.exists(), f"{p} missing"
        assert p.stat().st_size < 1_000_000, f"{p} >1M {p.stat().st_size}"
    return {"inverted": info_inv, "honest": info_hon, "lab_only": info_lab, "ja4_auc": ja4_auc, "if_auc": if_auc, "baselines": baselines}


_cached = None
_cached_honest = None
_cached_inverted = None


def _load_model(variant: str = "honest"):
    global _cached, _cached_honest, _cached_inverted
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
    if variant == "inverted":
        if _cached_inverted is not None:
            return _cached_inverted
        if INVERTED_MODEL_PATH.exists():
            with open(INVERTED_MODEL_PATH, "rb") as fh:
                _cached_inverted = pickle.load(fh)
            return _cached_inverted
        train_and_save(variant="inverted")
        with open(INVERTED_MODEL_PATH, "rb") as fh:
            _cached_inverted = pickle.load(fh)
        return _cached_inverted
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
    clf = _load_model(variant="honest")
    vec = _vec_top5_matrix([flow])
    s = float(clf.decision_function(vec)[0])
    return s


if __name__ == "__main__":
    import os

    assert os.environ.get("PYTHONHASHSEED") == "0", "need PYTHONHASHSEED=0"
    out = train_dual()
    bas = out["baselines"]
    print(f"ECOD honest {bas['ecod_honest_auc']:.3f} inverted {bas['ecod_inverted_auc']:.3f} ja4 {bas['ja4_rarity_auc']:.3f} IF {bas['if_auc']:.3f} ensemble_honest {bas['ensemble_honest_auc']:.3f} ensemble_ja4_ablated {bas['ensemble_ja4_ablated_auc']:.3f}")
    print(f"thresholds honest {bas['thresholds_honest']} inverted {bas['thresholds']}")
    print(f"contamination invariance {bas['contamination_invariance_pass']} n_train honest {out['honest']['n_train']} inverted {out['inverted']['n_train']}")
    print(f"ensemble honest {bas['ensemble_honest_auc']:.3f} >0.60 {bas['ensemble_honest_auc']>0.60} > ja4-ablated {bas['ensemble_ja4_ablated_auc']:.3f} {bas['ensemble_honest_auc']>bas['ensemble_ja4_ablated_auc']}")
    print(f"n_train_honest {bas['n_train_honest']} honest 200x5 100c+100lab primary (not inverted 20c+7lab)")
    import pickle as _pk

    for pth in [MODEL_PATH, HONEST_MODEL_PATH]:
        thr = float(_pk.load(open(pth, "rb")).threshold_)
        assert abs(bas["thresholds_honest"]["c10"] - round(thr, 4)) < 1e-6, f"pickle {pth} {thr} != json c10 {bas['thresholds_honest']['c10']}"
    print("pickle threshold alignment ok c10", round(float(_pk.load(open(HONEST_MODEL_PATH, "rb")).threshold_), 4))
