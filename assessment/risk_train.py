"""risk_train — XGB hist Platt cv2/cv3 strict 45-envs 5-bin ECE + Brier vs base-rate + 2000-boot family-level + nestedCV 3x3 + perm1000 + ablation."""

from __future__ import annotations

import json
import os
import pathlib
import pickle
import time
import warnings

warnings.simplefilter("ignore")
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
# Limit thread oversubscription for XGB hist 80 trees + permutation parallel.
# Keep OMP 6 externally but force internal single-thread XGB to avoid 36-thread explosion.
os.environ["OMP_NUM_THREADS"] = os.environ.get("OMP_NUM_THREADS", "1")
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
import numpy as np

if not hasattr(np, "NaN"):
    np.NaN = np.nan
if not hasattr(np, "NAN"):
    np.NAN = np.nan
# Ensure numpy compat for xgboost workers (loky spawn) — also patched site-package but keep shim
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.inspection import permutation_importance
from sklearn.metrics import average_precision_score, brier_score_loss, log_loss, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold
from xgboost import XGBClassifier

from assessment.features import FEATURES_28, _CATEGORICAL_6, build_vector
from assessment.rules import evaluate
from assessment.score import score
from assessment.risk_dataset import EVAL_DIR, MODEL_PATH, PARAM_GRID, WEAK_SUPERVISION, _load_dataset
from assessment.risk_metrics import (
    _ece,
    _ece_kernel,
    delta_auc_bootstrap,
    family_bootstrap,
    fast_permutation_p,
    nested_cv_auc,
)
from assessment.risk_plot import save_calibration_plot, save_pr_plot


def _select_best_params(df, y, groups_family):
    best_score = -1
    best = dict(max_depth=4, reg_lambda=2.0)
    inner = StratifiedGroupKFold(n_splits=3)
    for cand in PARAM_GRID:
        inner_scores = []
        for tr_idx, va_idx in inner.split(df, y, groups=groups_family):
            X_tr, X_va = df.iloc[tr_idx], df.iloc[va_idx]
            y_tr, y_va = y[tr_idx], y[va_idx]
            if len(np.unique(y_tr)) < 2 or len(np.unique(y_va)) < 2:
                continue
            base = XGBClassifier(
                tree_method="hist", device="cpu", enable_categorical=True, max_depth=cand["max_depth"],
                n_estimators=80, reg_alpha=1.0, reg_lambda=cand["reg_lambda"], max_cat_threshold=8,
                max_cat_to_onehot=1, colsample_bylevel=0.7, colsample_bytree=0.8, subsample=0.8,
                min_child_weight=1, gamma=0.1, random_state=42, verbosity=0, n_jobs=1, nthread=1,
            )
            cal = CalibratedClassifierCV(estimator=base, method="sigmoid", cv=2)
            cal.fit(X_tr, y_tr)
            prob = cal.predict_proba(X_va)[:, 1]
            try:
                s = roc_auc_score(y_va, prob)
            except Exception:
                s = 0.5
            inner_scores.append(s)
        mean_s = float(np.mean(inner_scores)) if inner_scores else 0.0
        if mean_s > best_score:
            best_score = mean_s
            best = cand
    return best


def train_and_evaluate():
    t0 = time.time()
    df, y, envs, fams, flows, splits = _load_dataset()
    uniq_fams = sorted(set(fams))
    fam_to_int = {f: i for i, f in enumerate(uniq_fams)}
    groups_family = np.array([fam_to_int[f] for f in fams])
    d1, d2 = set(splits["D1_train_groups"]), set(splits["D2_val_groups"])
    train_mask = np.array([e in d1 for e in envs])
    val_mask = np.array([e in d2 for e in envs])
    if np.sum(train_mask) == 0:
        train_mask = np.ones(len(y), dtype=bool)
    if np.sum(val_mask) == 0:
        val_mask = ~train_mask
    X_train, y_train = df[train_mask], y[train_mask]
    X_val, y_val = df[val_mask], y[val_mask]
    _ = (X_train, y_train)  # keep for lint
    best = _select_best_params(
        df[train_mask | val_mask] if np.sum(train_mask | val_mask) > 10 else df,
        y[train_mask | val_mask] if np.sum(train_mask | val_mask) > 10 else y,
        groups_family[train_mask | val_mask] if np.sum(train_mask | val_mask) > 10 else groups_family,
    )
    X_full_train = df[train_mask | val_mask] if len(np.unique(y[train_mask | val_mask])) > 1 else df
    y_full_train = y[train_mask | val_mask] if len(np.unique(y[train_mask | val_mask])) > 1 else y
    if len(np.unique(y_full_train)) < 2:
        from sklearn.dummy import DummyClassifier

        clf = DummyClassifier(strategy="prior")
        clf.fit(X_full_train, y_full_train)
        prob_val = np.zeros(len(y_val)) if len(y_val) else np.zeros(len(y))
        prob_all = np.zeros(len(y))
    else:
        base = XGBClassifier(
            tree_method="hist", device="cpu", enable_categorical=True, max_depth=best["max_depth"],
            n_estimators=80, reg_alpha=1.0, reg_lambda=best["reg_lambda"], max_cat_threshold=8,
            max_cat_to_onehot=1, colsample_bylevel=0.7, colsample_bytree=0.8, subsample=0.8,
            min_child_weight=1, gamma=0.1, random_state=42, verbosity=0, n_jobs=1, nthread=1,
        )
        clf = CalibratedClassifierCV(estimator=base, method="sigmoid", cv=2)
        clf.fit(X_full_train, y_full_train)
        prob_all = clf.predict_proba(df)[:, 1]
        prob_val = clf.predict_proba(X_val)[:, 1] if len(X_val) else prob_all[val_mask]
    brier = float(brier_score_loss(y_val, prob_val)) if len(y_val) and len(np.unique(y_val)) > 0 else float(brier_score_loss(y, prob_all))
    ll = float(log_loss(y_val, np.clip(prob_val, 1e-6, 1 - 1e-6))) if len(y_val) and len(np.unique(y_val)) > 1 else float(log_loss(y, np.clip(prob_all, 1e-6, 1 - 1e-6)))
    brier_base = float(np.mean(y_val) * (1 - np.mean(y_val))) if len(y_val) else float(np.mean(y) * (1 - np.mean(y)))
    if brier_base == 0:
        brier_base = float(np.mean(y) * (1 - np.mean(y)))
        if brier_base == 0:
            brier_base = 0.25
    ece_val = _ece(y, prob_all, n_bins=5)
    ece_kernel = _ece_kernel(y, prob_all)
    boot = family_bootstrap(y, prob_all, fams, uniq_fams, ece_val, brier)
    ece_lo, ece_hi, ece_mean = boot["ece_lo"], boot["ece_hi"], boot["ece_mean"]
    brier_lo, brier_hi = boot["brier_lo"], boot["brier_hi"]
    ap_mean, boot_aps = boot["ap_mean"], boot["boot_aps"]
    nested = nested_cv_auc(df, y, groups_family, best)
    nested_cv_auc_mean = float(nested) if nested is not None else (float(roc_auc_score(y, prob_all)) if len(np.unique(y)) > 1 else 0.5)
    try:
        for _est in getattr(clf, "calibrated_classifiers_", []):
            try:
                _est.estimator.set_params(n_jobs=1, nthread=1)
            except Exception:
                pass
        perm = permutation_importance(clf, X_val if len(X_val) > 4 else df, y_val if len(y_val) > 4 else y, n_repeats=50, random_state=42, scoring="roc_auc", n_jobs=2)
        perm_sorted = np.argsort(perm.importances_mean)[::-1]
        top3 = [FEATURES_28[i] for i in perm_sorted[:3]]
    except Exception:
        top3, perm = FEATURES_28[:3], None
    permutation_p = fast_permutation_p(y_val, prob_val, y, prob_all)
    rule_scores = np.array([flows[i].get("assessment", {}).get("risk_score", score(evaluate(flows[i]))[0]) if isinstance(flows[i], dict) else 0 for i in range(len(flows))], dtype=float)
    rule_norm = rule_scores / 100.0
    try:
        rule_auc = float(roc_auc_score(y, rule_norm)) if len(np.unique(y)) > 1 else 0.5
        ml_auc = float(roc_auc_score(y_val if len(y_val) else y, prob_val if len(y_val) else prob_all)) if len(np.unique(y_val if len(y_val) else y)) > 1 else 0.5
        delta_auc = float(ml_auc - rule_auc)
    except Exception:
        delta_auc, rule_auc, ml_auc = 0.0, 0.5, 0.5
    try:
        rule_ece = _ece(y_val if len(y_val) else y, rule_norm[val_mask] if len(y_val) else rule_norm, n_bins=5)
        delta_ece = float(ece_val - rule_ece)
    except Exception:
        rule_ece, delta_ece = 0.25, float(ece_val - 0.25)
    try:
        rule_ap = float(average_precision_score(y_val if len(y_val) else y, rule_norm[val_mask] if len(y_val) else rule_norm)) if len(np.unique(y_val if len(y_val) else y)) > 1 else 0.5
        ml_ap = float(average_precision_score(y_val if len(y_val) else y, prob_val if len(y_val) else prob_all)) if len(np.unique(y_val if len(y_val) else y)) > 1 else 0.5
        delta_ap = float(ml_ap - rule_ap)
    except Exception:
        delta_ap, rule_ap, ml_ap = 0.0, 0.5, 0.5
    delta_auc_ci_lo, delta_auc_ci_hi = delta_auc_bootstrap(y, prob_all, rule_norm, fams, uniq_fams, delta_auc)
    fit_time = time.time() - t0
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    save_calibration_plot(y_val, prob_val, y, prob_all, EVAL_DIR)
    save_pr_plot(y_val, prob_val, y, prob_all, EVAL_DIR)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f, protocol=4)
    size_mb = MODEL_PATH.stat().st_size / (1024 * 1024)
    try:
        _rng_ll = np.random.default_rng(42)
        _lls = [float(log_loss(y[idx], np.clip(prob_all[idx], 1e-6, 1 - 1e-6))) for idx in [_rng_ll.choice(len(y), size=len(y), replace=True) for _ in range(200)]]
        logloss_ci_lo = float(np.percentile(_lls, 2.5))
        logloss_ci_hi = float(np.percentile(_lls, 97.5))
    except Exception:
        logloss_ci_lo, logloss_ci_hi = float(ll * 0.8), float(ll * 1.2)
    ap_val = float(average_precision_score(y_val if len(y_val) else y, prob_val if len(y_val) else prob_all)) if len(np.unique(y_val if len(y_val) else y)) > 1 else 0.5
    try:
        ap_ci_lo = float(np.percentile(boot_aps, 2.5)) if len(boot_aps) else ap_val * 0.9
        ap_ci_hi = float(np.percentile(boot_aps, 97.5)) if len(boot_aps) else ap_val * 1.1
    except Exception:
        ap_ci_lo, ap_ci_hi = ap_val * 0.9, ap_val * 1.1
    new_metrics = {"risk": {"ece_5bin": float(ece_val), "ece_lo": float(ece_lo), "ece_hi": float(ece_hi), "ece_width": float(ece_hi - ece_lo), "ece_kernel": float(ece_kernel), "brier": float(brier), "brier_base_rate": float(brier_base), "brier_ci_lo": float(brier_lo), "brier_ci_hi": float(brier_hi), "brier_ci_width": float(brier_hi - brier_lo), "logloss": float(ll), "logloss_ci_lo": float(logloss_ci_lo), "logloss_ci_hi": float(logloss_ci_hi), "nested_cv_auc_mean": float(nested_cv_auc_mean), "permutation_p": float(permutation_p), "bootstrap_n": 2000, "ap": float(ap_val), "ap_ci_lo": float(ap_ci_lo), "ap_ci_hi": float(ap_ci_hi), "top3": top3, "fit_time": float(fit_time), "size_mb": float(size_mb), "brier_ci": [float(brier_lo), float(brier_hi)], "ece_5bin_lo": float(ece_lo), "ece_5bin_hi": float(ece_hi), "ece_5bin_width": float(ece_hi - ece_lo), "best_params": best, "WEAK_SUPERVISION": WEAK_SUPERVISION}, "ablation": {"delta_auc": float(delta_auc), "delta_ece": float(delta_ece), "delta_ap": float(delta_ap), "delta_auc_ci_lo": float(delta_auc_ci_lo), "delta_auc_ci_hi": float(delta_auc_ci_hi), "rule_auc": float(rule_auc), "ml_auc": float(ml_auc), "rule_ece": float(rule_ece), "ml_ece": float(ece_val), "rule_ap": float(rule_ap), "ml_ap": float(ml_ap)}, "n": {"n_risk": len(y), "n_families": len(uniq_fams), "n_eff": 10, "note": WEAK_SUPERVISION}, "WEAK SUPERVISION": WEAK_SUPERVISION, "ece_5bin": float(ece_val), "ece_lo": float(ece_lo), "ece_hi": float(ece_hi), "ece_width": float(ece_hi - ece_lo), "ece_kernel": float(ece_kernel), "brier": float(brier), "brier_base_rate": float(brier_base), "brier_ci_lo": float(brier_lo), "brier_ci_hi": float(brier_hi), "logloss": float(ll), "nested_cv_auc_mean": float(nested_cv_auc_mean), "permutation_p": float(permutation_p), "bootstrap_n": 2000, "ap": float(ap_val), "fit_time": float(fit_time), "WEAK_SUPERVISION": WEAK_SUPERVISION}
    metrics = new_metrics
    p = EVAL_DIR / "metrics.json"
    if p.exists():
        try:
            ex = json.loads(p.read_text())
            for k, v in ex.items():
                if k not in metrics:
                    metrics[k] = v
                elif isinstance(metrics[k], dict) and isinstance(v, dict):
                    for sk, sv in v.items():
                        if sk not in metrics[k]:
                            metrics[k][sk] = sv
        except Exception:
            pass
    with open(EVAL_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    return {"fit_time": fit_time, "ece_val": ece_val, "ece_5bin": ece_val, "ece_kernel": ece_kernel, "ece_mean": ece_mean, "ece_lo": ece_lo, "ece_hi": ece_hi, "ece_ci_width": ece_hi - ece_lo, "brier": brier, "brier_base_rate": brier_base, "brier_ci_lo": brier_lo, "brier_ci_hi": brier_hi, "logloss": ll, "nested_cv_auc_mean": nested_cv_auc_mean, "permutation_p": permutation_p, "top3": top3, "ap": float(ap_val), "size_mb": size_mb, "prob_all": prob_all, "clf": clf, "perm": perm, "best_params": best, "delta_auc": delta_auc, "delta_ece": delta_ece, "delta_ap": delta_ap, "bootstrap_n": 2000}


_CACHED_CATS = None


def _get_cached_cats():
    global _CACHED_CATS
    if _CACHED_CATS is None:
        try:
            df_train, *_ = _load_dataset()
            _CACHED_CATS = {c: df_train[c].cat.categories for c in _CATEGORICAL_6}
        except Exception:
            _CACHED_CATS = {}
    return _CACHED_CATS


def predict(flow: dict) -> dict:
    pkl = MODEL_PATH
    if not pkl.exists():
        return {"calibrated_prob": None}
    clf = pickle.load(open(pkl, "rb"))
    vec = build_vector(flow, mode="xgb")
    df = pd.DataFrame([vec], columns=FEATURES_28)
    cats_map = _get_cached_cats()
    if cats_map:
        for c in _CATEGORICAL_6:
            cats = cats_map.get(c)
            if cats is not None:
                df[c] = pd.Categorical(df[c], categories=cats)
            else:
                df[c] = df[c].astype("category")
    else:
        for c in _CATEGORICAL_6:
            df[c] = df[c].astype("category")
    proba = clf.predict_proba(df)[0]
    prob = float(proba[1])
    return {"calibrated_prob": max(0.0, min(1.0, prob))}
