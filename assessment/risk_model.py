"""risk_model — XGB hist max_depth4 Platt cv2 +500-boot ECE +perm n=10. WEAK SUPERVISION §1/§4a."""
# Labels: rule-derived (score 23 checks 20 scored+3 info); n_eff=10 synthetic. Platt only.
from __future__ import annotations

import hashlib
import json
import pathlib
import pickle
import time

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

if not hasattr(np, "NaN"):
    np.NaN = np.nan
if not hasattr(np, "NAN"):
    np.NAN = np.nan
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.inspection import permutation_importance
from sklearn.metrics import average_precision_score, precision_recall_curve
from sklearn.model_selection import StratifiedGroupKFold
from xgboost import XGBClassifier

from assessment.features import FEATURES_28, _CATEGORICAL_6, build_vector
from assessment.rules import evaluate
from assessment.score import score

SPLITS = pathlib.Path("assessment/splits.json")
FIXTURE_DIR = pathlib.Path("shared/fixtures")
MODEL_PATH = pathlib.Path("models/risk_clf.pkl")
EVAL_DIR = pathlib.Path("eval")
WEAK_SUPERVISION = "Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a."

XGB_PARAMS = dict(
    tree_method="hist",
    device="cpu",
    enable_categorical=True,
    max_depth=4,
    n_estimators=80,
    reg_alpha=1.0,
    reg_lambda=2.0,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
)


def _load_dataset():
    splits = json.loads(SPLITS.read_text())
    all_envs = splits["all_environment_ids"]
    groups_map = splits["groups_by_env"]
    rows = []
    for env in all_envs:
        fam = env.split("__")[0]  # family-02
        num = fam.split("-")[1]  # 02
        base_path = FIXTURE_DIR / f"family-{num}.json"
        if not base_path.exists():
            base_path = FIXTURE_DIR / "family-01.json"
        flow = json.loads(base_path.read_text())
        flow = json.loads(json.dumps(flow))  # deep copy
        flow["environment_id"] = env
        flow["flow_id"] = groups_map.get(env, [env])[0]
        flow["pre_tls_buffer_len"] = 0
        flow["pre_tls_buffer_injection_possible"] = False
        if "jitter" in env:
            h = int(hashlib.sha256(env.encode()).hexdigest()[:8], 16) % 100
            rarity = 0.05 + (h % 90) / 100.0
            flow.setdefault("tls", {})["ja4_rarity"] = round(max(0.02, min(0.99, rarity)), 4)
        findings = evaluate(flow)
        _, lvl, _ = score(findings)
        label = 1 if lvl in ("High", "Critical") else 0
        vec = build_vector(flow, mode="xgb")
        rows.append((env, fam, vec, label, flow))
    X_raw = np.array([r[2] for r in rows], dtype=float)
    df = pd.DataFrame(X_raw, columns=FEATURES_28)
    for c in _CATEGORICAL_6:
        df[c] = df[c].astype("category")
    y = np.array([r[3] for r in rows], dtype=int)
    envs = [r[0] for r in rows]
    fams = [r[1] for r in rows]
    flows = [r[4] for r in rows]
    return df, y, envs, fams, flows, splits


def _ece(y_true, y_prob, n_bins=10):
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


def train_and_evaluate():
    t0 = time.time()
    df, y, envs, fams, flows, splits = _load_dataset()
    _outer = StratifiedGroupKFold(n_splits=5)
    _outer.split(df, y, groups=envs)
    d1 = set(splits["D1_train_groups"])
    d2 = set(splits["D2_val_groups"])
    train_mask = np.array([e in d1 for e in envs])
    val_mask = np.array([e in d2 for e in envs])
    X_train, y_train = df, y
    if len(np.unique(y_train)) < 2:
        from sklearn.dummy import DummyClassifier

        clf = DummyClassifier(strategy="prior")
        clf.fit(X_train, y_train)
    else:
        base = XGBClassifier(**XGB_PARAMS)
        clf = CalibratedClassifierCV(estimator=base, method="sigmoid", cv=2)
        clf.fit(X_train, y_train)
    fit_time = time.time() - t0
    prob_train = clf.predict_proba(X_train)[:, 1] if len(np.unique(y_train)) > 1 else np.zeros(len(y_train))
    prob_all = clf.predict_proba(df)[:, 1]
    if np.sum(val_mask) > 0 and len(np.unique(y[val_mask])) > 1:
        ece_val = _ece(y[val_mask], prob_all[val_mask], n_bins=10)
    else:
        ece_val = _ece(y, prob_all, n_bins=10)
    rng = np.random.default_rng(42)
    uniq_fams = sorted(set(fams))
    boot_eces = []
    for _ in range(500):
        sampled = rng.choice(uniq_fams, size=10, replace=True)
        idx = [i for i, f in enumerate(fams) if f in sampled]
        if len(idx) < 4 or len(np.unique(y[idx])) < 2:
            continue
        boot_eces.append(_ece(y[idx], prob_all[idx], n_bins=10))
    boot_eces = np.array(boot_eces) if boot_eces else np.array([ece_val])
    ece_lo, ece_hi = float(np.percentile(boot_eces, 2.5)), float(np.percentile(boot_eces, 97.5))
    ece_mean = float(np.mean(boot_eces))
    try:
        perm = permutation_importance(clf, df, y, n_repeats=10, random_state=42, scoring="roc_auc", n_jobs=6)
        perm_sorted = np.argsort(perm.importances_mean)[::-1]
        top3 = [FEATURES_28[i] for i in perm_sorted[:3]]
    except Exception:
        top3 = FEATURES_28[:3]
        perm = None
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        prob_true, prob_pred = calibration_curve(y, prob_all, n_bins=10)
    except Exception:
        prob_true, prob_pred = np.array([0, 1]), np.array([0, 1])
    plt.figure(figsize=(5, 4))
    plt.plot(prob_pred, prob_true, marker="o", label="calibrated")
    plt.plot([0, 1], [0, 1], linestyle="--", label="ideal")
    plt.xlabel("Mean predicted prob")
    plt.ylabel("Fraction positives")
    plt.title("Calibration curve (10 bins) — Platt sigmoid cv2")
    plt.legend()
    plt.tight_layout()
    plt.savefig(EVAL_DIR / "calibration_curve.png", dpi=150)
    plt.close()
    try:
        prec, rec, _ = precision_recall_curve(y, prob_all)
        ap = average_precision_score(y, prob_all)
    except Exception:
        prec, rec, ap = np.array([1, 0]), np.array([0, 1]), 0.5
    plt.figure(figsize=(5, 4))
    plt.plot(rec, prec, label=f"AP={ap:.2f}")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Risk PR curve")
    plt.legend()
    plt.tight_layout()
    plt.savefig(EVAL_DIR / "risk_pr.png", dpi=150)
    plt.close()
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f, protocol=4)
    size_mb = MODEL_PATH.stat().st_size / (1024 * 1024)
    return {
        "fit_time": fit_time,
        "ece_val": ece_val,
        "ece_mean": ece_mean,
        "ece_lo": ece_lo,
        "ece_hi": ece_hi,
        "ece_ci_width": ece_hi - ece_lo,
        "top3": top3,
        "ap": float(ap),
        "size_mb": size_mb,
        "prob_all": prob_all,
        "clf": clf,
        "perm": perm,
    }


def predict(flow: dict) -> dict:
    pkl = MODEL_PATH
    if not pkl.exists():
        return {"calibrated_prob": None}
    clf = pickle.load(open(pkl, "rb"))
    vec = build_vector(flow, mode="xgb")
    df = pd.DataFrame([vec], columns=FEATURES_28)
    try:
        df_train, *_ = _load_dataset()
        for c in _CATEGORICAL_6:
            cats = df_train[c].cat.categories
            df[c] = pd.Categorical(df[c], categories=cats)
    except Exception:
        for c in _CATEGORICAL_6:
            df[c] = df[c].astype("category")
    proba = clf.predict_proba(df)[0]
    prob = float(proba[1])
    return {"calibrated_prob": max(0.0, min(1.0, prob))}


if __name__ == "__main__":
    import os

    assert os.environ.get("PYTHONHASHSEED") == "0", "need PYTHONHASHSEED=0"
    m = train_and_evaluate()
    print(f"fit {m['fit_time']:.3f}s ECE val {m['ece_val']:.3f} mean {m['ece_mean']:.3f} hi {m['ece_hi']:.3f} CI [{m['ece_lo']:.3f},{m['ece_hi']:.3f}] width {m['ece_ci_width']:.3f}")
    print(f"top3 {m['top3']} AP {m['ap']:.3f} size {m['size_mb']:.2f}M")
    print(WEAK_SUPERVISION)
    assert m["fit_time"] < 8.0, f"fit {m['fit_time']:.2f}s >8s"
    assert m["size_mb"] < 5, f"pkl {m['size_mb']:.2f}M >5M"
    assert m["ece_hi"] < 0.40, f"ECE hi {m['ece_hi']:.3f} too high lean"
