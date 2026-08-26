"""risk_dataset — load 85-env (50 families n_eff 50) dataset + XGB constants LOFAM stump honest."""

from __future__ import annotations
import hashlib
import json
import pathlib
import numpy as np
import pandas as pd
from assessment.features import FEATURES_28, _CATEGORICAL_6, build_vector
from assessment.rules import evaluate
from assessment.score import score

SPLITS = pathlib.Path("assessment/splits.json")
FIXTURE_DIR = pathlib.Path("shared/fixtures")
MODEL_PATH = pathlib.Path("models/risk_clf.pkl")
EVAL_DIR = pathlib.Path("eval")
WEAK_SUPERVISION = "Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=50 synthetic independent. See Dataset Charter §1/§4a."

# LOFAM stump honest: max_depth 1-2 only, reg_lambda 5-10, min_child_weight 3-5, n_estimators 100, learning_rate 0.05, early_stopping_rounds 20
XGB_PARAMS = dict(
    tree_method="hist",
    device="cpu",
    enable_categorical=True,
    max_depth=1,
    n_estimators=100,
    learning_rate=0.05,
    reg_alpha=1.0,
    reg_lambda=5.0,
    max_cat_threshold=8,
    max_cat_to_onehot=1,
    colsample_bylevel=0.7,
    colsample_bytree=0.8,
    subsample=0.8,
    min_child_weight=3,
    gamma=0.1,
    random_state=42,
    verbosity=0,
    early_stopping_rounds=20,
)
PARAM_GRID = [
    dict(max_depth=1, reg_lambda=5.0, min_child_weight=3),
    dict(max_depth=1, reg_lambda=5.0, min_child_weight=5),
    dict(max_depth=1, reg_lambda=10.0, min_child_weight=3),
    dict(max_depth=1, reg_lambda=10.0, min_child_weight=5),
    dict(max_depth=2, reg_lambda=5.0, min_child_weight=3),
    dict(max_depth=2, reg_lambda=5.0, min_child_weight=5),
    dict(max_depth=2, reg_lambda=10.0, min_child_weight=3),
    dict(max_depth=2, reg_lambda=10.0, min_child_weight=5),
]

from functools import lru_cache as _lru

@_lru(maxsize=1)
def _load_dataset():
    splits = json.loads(SPLITS.read_text())
    all_envs = splits["all_environment_ids"]
    groups_map = splits["groups_by_env"]
    rows = []
    for env in all_envs:
        fam = env.split("__")[0]
        num = fam.split("-")[1]
        base_path = FIXTURE_DIR / f"family-{num}.json"
        if not base_path.exists():
            base_path = FIXTURE_DIR / "family-01.json"
        flow = json.loads(base_path.read_text())
        flow = json.loads(json.dumps(flow))
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
