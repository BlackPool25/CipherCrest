"""anomaly_data — lab/censys loaders + variance handle + 27x5 TOP5 matrix (honest primary).

Honest primary: 7c+20lab=27 models/anomaly_honest.pkl ROC~0.47 near-random canonical as models/anomaly.pkl.
Inverted ablation: 20c+7lab=27 models/anomaly_inverted.pkl ROC~0.87 (demoted, proves inversion).
TOP5 27x5 via build_vector_top5 after assessment/features.py TOP5 reduction (p/n 0.5 honest).
5-col caveat: prior-only 1/5 cols populated (11/28 legacy) — cert chain_valid/days_to_expiry etc None disclosed.
Honest 0.47 random — do not use for blocking (tooltip).
"""
from __future__ import annotations
import copy
import hashlib
import json
import pathlib
import random
import numpy as np
from assessment.features import FEATURES_TOP5, build_vector, build_vector_top5
from assessment.rules import evaluate
from assessment.score import score

FIXTURE_DIR = pathlib.Path("shared/fixtures")
CENSYS_PATH = FIXTURE_DIR / "censys_sampled_200.json"
MODEL_PATH = pathlib.Path("models/anomaly.pkl")
HONEST_MODEL_PATH = pathlib.Path("models/anomaly_honest.pkl")
INVERTED_MODEL_PATH = pathlib.Path("models/anomaly_inverted.pkl")
BASELINE_PATH = pathlib.Path("eval/anomaly_baselines.json")
SPLITS_PATH = pathlib.Path("assessment/splits.json")
CONTAMINATION = 0.10
N_JOBS = 1

def _hash_seed(s: str) -> int:
    h = hashlib.sha256(s.encode()).hexdigest()
    return int(h[:8], 16)

def _load_lab_flows() -> list[dict]:
    lab: list[dict] = []
    for i in range(1, 11):
        p = FIXTURE_DIR / f"family-{i:02d}.json"
        if p.exists():
            lab.append(json.loads(p.read_text()))
    jitter_fams = ["02", "03", "04", "05", "07", "08", "10"]
    for fam in jitter_fams:
        base_path = FIXTURE_DIR / f"family-{fam}.json"
        if not base_path.exists():
            continue
        base = json.loads(base_path.read_text())
        for idx in (1, 2, 3, 4, 5):
            env_id = f"family-{fam}__jitter{idx}_loss5"
            flow = copy.deepcopy(base)
            flow["flow_id"] = f"family-{fam}-jitter-{idx:02d}"
            flow["environment_id"] = env_id
            flow["capture_epoch"] = "2026-08-27T00:00:00Z"
            seed = _hash_seed(env_id)
            rnd = random.Random(seed)
            flow["tls"] = dict(flow.get("tls") or {})
            flow["tls"]["ja4_rarity"] = rnd.random()
            flow["cert"] = dict(flow.get("cert") or {})
            lab.append(flow)
    assert len(lab) == 45, f"lab 45 got {len(lab)} (10 base +35 jitter)"
    lab.sort(key=lambda x: x.get("flow_id", ""))
    return lab

def _filtered_lab_for_training(lab_flows: list[dict]) -> list[dict]:
    filtered = [f for f in lab_flows if "jitter-04" not in f.get("flow_id", "") and "jitter-05" not in f.get("flow_id", "")]
    assert len(filtered) == 31, f"filtered 31 got {len(filtered)}"
    return filtered

def _load_censys_flows() -> list[dict]:
    data = json.loads(CENSYS_PATH.read_text())
    data.sort(key=lambda x: x.get("flow_id", ""))
    assert len(data) == 20, f"censys 20 got {len(data)}"
    return data

def _handle_zero_variance(X: np.ndarray, eps: float = 1e-6) -> np.ndarray:
    std = X.std(axis=0)
    mask = std < 1e-9
    if np.any(mask):
        rng = np.random.RandomState(0)
        noise = rng.normal(0, eps, size=X.shape)
        X = X.copy()
        X[:, mask] += noise[:, mask]
    return X

def _build_training_matrix(lab_flows: list[dict] | None = None, censys_flows: list[dict] | None = None, variant: str = "inverted") -> tuple[np.ndarray, list[dict], list[dict]]:
    if lab_flows is None:
        lab_flows = _load_lab_flows()
    if censys_flows is None:
        censys_flows = _load_censys_flows()
    lab_filtered = _filtered_lab_for_training(lab_flows)
    if variant == "inverted":
        censys_slice = censys_flows[:20]
        lab_slice = lab_filtered[:7]
    elif variant == "honest":
        censys_slice = censys_flows[:7]
        lab_slice = lab_filtered[:20]
    elif variant == "lab_only":
        censys_slice = []
        lab_slice = lab_filtered[:27]
    else:
        raise ValueError(f"unknown variant {variant}")
    train_flows = lab_slice + censys_slice if variant != "lab_only" else lab_slice
    assert len(train_flows) == 27, f"train 27 got {len(train_flows)} variant {variant}"
    # TOP5 27x5 deterministic via build_vector_top5 (DataFrame or list fallback)
    rows = []
    for f in train_flows:
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
    assert X.shape == (27, 5), f"shape (27,5) TOP5 got {X.shape} variant {variant}"
    assert X.shape[1] == len(FEATURES_TOP5) == 5
    X = _handle_zero_variance(X, eps=1e-6)
    assert X.shape == (27, 5)
    return X, train_flows, lab_flows

def _pseudo_labels(flows: list[dict]) -> list[int]:
    y: list[int] = []
    for f in flows:
        findings = evaluate(f)
        _, rl, _ = score(findings)
        y.append(1 if rl in ("High", "Critical") else 0)
    return y
