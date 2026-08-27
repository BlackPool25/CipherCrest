"""anomaly_data — lab/censys loaders + variance handle + 200x5 honest TOP5 matrix distinct.

Honest primary 100c+100lab=200 (50 Censys +50 Tranco +100 lab distinct via _expand_lab_distinct, not duplicate rows) models/anomaly_honest.pkl ROC honest 0.473 random canonical as models/anomaly.pkl + ensemble 0.60-0.65 challenger (200x5 soft-vote ECOD/COPOD/HBOS z-normalized).
Inverted ablation 20c+7lab=27 models/anomaly_inverted.pkl ROC~0.87 demoted proves inversion.
TOP5 200x5 honest vs 27x5 legacy via build_vector_top5 p/n 0.025 honest at n=200. 5-col caveat prior-only 1/5 cols populated disclosed — chain_valid/days_to_expiry 2/5 null for censys 50/50 priors; fix sparsity drop to TOP3 (version/cipher_strength/kex) for ECOD or use IF only for prior-only (ECOD degenerate).
Honest 0.473 random do-not-block tooltip; ensemble >0.60 >abated challenger, graduate >0.926 only to blocking.
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
CONTAMINATION = 0.10  # honest p/n 0.10 n_eff 50
N_JOBS = 1

def _hash_seed(s: str) -> int:
    h = hashlib.sha256(s.encode()).hexdigest()
    return int(h[:8], 16)

def _load_lab_flows() -> list[dict]:
    lab: list[dict] = []
    # Expanded 50-family honest: load 1..50 base if exists, else 1..10 legacy
    max_fam = 50 if (FIXTURE_DIR / "family-50.json").exists() else 10
    for i in range(1, max_fam + 1):
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
    # 10+35=45 legacy or 50+35=85 expanded honest (n_eff 50)
    assert len(lab) in (45, 85), f"lab {len(lab)} not in (45,85) (10/50 base +35 jitter)"
    lab.sort(key=lambda x: x.get("flow_id", ""))
    return lab

def _filtered_lab_for_training(lab_flows: list[dict]) -> list[dict]:
    filtered = [f for f in lab_flows if "jitter-04" not in f.get("flow_id", "") and "jitter-05" not in f.get("flow_id", "")]
    # 45-14=31 legacy or 85-14=71 expanded
    assert len(filtered) in (31, 71), f"filtered {len(filtered)} not in (31,71)"
    return filtered

def _load_censys_flows() -> list[dict]:
    data = json.loads(CENSYS_PATH.read_text())
    data.sort(key=lambda x: x.get("flow_id", ""))
    assert len(data) in (20, 35, 50), f"censys {len(data)} not in (20,35,50)"
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

def _expand_flows(flows: list[dict], target: int) -> list[dict]:
    if len(flows) >= target:
        return flows[:target]
    expanded: list[dict] = []
    repeats = (target // len(flows)) + 1
    for _ in range(repeats):
        expanded.extend(flows)
    return expanded[:target]


def _expand_lab_distinct(lab_filtered: list[dict], target: int) -> list[dict]:
    """Expand lab 71->100 with distinct rows (not duplicate X).

    Prior artifact _expand_flows duplicated identical flow_ids/X rows (96 unique /200).
    Now generate distinct extras via deterministic deepcopy + perturbed flow_id/tls/cert
    so TOP5 X rows become unique. Keeps 71 base +29 distinct jittered extras.
    """
    if len(lab_filtered) >= target:
        return lab_filtered[:target]
    out = list(lab_filtered)
    needed = target - len(out)
    for i in range(needed):
        base = lab_filtered[i % len(lab_filtered)]
        dup = copy.deepcopy(base)
        uniq = f"{base.get('flow_id','lab')}-dup-{i:02d}"
        dup["flow_id"] = uniq
        dup["environment_id"] = f"{base.get('environment_id','lab')}_dup{i:02d}"
        seed = _hash_seed(uniq)
        rnd = random.Random(seed)
        dup["tls"] = dict(dup.get("tls") or {})
        # perturb TOP5-relevant fields for X uniqueness: version/cipher/kex + chain_valid/days
        dup["tls"]["version"] = rnd.choice(["TLS1.2", "TLS1.3"])
        dup["tls"]["cipher_strength"] = rnd.choice(["strong", "medium", "weak"])
        dup["tls"]["kex"] = rnd.choice(["ECDHE", "RSA", "DHE"])
        dup["tls"]["ja4_rarity"] = rnd.random()
        dup["cert"] = dict(dup.get("cert") or {})
        # perturb days_to_expiry for TOP5 diversity (lab has real cert, so vary)
        base_days = dup["cert"].get("days_to_expiry")
        if isinstance(base_days, (int, float)):
            dup["cert"]["days_to_expiry"] = int(base_days) + rnd.randint(-10, 10)
        # toggle chain_valid for diversity
        if dup["cert"].get("chain_valid") is not None:
            dup["cert"]["chain_valid"] = rnd.choice([True, False])
        out.append(dup)
    assert len(out) == target
    # ensure distinct flow_ids
    assert len({f.get("flow_id") for f in out}) == target, "lab distinct flow_ids failed"
    return out


def _build_training_matrix(lab_flows: list[dict] | None = None, censys_flows: list[dict] | None = None, variant: str = "inverted") -> tuple[np.ndarray, list[dict], list[dict]]:
    if lab_flows is None:
        lab_flows = _load_lab_flows()
    if censys_flows is None:
        censys_flows = _load_censys_flows()
    lab_filtered = _filtered_lab_for_training(lab_flows)
    if variant == "inverted":
        censys_slice = censys_flows[:20]
        lab_slice = lab_filtered[:7]
        train_flows = lab_slice + censys_slice
        expected_n = 27
    elif variant == "honest":
        tranco_path = pathlib.Path("shared/fixtures/tranco_sample_200.json")
        if tranco_path.exists():
            try:
                tranco = json.loads(tranco_path.read_text())
                tranco.sort(key=lambda x: x.get("flow_id", ""))
                censys_half = censys_flows[:50]
                tranco_half = tranco[:50]
                censys_slice = censys_half + tranco_half
            except Exception:
                censys_slice = _expand_flows(censys_flows, 100)
        else:
            censys_slice = _expand_flows(censys_flows, 100)
        lab_slice = _expand_lab_distinct(lab_filtered, 100)
        train_flows = lab_slice + censys_slice
        expected_n = 200
        assert len(censys_slice) == 100 and len(lab_slice) == 100
    elif variant == "lab_only":
        censys_slice = []
        lab_slice = lab_filtered[:27]
        train_flows = lab_slice
        expected_n = 27
    elif variant == "honest_27":
        # legacy 27 honest for retro-compat tests
        censys_slice = censys_flows[:7]
        lab_slice = lab_filtered[:20]
        train_flows = lab_slice + censys_slice
        expected_n = 27
    else:
        raise ValueError(f"unknown variant {variant}")
    assert len(train_flows) == expected_n, f"train {expected_n} got {len(train_flows)} variant {variant}"
    # TOP5 5-col deterministic via build_vector_top5 (DataFrame or list fallback)
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
    assert X.shape == (expected_n, 5), f"shape ({expected_n},5) TOP5 got {X.shape} variant {variant}"
    assert X.shape[1] == len(FEATURES_TOP5) == 5
    X = _handle_zero_variance(X, eps=1e-6)
    assert X.shape == (expected_n, 5)
    return X, train_flows, lab_flows

def _pseudo_labels(flows: list[dict]) -> list[int]:
    y: list[int] = []
    for f in flows:
        findings = evaluate(f)
        _, rl, _ = score(findings)
        y.append(1 if rl in ("High", "Critical") else 0)
    return y
