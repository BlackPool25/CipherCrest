"""risk_dataset — load 45-env dataset + XGB constants LOFAM stump honest."""

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
WEAK_SUPERVISION = "Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a."

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
    # Load manifest for distinct synthesis when fixture missing (500 distinct guard)
    manifest_path = pathlib.Path("lab/manifest.json")
    manifest = {}
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text())
        except Exception:
            manifest = {}
    # Build env_id -> manifest entry for synthesis
    env_to_manifest = {}
    for _k, _v in manifest.items():
        eid = _v.get("environment_id")
        if eid:
            env_to_manifest[eid] = _v
    rows = []
    for env in all_envs:
        fam = env.split("__")[0]
        num = fam.split("-")[1]
        base_path = FIXTURE_DIR / f"family-{num}.json"
        if base_path.exists():
            flow = json.loads(base_path.read_text())
        else:
            # Synthesize distinct flow from manifest (avoid fallback to family-01.json for 415)
            # Use manifest entry for this env to ensure 500 distinct coherent families
            m_ent = env_to_manifest.get(env)
            if m_ent is not None:
                # Build minimal FlowVerdict dict from manifest coherence
                tls_version = m_ent.get("tls", "TLS1.2")
                cipher = m_ent.get("cipher", "ECDHE-RSA-AES128-GCM-SHA256")
                kex = m_ent.get("kex", "ECDHE")
                cert_type = m_ent.get("cert", "rsa2048")
                starttls = m_ent.get("starttls", "upgrade")
                port = int(m_ent.get("port", 587))
                # Deterministic ja4_rarity from hash
                h = int(hashlib.sha256(env.encode()).hexdigest()[:8], 16) % 100
                rarity = 0.05 + (h % 90) / 100.0
                # Map cipher to strength / kex coherence already
                is_aead = cipher in ("TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256","ECDHE-RSA-AES128-GCM-SHA256","ECDHE-RSA-AES256-GCM-SHA384","ECDHE-ECDSA-AES128-GCM-SHA256","ECDHE-ECDSA-AES256-GCM-SHA384","RSA-AES128-GCM-SHA256","RSA-AES256-GCM-SHA384","DHE-RSA-AES128-GCM-SHA256")
                is_deprecated = tls_version in ("TLS1.0","TLS1.1")
                fs_flag = kex == "ECDHE"
                # Cert fields
                is_tls13_opaque = tls_version == "TLS1.3" and cert_type == "opaque"
                leaf_present = not is_tls13_opaque and cert_type != "none"
                chain_valid = None if is_tls13_opaque or cert_type in ("none","selfsigned","expired","chain-incomplete") else True
                if cert_type == "selfsigned":
                    chain_valid = False
                # Build flow
                flow = {
                    "flow_id": env,
                    "environment_id": env,
                    "tls": {
                        "version": tls_version,
                        "cipher_suite": cipher,
                        "cipher_strength": "strong" if is_aead else "weak" if is_deprecated else "medium",
                        "kex": kex,
                        "fs_flag": fs_flag,
                        "is_deprecated": is_deprecated,
                        "is_aead": is_aead,
                        "handshake_success": tls_version != "none",
                        "alert_after_starttls": False,
                        "ja4_rarity": round(max(0.02, min(0.99, rarity)), 4),
                        "ja4": f"t13d1516h2_{hashlib.sha256(env.encode()).hexdigest()[:12]}_000000000000",
                    },
                    "cert": {
                        "leaf_present": leaf_present,
                        "is_tls13_opaque": is_tls13_opaque,
                        "chain_valid": chain_valid,
                        "san_match": chain_valid,
                        "days_to_expiry": 90 if leaf_present and cert_type not in ("expired",) else (-10 if cert_type=="expired" else None),
                        "chain_length": 2 if leaf_present else None,
                        "pubkey_bits": 2048 if cert_type not in ("rsa1024",) else 1024,
                        "sigalg_weak": cert_type in ("expired",),
                        "is_expired": cert_type == "expired",
                        "is_self_signed": cert_type == "selfsigned",
                        "keysize_weak": cert_type == "rsa1024",
                    },
                    "starttls_mode": starttls,
                    "port": port,
                    "app_protocol": "smtp" if port in (25,587) else "imap" if port in (143,993) else "pop3",
                }
            else:
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
