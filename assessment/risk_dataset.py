"""risk_dataset — load 45-env dataset + XGB constants LOFAM stump honest."""

from __future__ import annotations
import hashlib
import json
import pathlib
import numpy as np
import pandas as pd
from assessment.features import FEATURES_8, _TOP8_CATEGORICAL, build_vector
from assessment.rules import evaluate
from assessment.score import score

SPLITS = pathlib.Path("assessment/splits.json")
FIXTURE_DIR = pathlib.Path("shared/fixtures")
MODEL_PATH = pathlib.Path("models/risk_clf.pkl")
EVAL_DIR = pathlib.Path("eval")
WEAK_SUPERVISION = "Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a."

# T4 4-exp harness hist max_depth4 Platt cv2 lean — D1 exactly 4 exps not13 locked; G2 XGB+CatBoost candidates; D5 Platt only + T13 0.333
# Real-use imbalance T13: 435/580=0.75 bad prior vs old 435/500=0.87 → AP inflated, Brier base, Platt a steep, bins sparse; fix via scale_pos_weight 0.333 (145/435=0.333) + max_delta_step 1 (XGBoost param_tuning docs) + threshold moving Youden J + stratified GroupKFold canonical 156.
# Risk dataset stratified sampling: GroupKFold canonical 156 ensures 75% prior not leaking via family_id; oversample minority via SMOTE/undersample only on training folds, eval honest via GroupKFold. Upgrade: if High std >0.15 try FlyingSquid retrain.
XGB_PARAMS = dict(
    tree_method="hist",
    device="cpu",
    enable_categorical=True,
    max_depth=4,
    n_estimators=80,
    learning_rate=0.05,
    reg_alpha=1.0,
    reg_lambda=2.0,
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
    scale_pos_weight=0.333,
    max_delta_step=1,
)
PARAM_GRID = [
    dict(max_depth=4, reg_lambda=2.0, min_child_weight=3),
    dict(max_depth=4, reg_lambda=2.0, min_child_weight=5),
    dict(max_depth=4, reg_lambda=5.0, min_child_weight=3),
    dict(max_depth=4, reg_lambda=5.0, min_child_weight=5),
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
                import re as _re
                cipher_base = _re.sub(r"-G\d{3}$", "", cipher) if isinstance(cipher, str) else cipher
                is_aead = cipher_base in ("TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256","ECDHE-RSA-AES128-GCM-SHA256","ECDHE-RSA-AES256-GCM-SHA384","ECDHE-ECDSA-AES128-GCM-SHA256","ECDHE-ECDSA-AES256-GCM-SHA384","RSA-AES128-GCM-SHA256","RSA-AES256-GCM-SHA384","DHE-RSA-AES128-GCM-SHA256")
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
        assert len(vec) == 8, f"build_vector must be 8 got {len(vec)}"
        rows.append((env, fam, vec, label, flow))
    X_raw = np.array([r[2] for r in rows], dtype=float)
    df = pd.DataFrame(X_raw, columns=FEATURES_8)
    for c in _TOP8_CATEGORICAL:
        if c in df.columns:
            df[c] = df[c].astype("category")
    y = np.array([r[3] for r in rows], dtype=int)
    envs = [r[0] for r in rows]
    fams = [r[1] for r in rows]
    flows = [r[4] for r in rows]
    return df, y, envs, fams, flows, splits


XGB_PARAMS_BALANCED = dict(
    tree_method="hist",
    device="cpu",
    enable_categorical=True,
    max_depth=4,
    n_estimators=80,
    learning_rate=0.05,
    reg_alpha=1.0,
    reg_lambda=2.0,
    max_cat_threshold=8,
    max_cat_to_onehot=1,
    colsample_bylevel=0.7,
    colsample_bytree=0.8,
    subsample=0.8,
    min_child_weight=3,
    gamma=0.1,
    random_state=42,
    verbosity=0,
    n_jobs=1,
    nthread=1,
    scale_pos_weight=1.0,
    max_delta_step=1,
)

def _get_balanced_dataframe(n_per_level: int = 60, seed: int = 42):
    import random as _rnd
    import re as _re2
    splits_local = json.loads(SPLITS.read_text())
    balanced_ids = splits_local.get("balanced_training_ids") or splits_local.get("balanced_training_set", {}).get("n_total")
    if isinstance(balanced_ids, list):
        all_envs_bal = balanced_ids
    else:
        # Fallback stratified sampling from current manifest 680
        manifest_path = pathlib.Path("lab/manifest.json")
        manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
        # Build buckets via manifest synthesis level
        buckets: dict[str, list[str]] = {"Low": [], "Medium": [], "High": [], "Critical": []}
        for _k, _v in manifest.items():
            if "jitter" in _k:
                continue
            env = _v.get("environment_id")
            if not env:
                continue
            # Synthesize level quickly via tls/kex heuristic to avoid heavy evaluate for speed
            tls_version = _v.get("tls", "TLS1.2")
            cipher = _v.get("cipher", "")
            cipher_base = _re2.sub(r"-G\d{3}$", "", cipher) if isinstance(cipher, str) else cipher
            kex = _v.get("kex", "ECDHE")
            cert_type = _v.get("cert", "rsa2048")
            # Use same logic as _load_dataset for level
            is_aead = cipher_base in ("TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256","ECDHE-RSA-AES128-GCM-SHA256","ECDHE-RSA-AES256-GCM-SHA384","ECDHE-ECDSA-AES128-GCM-SHA256","ECDHE-ECDSA-AES256-GCM-SHA384","RSA-AES128-GCM-SHA256","RSA-AES256-GCM-SHA384","DHE-RSA-AES128-GCM-SHA256")
            is_deprecated = tls_version in ("TLS1.0","TLS1.1")
            fs_flag = kex == "ECDHE"
            is_tls13_opaque = tls_version == "TLS1.3" and cert_type == "opaque"
            leaf_present = not is_tls13_opaque and cert_type != "none"
            chain_valid = None if is_tls13_opaque or cert_type in ("none","selfsigned","expired","chain-incomplete") else True
            if cert_type == "selfsigned":
                chain_valid = False
            # Quick heuristic for level: use tls/kex to approximate but fallback to evaluate for correctness on sampled
            # Build flow for accurate evaluate
            h = int(hashlib.sha256(env.encode()).hexdigest()[:8], 16) % 100
            rarity = 0.05 + (h % 90) / 100.0
            flow_tmp = {
                "flow_id": env,
                "environment_id": env,
                "tls": {"version": tls_version, "cipher_suite": cipher, "cipher_strength": "strong" if is_aead else "weak" if is_deprecated else "medium", "kex": kex, "fs_flag": fs_flag, "is_deprecated": is_deprecated, "is_aead": is_aead, "handshake_success": tls_version != "none", "alert_after_starttls": False, "ja4_rarity": round(max(0.02, min(0.99, rarity)), 4), "ja4": f"t13d1516h2_{hashlib.sha256(env.encode()).hexdigest()[:12]}_000000000000"},
                "cert": {"leaf_present": leaf_present, "is_tls13_opaque": is_tls13_opaque, "chain_valid": chain_valid, "san_match": chain_valid, "days_to_expiry": 90 if leaf_present and cert_type not in ("expired",) else (-10 if cert_type=="expired" else None), "chain_length": 2 if leaf_present else None, "pubkey_bits": 2048 if cert_type not in ("rsa1024",) else 1024, "sigalg_weak": cert_type in ("expired",), "is_expired": cert_type == "expired", "is_self_signed": cert_type == "selfsigned", "keysize_weak": cert_type == "rsa1024"},
                "starttls_mode": _v.get("starttls","upgrade"),
                "port": int(_v.get("port",587)),
                "app_protocol": "smtp",
                "pre_tls_buffer_len": 0,
                "pre_tls_buffer_injection_possible": False,
            }
            try:
                _, lvl, _ = score(evaluate(flow_tmp))
            except Exception:
                lvl = "Low"
            if lvl in buckets:
                buckets[lvl].append(env)
        rnd2 = _rnd.Random(seed)
        all_envs_bal = []
        for lvl in ["Low","Medium","High","Critical"]:
            avail = sorted(buckets[lvl])
            if len(avail) < n_per_level:
                raise ValueError(f"not enough {lvl} {len(avail)} <{n_per_level}")
            all_envs_bal.extend(rnd2.sample(avail, n_per_level))
        rnd2.shuffle(all_envs_bal)
    # Now build dataframe for those envs via same synthesis as _load_dataset but filtered
    manifest_path = pathlib.Path("lab/manifest.json")
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    env_to_manifest = {v.get("environment_id"): v for v in manifest.values() if v.get("environment_id")}
    groups_map = json.loads(SPLITS.read_text()).get("groups_by_env", {})
    rows = []
    for env in all_envs_bal:
        fam = env.split("__")[0]
        m_ent = env_to_manifest.get(env)
        if m_ent is not None:
            tls_version = m_ent.get("tls", "TLS1.2")
            cipher = m_ent.get("cipher", "ECDHE-RSA-AES128-GCM-SHA256")
            kex = m_ent.get("kex", "ECDHE")
            cert_type = m_ent.get("cert", "rsa2048")
            starttls = m_ent.get("starttls", "upgrade")
            port = int(m_ent.get("port", 587))
            h = int(hashlib.sha256(env.encode()).hexdigest()[:8], 16) % 100
            rarity = 0.05 + (h % 90) / 100.0
            import re as _re3
            cipher_base = _re3.sub(r"-G\d{3}$", "", cipher) if isinstance(cipher, str) else cipher
            is_aead = cipher_base in ("TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256","ECDHE-RSA-AES128-GCM-SHA256","ECDHE-RSA-AES256-GCM-SHA384","ECDHE-ECDSA-AES128-GCM-SHA256","ECDHE-ECDSA-AES256-GCM-SHA384","RSA-AES128-GCM-SHA256","RSA-AES256-GCM-SHA384","DHE-RSA-AES128-GCM-SHA256")
            is_deprecated = tls_version in ("TLS1.0","TLS1.1")
            fs_flag = kex == "ECDHE"
            is_tls13_opaque = tls_version == "TLS1.3" and cert_type == "opaque"
            leaf_present = not is_tls13_opaque and cert_type != "none"
            chain_valid = None if is_tls13_opaque or cert_type in ("none","selfsigned","expired","chain-incomplete") else True
            if cert_type == "selfsigned":
                chain_valid = False
            flow = {"flow_id": env, "environment_id": env, "tls": {"version": tls_version, "cipher_suite": cipher, "cipher_strength": "strong" if is_aead else "weak" if is_deprecated else "medium", "kex": kex, "fs_flag": fs_flag, "is_deprecated": is_deprecated, "is_aead": is_aead, "handshake_success": tls_version != "none", "alert_after_starttls": False, "ja4_rarity": round(max(0.02, min(0.99, rarity)), 4), "ja4": f"t13d1516h2_{hashlib.sha256(env.encode()).hexdigest()[:12]}_000000000000"}, "cert": {"leaf_present": leaf_present, "is_tls13_opaque": is_tls13_opaque, "chain_valid": chain_valid, "san_match": chain_valid, "days_to_expiry": 90 if leaf_present and cert_type not in ("expired",) else (-10 if cert_type=="expired" else None), "chain_length": 2 if leaf_present else None, "pubkey_bits": 2048 if cert_type not in ("rsa1024",) else 1024, "sigalg_weak": cert_type in ("expired",), "is_expired": cert_type == "expired", "is_self_signed": cert_type == "selfsigned", "keysize_weak": cert_type == "rsa1024"}, "starttls_mode": starttls, "port": port, "app_protocol": "smtp" if port in (25,587) else "imap" if port in (143,993) else "pop3"}
        else:
            flow = json.loads((FIXTURE_DIR / "family-01.json").read_text())
        flow = json.loads(json.dumps(flow))
        flow["environment_id"] = env
        flow["flow_id"] = groups_map.get(env, [env])[0]
        flow["pre_tls_buffer_len"] = 0
        flow["pre_tls_buffer_injection_possible"] = False
        findings = evaluate(flow)
        _, lvl, _ = score(findings)
        label = 1 if lvl in ("High", "Critical") else 0
        vec = build_vector(flow, mode="xgb")
        rows.append((env, fam, vec, label, flow, lvl))
    X_raw = np.array([r[2] for r in rows], dtype=float)
    df = pd.DataFrame(X_raw, columns=FEATURES_8)
    for c in _TOP8_CATEGORICAL:
        if c in df.columns:
            df[c] = df[c].astype("category")
    y = np.array([r[3] for r in rows], dtype=int)
    y_multi = np.array([{"Low":0,"Medium":1,"High":2,"Critical":2}[r[5]] if r[5] in ("High","Critical") else {"Low":0,"Medium":1,"High":2,"Critical":3}[r[5]] for r in rows], dtype=int)
    # Actually 4-class 0 Low 1 Medium 2 High 3 Critical
    y_multi4 = np.array([{"Low":0,"Medium":1,"High":2,"Critical":3}[r[5]] for r in rows], dtype=int)
    envs_bal = [r[0] for r in rows]
    fams_bal = [r[1] for r in rows]
    flows_bal = [r[4] for r in rows]
    return df, y, y_multi4, envs_bal, fams_bal, flows_bal


def _saerens_prior_correction(p, p_train: float = 0.5, p_real: float = 0.75):
    import numpy as _np2
    p = _np2.clip(p, 1e-6, 1-1e-6)
    logit = _np2.log(p/(1-p))
    correction = _np2.log(p_real/(1-p_real)) - _np2.log(p_train/(1-p_train))
    p_corr = 1/(1+_np2.exp(-(logit+correction)))
    return _np2.clip(p_corr, 0.01, 0.99)


def _get_catboost_dataframe(flows: list[dict]) -> pd.DataFrame:
    """String-category DataFrame for CatBoost — preserves _TOP8_CATEGORICAL as strings not numeric codes.

    Fixes Brier 0.179>base collapse: numeric codes 0.0 float invalid for CatBoost cat_features, must be string categories via flows rebuild.
    """
    rows_cb: list[list[object]] = []
    for flow in flows:
        tls = flow.get("tls") or {}
        cert = flow.get("cert") or {}
        rows_cb.append(
            [
                str(tls.get("version") or "unknown"),
                str(tls.get("cipher_strength") or "unknown"),
                str(tls.get("kex") or "unknown"),
                cert.get("chain_valid"),
                cert.get("days_to_expiry"),
                bool(tls.get("fs_flag")),
                str(flow.get("starttls_mode") or "none"),
                1 if cert.get("days_to_expiry") is None else 0,
            ]
        )
    df_cb = pd.DataFrame(rows_cb, columns=list(FEATURES_8))
    for c in _TOP8_CATEGORICAL:
        if c in df_cb.columns:
            df_cb[c] = df_cb[c].astype("category")
    return df_cb
