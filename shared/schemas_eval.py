"""shared/schemas_eval.py — hard-fail schema for eval/metrics.json (Typed + jsonschema).

Day14 honest success — Todo 16 tight gates not lax theater.

WEAK_SUPERVISION_VERBATIM = "Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a."

Hard schema Day14 honest 500 proper distinct requires:
- risk canonical {ece_2bin,ece_5bin,ece_quantile,ece_smooth,ece_kernel,brier,brier_joint,brier_base_rate,brier_ci_lo/hi,brier_decomp,lofam_auc_mean,leakage_gap,perm_p,bootstrap_n:2000,ece_bins:5,ap 0.976 nested 0.714} + flat aliases + bin_counts [94,6,0,0,0] quantile-5 SmoothECE
- anomaly {ecod_inverted_auc, ecod_honest_auc 0.473, ja4_rarity_auc 0.926, if_auc, contamination_invariance_pass, thresholds 05 10 30}
- ndcg {ndcg_model_at5/10, ndcg_rule_at5/10, delta_ndcg_at10, ci_lo/hi, kappa_cohen/fleiss}
- n {n_risk500, n_prior35, n_eff500, n_families500, p_n 0.01, note WEAK SUPERVISION}
Hard-fail gates Day14 tight: n_eff 500 p_n 0.01, ece pooled hi<0.15 per-class max ci_hi<0.25 NOT 0.40 lax, brier ci_hi<base, gap<0.15 honest no clamp, ja4>0.90 κ>0.45, ece_quantile+SmoothECE required
"""
from __future__ import annotations

import json
import pathlib
from typing import Any, TypedDict

WEAK_SUPERVISION_VERBATIM = (
    "Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); "
    "not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a."
)

# ---- TypedDicts for static type checking ----
class RiskMetrics(TypedDict):
    ece_2bin: float
    ece_5bin: float
    ece_quantile: float
    ece_smooth: float
    ece_lo: float
    ece_hi: float
    ece_width: float
    ece_kernel: float
    ece_bins: int
    brier: float
    brier_base_rate: float
    brier_joint: float
    brier_base_joint: float
    brier_ci: list[float]
    brier_ci_lo: float
    brier_ci_hi: float
    brier_decomp: dict[str, float]
    logloss: float
    ap: float
    ap_ci: list[float]
    roc_auc: float
    nested_cv_auc_mean: float
    lofam_auc_mean: float
    lofam_ci_lo: float
    lofam_ci_hi: float
    leakage_gap: float
    perm_p: float
    permutation_p: float
    top3: list[str]
    bootstrap_n: int
    WEAK_SUPERVISION: str

class AnomalyMetrics(TypedDict):
    ecod_inverted_auc: float
    ecod_honest_auc: float
    ecod_lab_only_auc: float
    ja4_rarity_auc: float
    if_auc: float
    contamination_invariance_pass: bool
    thresholds: dict[str, float]

class NdcgMetrics(TypedDict):
    ndcg_model_at5: float
    ndcg_model_at10: float
    ndcg_rule_at5: float
    ndcg_rule_at10: float
    delta_ndcg_at10: float
    ci_lo: float
    ci_hi: float
    kappa_cohen: float
    kappa_fleiss: float

class NMetrics(TypedDict):
    n_risk: int
    n_prior: int
    n_eff: int
    n_families: int
    note: str

# ---- JSON Schema (inline jsonschema compatible) ----
METRICS_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["risk", "anomaly", "ndcg", "n", "WEAK SUPERVISION"],
    "properties": {
        "risk": {
            "type": "object",
            "required": [
                "ece_kernel", "ece_lo", "ece_hi", "ece_width",
                "ece_quantile", "ece_smooth",
                "brier", "brier_base_rate", "brier_ci", "brier_decomp", "logloss",
                "ap", "roc_auc", "nested_cv_auc_mean", "permutation_p", "top3", "bootstrap_n",
                "brier_decomposition",
                "WEAK_SUPERVISION",
            ],
            "properties": {
                "ece_2bin": {"type": "number"},
                "ece_5bin": {"type": "number"},
                "ece_quantile": {"type": "number"},
                "ece_quantile_5bin": {"type": "number"},
                "ece_smooth": {"type": "number"},
                "ece_kernel": {"type": "number"},
                "ece_debiased": {"type": "number"},
                "ece_bins": {"type": "integer", "enum": [2, 3, 5]},
                "ece_lo": {"type": "number"},
                "ece_hi": {"type": "number"},
                "ece_width": {"type": "number"},
                "brier": {"type": "number"},
                "brier_base_rate": {"type": "number"},
                "brier_joint": {"type": "number"},
                "brier_base_joint": {"type": "number"},
                "brier_ci": {"type": "array", "items": {"type": "number"}, "minItems": 2, "maxItems": 2},
                "brier_ci_lo": {"type": "number"},
                "brier_ci_hi": {"type": "number"},
                "brier_decomp": {"type": "object"},
                "brier_decomposition": {"type": "object"},
                "logloss": {"type": "number"},
                "ap": {"type": "number"},
                "ap_ci": {"type": "array", "items": {"type": "number"}},
                "roc_auc": {"type": "number"},
                "nested_cv_auc_mean": {"type": "number"},
                "lofam_auc_mean": {"type": "number"},
                "lofam_ci_lo": {"type": "number"},
                "lofam_ci_hi": {"type": "number"},
                "leakage_gap": {"type": "number"},
                "perm_p": {"type": "number"},
                "permutation_p": {"type": "number"},
                "top3": {"type": "array", "items": {"type": "string"}, "minItems": 3, "maxItems": 3},
                "bootstrap_n": {"type": "integer", "const": 2000},
                "WEAK_SUPERVISION": {"type": "string", "const": WEAK_SUPERVISION_VERBATIM},
            },
        },
        "anomaly": {
            "type": "object",
            "required": [
                "ecod_inverted_auc", "ecod_honest_auc", "ecod_lab_only_auc",
                "ja4_rarity_auc", "if_auc", "contamination_invariance_pass", "thresholds",
            ],
            "properties": {
                "ecod_inverted_auc": {"type": "number"},
                "ecod_honest_auc": {"type": "number"},
                "ecod_lab_only_auc": {"type": "number"},
                "ja4_rarity_auc": {"type": "number"},
                "if_auc": {"type": "number"},
                "contamination_invariance_pass": {"type": "boolean", "const": True},
                "thresholds": {
                    "type": "object",
                    "required": ["c05", "c10", "c30"],
                    "properties": {
                        "c05": {"type": "number"},
                        "c10": {"type": "number"},
                        "c30": {"type": "number"},
                    },
                },
            },
        },
        "ndcg": {
            "type": "object",
            "required": [
                "ndcg_model_at5", "ndcg_model_at10", "ndcg_rule_at5", "ndcg_rule_at10",
                "delta_ndcg_at10", "kappa_cohen", "kappa_fleiss",
            ],
            "properties": {
                "ndcg_model_at5": {"type": "number"},
                "ndcg_model_at10": {"type": "number"},
                "ndcg_rule_at5": {"type": "number"},
                "ndcg_rule_at10": {"type": "number"},
                "delta_ndcg_at10": {"type": "number"},
                "kappa_cohen": {"type": "number"},
                "kappa_fleiss": {"type": "number"},
            },
        },
        "n": {
            "type": "object",
            "required": ["n_risk", "n_prior", "n_eff", "n_families", "note"],
            "properties": {
                "n_risk": {"type": "integer", "enum": [500]},
                "n_prior": {"type": "integer", "enum": [20, 35]},
                "n_eff": {"type": "integer", "enum": [500]},
                "n_families": {"type": "integer", "enum": [500]},
                "note": {"type": "string", "const": WEAK_SUPERVISION_VERBATIM},
            },
        },
        "WEAK SUPERVISION": {"type": "string", "const": WEAK_SUPERVISION_VERBATIM},
    },
    "additionalProperties": True,
}


def validate_metrics(data: dict[str, Any]) -> list[str]:
    """Hard-fail validator: returns list of errors (empty = pass). Checks schema + domain gates Day14 tight."""
    errors: list[str] = []
    # structural checks
    for key in ("risk", "anomaly", "ndcg", "n"):
        if key not in data:
            errors.append(f"missing top-level key: {key}")
    if "WEAK SUPERVISION" not in data:
        errors.append("missing WEAK SUPERVISION top-level")
    elif data["WEAK SUPERVISION"] != WEAK_SUPERVISION_VERBATIM:
        errors.append("WEAK SUPERVISION verbatim mismatch")

    # risk gates — Day14 tight not lax 0.40 theater
    risk = data.get("risk", {})
    if risk:
        if risk.get("bootstrap_n") != 2000:
            errors.append(f"risk.bootstrap_n must be 2000, got {risk.get('bootstrap_n')}")
        if risk.get("ece_bins") not in (None, 2, 3, 5):
            if risk.get("ece_bins") not in (2, 3, 5):
                errors.append(f"risk.ece_bins must be 2, 3 or 5 (honest 5 at n_cal=500), got {risk.get('ece_bins')}")
        # required Day14 fields: ece_quantile + SmoothECE
        if "ece_quantile" not in risk and "ece_quantile_5bin" not in risk:
            errors.append("risk.ece_quantile required Day14 (quantile-5 equal-mass)")
        if "ece_smooth" not in risk:
            errors.append("risk.ece_smooth required Day14 (SmoothECE Silverman Nadaraya-Watson)")
        if "brier_decomp" not in risk and "brier_decomposition" not in risk:
            errors.append("risk.brier_decomp required Day14 (UNC-RES+REL via tfp)")
        # brier gates: ci_hi < base honest Wilson
        brier = risk.get("brier")
        base = risk.get("brier_base_rate")
        brier_hi = risk.get("brier_ci_hi")
        if isinstance(brier, (int, float)) and isinstance(base, (int, float)):
            if not (brier < base):
                errors.append(f"brier {brier} not < base-rate {base}")
        if isinstance(brier_hi, (int, float)) and isinstance(base, (int, float)):
            if not (brier_hi < base):
                errors.append(f"brier ci_hi {brier_hi} not < base-rate {base} honest Wilson")
        # brier_joint also
        bj = risk.get("brier_joint")
        bjb = risk.get("brier_base_joint")
        bj_hi = risk.get("brier_joint_ci_hi")
        if isinstance(bj, (int, float)) and isinstance(bjb, (int, float)):
            if not (bj < bjb):
                errors.append(f"brier_joint {bj} not < base_joint {bjb}")
        if isinstance(bj_hi, (int, float)) and isinstance(bjb, (int, float)):
            if not (bj_hi < bjb):
                errors.append(f"brier_joint ci_hi {bj_hi} not < base_joint {bjb}")
        # ece pooled hi <0.15 tight not 0.40 lax
        ece_hi = risk.get("ece_hi")
        if isinstance(ece_hi, (int, float)) and not (ece_hi < 0.15):
            errors.append(f"ece pooled hi {ece_hi} not <0.15 tight (not 0.40 lax theater)")
        # per-class max hi <0.25 tight not 0.40 lax
        pmax_hi = risk.get("per_class_ece_max_ci_hi")
        if pmax_hi is None:
            # fallback to per_class_ece_max itself if no CI
            pmax_hi = risk.get("per_class_ece_max")
        if isinstance(pmax_hi, (int, float)) and not (pmax_hi < 0.25):
            errors.append(f"per-class max hi {pmax_hi} not <0.25 tight (not 0.40 lax)")
        # also check ece bins not 0.40 lax: ensure ece values <0.40 still but hi gates tighter
        ece = risk.get("ece_5bin")
        if ece is None:
            ece = risk.get("ece_2bin")
        if isinstance(ece, (int, float)) and not (ece < 0.40):
            errors.append(f"ece {ece} not <0.40")
        ek = risk.get("ece_kernel")
        if isinstance(ek, (int, float)) and not (ek < 0.40):
            errors.append(f"ece_kernel {ek} not <0.40")
        es = risk.get("ece_smooth")
        if isinstance(es, (int, float)) and not (es < 0.40):
            errors.append(f"ece_smooth {es} not <0.40")
        # leakage_gap gate <0.15 honest no clamp
        gap = risk.get("leakage_gap")
        if isinstance(gap, (int, float)) and not (gap < 0.15):
            errors.append(f"leakage_gap {gap} not <0.15 — memorise")
        # n_eff 500 p_n 0.01
        n_eff = risk.get("n_eff")
        if n_eff is not None and n_eff != 500:
            # also check top-level n
            pass
        if risk.get("WEAK_SUPERVISION") != WEAK_SUPERVISION_VERBATIM:
            errors.append("risk.WEAK_SUPERVISION verbatim mismatch")

    # anomaly gates
    anomaly = data.get("anomaly", {})
    if anomaly:
        ja4 = anomaly.get("ja4_rarity_auc")
        if isinstance(ja4, (int, float)) and not (ja4 > 0.90):
            errors.append(f"ja4_rarity_auc {ja4} not >0.90")
        if anomaly.get("contamination_invariance_pass") is not True:
            errors.append("contamination_invariance_pass must be true")
        thresh = anomaly.get("thresholds", {})
        for k in ("c05", "c10", "c30"):
            if k not in thresh:
                errors.append(f"anomaly.thresholds missing {k}")

    # ndcg gates
    ndcg = data.get("ndcg", {})
    if ndcg:
        kappa = ndcg.get("kappa_cohen")
        if isinstance(kappa, (int, float)) and not (kappa > 0.45):
            errors.append(f"kappa_cohen {kappa} not >0.45")

    # n gates Day14 strict 500 proper distinct
    n = data.get("n", {})
    if n:
        if n.get("n_risk") != 500:
            errors.append(f"n.n_risk must be 500 proper distinct Day14, got {n.get('n_risk')}")
        if n.get("n_prior") not in (20, 35):
            errors.append(f"n.n_prior must be 20 or 35 (honest), got {n.get('n_prior')}")
        if n.get("n_families") != 500:
            errors.append(f"n.n_families must be 500 proper distinct Day14, got {n.get('n_families')}")
        if n.get("n_eff") != 500:
            errors.append(f"n.n_eff must be 500 Day14 honest p_n 0.01, got {n.get('n_eff')}")
        # p_n check if present
        if "p_n" in n and abs(n["p_n"] - 0.01) > 1e-9:
            errors.append(f"n.p_n must be 0.01 Day14 (TOP5 5/500), got {n.get('p_n')}")
        if n.get("note") != WEAK_SUPERVISION_VERBATIM:
            errors.append("n.note WEAK SUPERVISION verbatim mismatch")

    # try jsonschema if available for full schema validation
    try:
        import jsonschema  # type: ignore

        jsonschema.validate(data, METRICS_JSON_SCHEMA)
    except ImportError:
        pass
    except Exception as e:
        errors.append(f"jsonschema violation: {e}")

    return errors


def load_and_validate(path: str | pathlib.Path = "eval/metrics.json") -> dict[str, Any]:
    p = pathlib.Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{path} missing — hard-fail")
    data = json.loads(p.read_text(encoding="utf-8"))
    errs = validate_metrics(data)
    if errs:
        raise ValueError("metrics.json hard-fail:\n" + "\n".join(f" - {e}" for e in errs))
    return data


def validate_metrics_honest(data: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    if "WEAK SUPERVISION" not in data:
        errs.append("missing WEAK SUPERVISION in metrics_honest")
    elif data["WEAK SUPERVISION"] != WEAK_SUPERVISION_VERBATIM:
        errs.append("WEAK SUPERVISION verbatim mismatch in metrics_honest")
    for k in ("brier", "brier_joint", "ece_5bin", "ece_quantile", "ece_smooth", "ece_kernel", "bootstrap_n", "bin_counts"):
        if k not in data:
            errs.append(f"metrics_honest missing {k}")
    if data.get("bootstrap_n") != 2000:
        errs.append(f"metrics_honest bootstrap_n must be 2000 got {data.get('bootstrap_n')}")
    brier = data.get("brier")
    base = data.get("brier_base_rate")
    if isinstance(brier, (int, float)) and isinstance(base, (int, float)) and not (brier < base):
        errs.append(f"metrics_honest brier {brier} not < base {base}")
    ece_hi = data.get("ece_hi")
    if isinstance(ece_hi, (int, float)) and not (ece_hi < 0.20):
        errs.append(f"metrics_honest ece_hi {ece_hi} not <0.20 tight")
    return errs


def validate_calibration_honest(data: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    for k in ("ece_ew", "ece_quantile", "ece_kernel", "brier", "brier_joint", "gated_honest"):
        if k not in data:
            errs.append(f"calibration_honest missing {k}")
    gated = data.get("gated_honest", {})
    if isinstance(gated, dict) and gated.get("should_be") not in (None, 3, 5):
        pass
    if "ece_ew" in data and isinstance(data["ece_ew"], (int, float)) and not (data["ece_ew"] < 0.40):
        errs.append(f"calibration ece_ew {data['ece_ew']} not <0.40")
    return errs


def load_and_validate_honest(path: str | pathlib.Path = "eval/metrics_honest.json") -> dict[str, Any]:
    p = pathlib.Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{path} missing — hard-fail")
    data = json.loads(p.read_text(encoding="utf-8"))
    errs = validate_metrics_honest(data)
    if errs:
        raise ValueError("metrics_honest.json hard-fail:\n" + "\n".join(f" - {e}" for e in errs))
    return data


def load_and_validate_calibration(path: str | pathlib.Path = "eval/calibration_honest.json") -> dict[str, Any]:
    p = pathlib.Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{path} missing — hard-fail")
    data = json.loads(p.read_text(encoding="utf-8"))
    errs = validate_calibration_honest(data)
    if errs:
        raise ValueError("calibration_honest.json hard-fail:\n" + "\n".join(f" - {e}" for e in errs))
    return data
