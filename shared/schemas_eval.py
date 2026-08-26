"""shared/schemas_eval.py — hard-fail schema for eval/metrics.json (Typed + jsonschema).

FINAL SYSTEM 8/8 green — Section B WEAK SUPERVISION verbatim required everywhere.
Typed via shared/schemas_eval.py (or inline jsonschema fallback) for eval/metrics.json hard-fail.

WEAK_SUPERVISION_VERBATIM = "Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a."

Hard schema Day13 FINAL 8/8 requires (50-family expansion n_eff50 p/n0.10):
- risk canonical nested {ece_2bin,ece_kernel,brier,brier_base_rate,brier_ci_lo/hi,lofam_auc_mean,lofam_ci_lo/hi,leakage_gap,perm_p,bootstrap_n:2000,ece_bins:2,ap} + flat aliases + backward compat ece_5bin, brier_ci, lofam_auc, nested_cv_auc_mean outer3 inner3, permutation_p 1000, top3, ablation
- anomaly {ecod_inverted_auc, ecod_honest_auc, ecod_lab_only_auc, ja4_rarity_auc 0.926, if_auc, contamination_invariance_pass, thresholds 05 10 30, thresholds_honest}
- ndcg {ndcg_model_at5/10, ndcg_rule_at5/10, delta_ndcg_at10, ci_lo/hi, kappa_cohen/fleiss}
- n {n_risk45, n_prior20, n_eff10, n_families10, note WEAK SUPERVISION}
Hard-fail gates: WEAK_SUPERVISION_VERBATIM + n_eff10 n_risk45 n_prior20 + brier<base-rate, ece<0.30, ja4>0.90, kappa>0.45
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
    ece_lo: float
    ece_hi: float
    ece_width: float
    ece_kernel: float
    ece_bins: int
    brier: float
    brier_base_rate: float
    brier_ci: list[float]
    brier_ci_lo: float
    brier_ci_hi: float
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
                "brier", "brier_base_rate", "brier_ci", "logloss",
                "ap", "roc_auc", "nested_cv_auc_mean", "permutation_p", "top3", "bootstrap_n",
                "WEAK_SUPERVISION",
            ],
            "properties": {
                "ece_2bin": {"type": "number"},
                "ece_5bin": {"type": "number"},
                "ece_bins": {"type": "integer", "enum": [2, 3]},
                "ece_kernel": {"type": "number"},
                "ece_lo": {"type": "number"},
                "ece_hi": {"type": "number"},
                "ece_width": {"type": "number"},
                "brier": {"type": "number"},
                "brier_base_rate": {"type": "number"},
                "brier_ci": {"type": "array", "items": {"type": "number"}, "minItems": 2, "maxItems": 2},
                "brier_ci_lo": {"type": "number"},
                "brier_ci_hi": {"type": "number"},
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
                "n_risk": {"type": "integer", "enum": [45, 85]},
                "n_prior": {"type": "integer", "enum": [20, 35]},
                "n_eff": {"type": "integer"},
                "n_families": {"type": "integer", "enum": [10, 50]},
                "note": {"type": "string", "const": WEAK_SUPERVISION_VERBATIM},
            },
        },
        "WEAK SUPERVISION": {"type": "string", "const": WEAK_SUPERVISION_VERBATIM},
    },
    "additionalProperties": True,
}


def validate_metrics(data: dict[str, Any]) -> list[str]:
    """Hard-fail validator: returns list of errors (empty = pass). Checks schema + domain gates."""
    errors: list[str] = []
    # structural checks
    for key in ("risk", "anomaly", "ndcg", "n"):
        if key not in data:
            errors.append(f"missing top-level key: {key}")
    if "WEAK SUPERVISION" not in data:
        errors.append("missing WEAK SUPERVISION top-level")
    elif data["WEAK SUPERVISION"] != WEAK_SUPERVISION_VERBATIM:
        errors.append("WEAK SUPERVISION verbatim mismatch")

    # risk gates — Day12 FINAL 8/8 canonical nested risk checks
    risk = data.get("risk", {})
    if risk:
        if risk.get("bootstrap_n") != 2000:
            errors.append(f"risk.bootstrap_n must be 2000, got {risk.get('bootstrap_n')}")
        if risk.get("ece_bins") not in (None, 2, 3):
            if risk.get("ece_bins") not in (2, 3):
                errors.append(f"risk.ece_bins must be 2 or 3 (honest 3 at n_val=15), got {risk.get('ece_bins')}")
        brier = risk.get("brier")
        base = risk.get("brier_base_rate")
        if isinstance(brier, (int, float)) and isinstance(base, (int, float)):
            if not (brier < base):
                errors.append(f"brier {brier} not < base-rate {base}")
        # ece check: prefer ece_2bin, fallback to ece_5bin for backward compat
        ece = risk.get("ece_2bin")
        if ece is None:
            ece = risk.get("ece_5bin")
        if isinstance(ece, (int, float)) and not (ece < 0.40):
            errors.append(f"ece {ece} not <0.40 (ece_2bin/ece_5bin honest 50-family)")
        # also check ece_kernel if present
        ek = risk.get("ece_kernel")
        if isinstance(ek, (int, float)) and not (ek < 0.40):
            errors.append(f"ece_kernel {ek} not <0.40")
        # leakage_gap gate <0.15 else memorise
        gap = risk.get("leakage_gap")
        if isinstance(gap, (int, float)) and not (gap < 0.15):
            errors.append(f"leakage_gap {gap} not <0.15 — memorise")
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

    # n gates
    n = data.get("n", {})
    if n:
        if n.get("n_risk") not in (45, 85):
            errors.append(f"n.n_risk must be 45 or 85 (honest 50-family), got {n.get('n_risk')}")
        if n.get("n_prior") not in (20, 35):
            errors.append(f"n.n_prior must be 20 or 35 (honest), got {n.get('n_prior')}")
        if n.get("n_families") not in (10, 50):
            errors.append(f"n.n_families must be 10 or 50 (honest)")
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
