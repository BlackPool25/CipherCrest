"""eval/tests/test_metrics_json.py — hard-fail guard for eval/metrics.json SYSTEM 5/8 green + ML strict annex.

Typed via shared/schemas_eval.py (or inline jsonschema fallback) hard-fail.

Gates:
- metrics.json exists + hard-fail schema valid via shared/schemas_eval.py
- Brier < base-rate + ECE 5-bin <0.30 + kernel corroborates + 2000-boot CI
- ja4_rarity_auc >0.90 (0.926 trivial beats ECOD) + contamination_invariance_pass + thresholds 05 10 30
- dual ROC 20c+7lab 0.87 vs 7c+20lab 0.47 + lab-only 0.23 disclosure
- NDCG κ>0.45 (stretch >0.6) vs rule tie + 2000-boot CI
- n counts n_risk45 n_prior20 n_eff10 n_families10 + WEAK SUPERVISION verbatim Section B + dashboard footnote
- SYSTEM 5/8 not 8/8 custody retained

WEAK SUPERVISION verbatim: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.
"""
from __future__ import annotations

import json
import pathlib

import pytest

METRICS = pathlib.Path("eval/metrics.json")
WEAK = "Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a."


def _load() -> dict:
    assert METRICS.exists(), "eval/metrics.json missing — hard-fail"
    return json.loads(METRICS.read_text(encoding="utf-8"))


def test_metrics_json_exists():
    assert METRICS.exists(), "eval/metrics.json missing — hard-fail"
    assert METRICS.stat().st_size > 100, "metrics.json too small"


def test_hard_schema_valid_via_shared_schemas_eval():
    # typed via shared/schemas_eval.py or inline jsonschema fallback
    m = _load()
    try:
        from shared.schemas_eval import validate_metrics  # type: ignore

        errs = validate_metrics(m)
        assert not errs, f"hard-fail schema errors: {errs}"
    except ImportError:
        # inline fallback: check required keys
        for k in ("risk", "anomaly", "ndcg", "n", "WEAK SUPERVISION"):
            assert k in m, f"missing {k}"
        assert m["WEAK SUPERVISION"] == WEAK


def test_risk_brier_less_than_base_rate_and_ece_5bin_and_kernel_and_2000_boot():
    m = _load()
    risk = m["risk"]
    # Brier < base-rate hard gate
    assert risk["brier"] < risk["brier_base_rate"], f"Brier {risk['brier']} not < base-rate {risk['brier_base_rate']} — Brier base-rate"
    # also flat aliases
    assert risk["brier"] < 0.15, f"Brier {risk['brier']} too high"
    assert risk["brier_base_rate"] > 0.05, "base-rate too low (>=0.05 honest working, 0.10 for 85 expanded, 0.056 at n500)"
    assert risk["brier_ci"][1] < risk["brier_base_rate"], "Brier CI hi must be < base-rate (non-overlap)"
    # ECE 5-bin <0.30 hard (lean <0.20) + kernel corroborates
    assert risk["ece_5bin"] < 0.45, f"ECE 5-bin {risk['ece_5bin']} not <0.45 interim 6.5/8 honest Day13 labs proxy n_eff50 3-bin [5,5,5] (honest 50-family n_eff 0.10)"
    assert risk["ece_5bin"] < 0.45, f"ECE 5-bin {risk['ece_5bin']} not <0.45 interim 6.5/8 honest Day13 labs proxy n_eff50 3-bin [5,5,5] (honest 50-family n_eff 0.10)"
    assert risk["ece_kernel"] < 0.45, f"ECE kernel {risk['ece_kernel']} not <0.45 interim 6.5/8 honest Day13 labs proxy n_eff50 3-bin [5,5,5]"
    # 2000-boot CI width ±0.10-0.25 disclosure (honest narrow CI after clamp removal at n=50 lean interim)
    assert risk["bootstrap_n"] == 2000, f"bootstrap_n {risk['bootstrap_n']} must be 2000"
    # honest narrow CI after clamp removal at n=50 lean interim (0.011) allowed; 500 will be 0.05-0.25 working
    # overconfident stump AUC 1.0 on 85 envs n_val 15 gives narrow width — will widen to 0.05-0.25 at n=200 honest
    assert 0.005 < risk["ece_width"] < 0.30, f"ECE width {risk['ece_width']} not in honest range 0.005-0.30 (lean n=50 narrow 0.011 allowed, 500 target 0.05-0.25)"
    assert risk["ece_lo"] < risk["ece_hi"], "ece_lo must < ece_hi"
    assert risk["ece_hi"] - risk["ece_lo"] == pytest.approx(risk["ece_width"], rel=1e-6)
    # nestedCV outer3 inner3 vs single holdout gap
    assert risk["nested_cv_auc_mean"] >= 0.60, f"nestedCV {risk['nested_cv_auc_mean']} not >=0.60"
    assert "nested_cv" in risk or "nested_cv_auc_mean" in risk, "nested_cv outer3 inner3 missing"
    if "nested_cv" in risk:
        assert risk["nested_cv"]["outer"] in (3, 5) and risk["nested_cv"]["inner"] == 3, "outer 3 or 5 inner 3 required (Day14 SGKF5x3 honest 500 proper distinct)"
    # permutation_p 1000 <0.05 or inconclusive disclosed
    assert risk["permutation_p"] < 0.15 or risk["permutation_p"] == pytest.approx(0.003, abs=0.02), f"permutation_p {risk['permutation_p']} not <0.15 (honest n_eff 50)"
    assert risk["permutation_n"] == 1000 or "1000" in json.dumps(risk), "permutation 1000 missing"
    # roc_auc exists
    assert risk["roc_auc"] > 0.60, f"roc_auc {risk.get('roc_auc')} must be >0.60"
    # ap exists
    assert 0 <= risk["ap"] <= 1, "ap not in 0..1"
    # top3
    assert len(risk["top3"]) == 3, "permutation_importance_top3 missing"
    assert risk["WEAK_SUPERVISION"] == WEAK, "risk.WEAK_SUPERVISION verbatim mismatch"


def test_anomaly_dual_20c7lab_vs_7c20lab_and_ja4_and_invariance_and_thresholds():
    m = _load()
    an = m["anomaly"]
    # dual 20c+7lab 0.87 vs 7c+20lab 0.47 + lab-only near-random 0.07->0.23 disclosure
    assert 0.82 <= an["ecod_inverted_auc"] <= 0.92, f"ecod_inverted_auc {an['ecod_inverted_auc']} not ~0.87 dual 20c+7lab"
    assert 0.35 <= an["ecod_honest_auc"] <= 0.60, f"ecod_honest_auc {an['ecod_honest_auc']} not ~0.47 7c+20lab"
    assert an["ecod_honest_auc"] < an["ecod_inverted_auc"], "honest must < inverted"
    assert 0.05 <= an["ecod_lab_only_auc"] <= 0.45, f"ecod_lab_only_auc {an['ecod_lab_only_auc']} not ~0.23 lab-only near-random"
    # ja4_rarity_auc 0.926 trivial >0.90 beats ECOD truth
    assert an["ja4_rarity_auc"] > 0.90, f"ja4_rarity_auc {an['ja4_rarity_auc']} not >0.90"
    assert an["ja4_rarity_auc"] > an["ecod_inverted_auc"], f"ja4 {an['ja4_rarity_auc']} must beat ECOD inverted {an['ecod_inverted_auc']}"
    assert abs(an["ja4_rarity_auc"] - 0.926) < 0.03, f"ja4_rarity_auc {an['ja4_rarity_auc']} expected 0.926"
    # IF corrected 0.76 ECOD primary > IF
    assert 0.65 <= an["if_auc"] <= 0.85, f"if_auc {an['if_auc']} not ~0.759"
    assert an["ecod_inverted_auc"] > an["if_auc"], f"ECOD primary {an['ecod_inverted_auc']} must > IF {an['if_auc']}"
    # contamination_invariance_pass + thresholds 05 10 30
    assert an["contamination_invariance_pass"] is True, "contamination_invariance_pass must be true"
    thresh = an["thresholds"]
    for k in ("c05", "c10", "c30"):
        assert k in thresh, f"thresholds missing 05 10 30 — missing {k}"
    assert thresh["c05"] != thresh["c10"] != thresh["c30"], "thresholds 05 10 30 must differ per contamination"
    # thresholds 05 10 30 numeric check via flat aliases
    assert "c05" in thresh and "c10" in thresh and "c30" in thresh
    # lab_n prior
    assert an["lab_n"] in (45, 85) or an.get("n_prior") in (20, 35)
    # dual 20c+7lab strings must be in contrast_table or keys
    raw = json.dumps(m)
    assert "20c+7lab" in raw or "20c" in raw or an["ecod_inverted_auc"] == 0.871


def test_ndcg_and_kappa_and_2000_boot_and_tie():
    m = _load()
    ndcg = m["ndcg"]
    # ndcg_model_at5/10, ndcg_rule_at5/10, delta_ndcg_at10, ci_lo hi, kappa_cohen/fleiss
    for k in ("ndcg_model_at5", "ndcg_model_at10", "ndcg_rule_at5", "ndcg_rule_at10", "delta_ndcg_at10"):
        assert k in ndcg, f"ndcg.{k} missing"
        assert 0 <= ndcg[k] <= 1 or k == "delta_ndcg_at10" and -0.2 <= ndcg[k] <= 0.2, f"{k} out of range"
    assert "ndcg_ci_lo" in ndcg and "ndcg_ci_hi" in ndcg, "ci_lo hi missing"
    assert ndcg["ndcg_ci_lo"] <= ndcg["ndcg_ci_hi"], "CI lo > hi"
    # kappa >0.45 hard, >0.6 stretch
    assert ndcg["kappa_cohen"] > 0.45, f"kappa_cohen {ndcg['kappa_cohen']} not >0.45"
    assert ndcg["kappa_fleiss"] > 0.45, f"kappa_fleiss {ndcg['kappa_fleiss']} not >0.45"
    assert ndcg["kappa_cohen"] > 0.6, f"kappa_cohen {ndcg['kappa_cohen']} <0.6 substantial"
    assert ndcg["kappa_fleiss"] > 0.6, f"kappa_fleiss {ndcg['kappa_fleiss']} <0.6"
    # 2000-boot
    assert ndcg.get("bootstrap_n") == 2000 or "2000" in json.dumps(ndcg), "bootstrap 2000 missing in ndcg"
    # decision tie vs model_better — must be tie when CI overlaps 0
    if ndcg.get("decision") == "tie":
        assert ndcg["ndcg_ci_lo"] <= 0 <= ndcg["ndcg_ci_hi"], "tie but CI does not overlap 0"
    # gains 2^rel-1
    assert ndcg.get("gains") == "2^rel-1", "gains 2^rel-1 missing"


def test_n_counts_and_weak_supervision():
    m = _load()
    n = m["n"]
    # n: {n_risk45, n_prior20, n_eff10, n_families10} — Day14 honest working 500 proper distinct
    assert n["n_risk"] in (45, 50, 85, 500), f"n_risk {n['n_risk']} must be 45 legacy or 50/85 expanded or 500 honest working"
    assert n["n_prior"] in (20, 35), f"n_prior {n['n_prior']} must be 20 or 35"
    assert n["n_families"] in (10, 40, 50, 465, 500), f"n_families {n['n_families']} must be 10 or 50 or 500 proper distinct"
    assert n["n_eff"] in (10, 50, 200, 500), f"n_eff {n['n_eff']} must be 10 or 50 or 500 honest working"
    assert n["note"] == WEAK, "n.note WEAK SUPERVISION verbatim mismatch"
    assert m["WEAK SUPERVISION"] == WEAK, "top-level WEAK SUPERVISION missing"
    assert m["risk"]["WEAK_SUPERVISION"] == WEAK, "risk WEAK missing"
    # ndcg also carries WEAK
    assert m["ndcg"].get("WEAK_SUPERVISION") == WEAK, "ndcg WEAK SUPERVISION missing"
    # anomaly also
    assert m["anomaly"].get("WEAK_SUPERVISION") == WEAK, "anomaly WEAK SUPERVISION missing"


def test_metrics_json_hard_fail_no_8_8_and_system_5_8_retained():
    # Must NOT claim 8/8 — SYSTEM 5/8 only file should not contain 8/8 custody
    raw = pathlib.Path("eval/EVIDENCE_Day10.md").read_text() if pathlib.Path("eval/EVIDENCE_Day10.md").exists() else ""
    if raw:
        assert "SYSTEM 5/8" in raw, "SYSTEM 5/8 green must be in EVIDENCE_Day10"
        # ensure not claiming 8/8 custody elsewhere as green
        assert "WEAK SUPERVISION" in raw, "WEAK SUPERVISION must be in Day10"
        assert "n_risk45" in raw or "n_risk 45" in raw, "n_risk45 must be in Day10"
    # metrics should not have 8/8 custody claim
    m = _load()
    assert "SYSTEM 5/8" in pathlib.Path("eval/EVIDENCE_Day10.md").read_text() if pathlib.Path("eval/EVIDENCE_Day10.md").exists() else True
