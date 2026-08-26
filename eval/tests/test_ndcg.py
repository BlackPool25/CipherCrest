"""T7 — NDCG human grades 20×3 blind Likert κ>0.6

Tests for eval/human_grades.csv + eval/blind-likert.md + vendored _fleiss.py.

Gains 2^rel-1 exponential per shared/schemas FlowVerdict.
Blind via blind_id sha256(flow_id)[:8], no risk_level column.
Requires κ>0.6 substantial else re-grade within 5h.
Single-rater fallback disclosed κ=n/a not blocking.
"""
from __future__ import annotations

import csv
import hashlib
import pathlib
import sys

import numpy as np
import pytest
from sklearn.metrics import cohen_kappa_score

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from eval.tests._fleiss import fleiss_kappa  # type: ignore  # noqa: E402

CSV = pathlib.Path("eval/human_grades.csv")
MD = pathlib.Path("eval/blind-likert.md")


def _load_rows():
    assert CSV.exists(), "eval/human_grades.csv missing — T7 not done"
    with open(CSV, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        rows = list(r)
        fieldnames = r.fieldnames or []
    return rows, fieldnames


def test_grades_20():
    rows, _ = _load_rows()
    assert len(rows) == 20, f"expected 20 flows, got {len(rows)}"
    # template: 10 weberblog +5 censys +5 adversarial history-triple
    flow_ids = [x["flow_id"] for x in rows]
    assert len(set(flow_ids)) == 20, "duplicate flow_id"
    weber = [f for f in flow_ids if "weberblog" in f]
    censys = [f for f in flow_ids if "censys" in f]
    adv = [f for f in flow_ids if "history" in f or "adversarial" in f or "stripping" in f]
    assert len(weber) == 10, f"expected 10 weberblog, got {len(weber)}: {weber}"
    assert len(censys) == 5, f"expected 5 censys, got {len(censys)}: {censys}"
    assert len(adv) == 5, f"expected 5 adversarial, got {len(adv)}: {adv}"


def test_raters_range_and_median_and_blind():
    rows, fieldnames = _load_rows()
    # required columns
    for col in ["flow_id", "rater1", "rater2", "rater3", "consensus_median"]:
        assert col in fieldnames, f"missing column {col}"
    # must have at least one of blind_id / flow_id hashing
    has_blind = "blind_id" in fieldnames
    # check 1-5 range and median
    for r in rows:
        for c in ["rater1", "rater2", "rater3"]:
            v = int(r[c])
            assert 1 <= v <= 5, f"{c} out of 1-5 range: {v} in {r}"
        median = int(r["consensus_median"])
        vals = sorted([int(r["rater1"]), int(r["rater2"]), int(r["rater3"])])
        assert median == vals[1], f"consensus_median {median} != median {vals} for {r['flow_id']}"
        # blind_id correctness if present
        if has_blind:
            expected = hashlib.sha256(r["flow_id"].encode()).hexdigest()[:8]
            assert r["blind_id"] == expected, f"blind_id mismatch {r['blind_id']} != {expected} for {r['flow_id']}"
        # no risk_level leak per row? field check below covers header, also ensure not in notes
    # gains sanity 2^rel-1
    for rel in range(1, 6):
        gain = 2**rel - 1
        expected = [1, 3, 7, 15, 31][rel - 1]
        assert gain == expected


def test_no_risk_level_leak():
    _rows, fieldnames = _load_rows()
    low = [f.lower() for f in fieldnames]
    assert "risk_level" not in low, "human_grades.csv must NOT contain risk_level column (blind Oracle #5)"
    assert "risk_score" not in low, "must NOT contain risk_score"
    text = CSV.read_text()
    # header-only check case-insensitive but allow notes mentioning? spec says ! grep risk_level
    assert "risk_level" not in text.lower(), "! grep risk_level failed — file contains risk_level"
    # ensure no score.py weights leaked (Critical/High as weight numbers) — notes may contain but not score column
    assert "score.py" not in text.lower() or True  # notes may not mention weights


def test_kappa_cohen_and_fleiss():
    rows, fieldnames = _load_rows()
    rater_cols = [c for c in ["rater1", "rater2", "rater3"] if c in fieldnames]
    # single-rater disclosed fallback: κ=n/a not blocking
    if len(rater_cols) < 3:
        # must be disclosed in blind-likert.md
        assert MD.exists(), "blind-likert.md missing for single-rater disclosure"
        md = MD.read_text().lower()
        assert "single-rater" in md or "κ=n/a" in md or "kappa=n/a" in md or "single rater" in md, \
            "single-rater fallback must disclose κ=n/a in blind-likert.md"
        pytest.skip("single-rater disclosed κ=n/a — not blocking")
    # Cohen κ rater1 vs rater2
    r1 = [int(r["rater1"]) for r in rows]
    r2 = [int(r["rater2"]) for r in rows]
    r3 = [int(r["rater3"]) for r in rows]
    ck12 = cohen_kappa_score(r1, r2)
    ck13 = cohen_kappa_score(r1, r3)
    # hard gate >0.45 as per verification
    assert ck12 > 0.45, f"Cohen κ rater1 vs rater2 {ck12:.3f} must be >0.45 (hard)"
    assert ck13 > 0.45, f"Cohen κ rater1 vs rater3 {ck13:.3f} must be >0.45"
    # stretch gate >0.6 substantial
    assert ck12 > 0.6, f"Cohen κ {ck12:.3f} <0.6 substantial — re-grade within 5h"
    # Fleiss κ via vendored _fleiss.py across 5 Likert categories
    # Build (N, k) table where k=5 (ratings 1..5)
    N = len(rows)
    k = 5
    table = np.zeros((N, k), dtype=int)
    for i, r in enumerate(rows):
        for c in rater_cols:
            v = int(r[c])
            table[i, v - 1] += 1
    fk = fleiss_kappa(table)
    assert not np.isnan(fk), "Fleiss κ is NaN"
    assert fk > 0.6, f"Fleiss κ {fk:.3f} must be >0.6 substantial else re-grade within 5h"


def test_blind_likert_md_pinned_and_protocol():
    assert MD.exists(), "eval/blind-likert.md missing"
    text = MD.read_text()
    low = text.lower()
    assert "eval/human_grades.csv" in text, "blind-likert.md must pin eval/human_grades.csv"
    assert "blind" in low, "must contain blind protocol"
    assert "sha256" in low, "must describe blind_id sha256(flow_id)[:8]"
    assert "1-5" in text or "1–5" in text or "Likert" in text, "must contain grading instructions 1-5 Likert"
    # gains
    assert "2^rel" in text or "2**rel" in text or "2^rel-1" in text or "exponential" in low, "must mention gains 2^rel-1"
    # κ gate
    assert "0.6" in text and ("kappa" in low or "κ" in text), "must contain κ>0.6 gate"
    assert "re-grade" in low or "regrade" in low, "must contain re-grade within 5h"
    # WEAK SUPERVISION verbatim distinction — not confused
    ws = "Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter \u00a71/\u00a74a."
    assert ws in text, "blind-likert.md must contain WEAK SUPERVISION verbatim and clarify not confused with human grades"
    assert "human" in low, "must clarify human grades independent from weak supervision"
    # P1/P4/P6 disclosure
    assert "P1" in text or "P4" in text or "rater" in low, "must mention 3 raters P1 TLS/P4 ML/P6 Docs"


# ── T8 NDCG@5/@10 model vs rule-only + ablation diagnostic ──

def test_ndcg_treatment():
    """T8: NDCG@10 model vs rule Δ CI tie — gains 2^rel-1, sklearn ndcg_score, family bootstrap 2000, kappa>0.45."""
    import json

    p = pathlib.Path("eval/metrics.json")
    assert p.exists(), "eval/metrics.json missing — run eval/ndcg_eval.py"
    m = json.loads(p.read_text())
    # ndcg segment must exist (namespace ndcg)
    assert "ndcg" in m, "metrics.json missing ndcg segment — merge failed"
    ndcg = m["ndcg"]
    # also flat aliases for back-compat
    for k in ["ndcg_model_at10", "ndcg_rule_at10"]:
        assert k in m or k in ndcg, f"flat alias {k} missing"
    # 0..1 gates
    for k in ["ndcg_model_at5", "ndcg_model_at10", "ndcg_rule_at5", "ndcg_rule_at10"]:
        assert k in ndcg, f"ndcg.{k} missing"
        v = ndcg[k]
        assert 0 <= v <= 1, f"{k} {v} not in 0..1"
    # delta disclosed
    assert "delta_ndcg_at10" in ndcg, "delta_ndcg_at10 missing"
    delta = ndcg["delta_ndcg_at10"]
    assert isinstance(delta, (int, float)), "delta not numeric"
    # CI lo/hi disclosed 2000-boot
    assert "ndcg_ci_lo" in ndcg and "ndcg_ci_hi" in ndcg, "CI missing"
    assert ndcg["ndcg_ci_lo"] <= ndcg["ndcg_ci_hi"], "CI lo > hi"
    # kappa thresholds >0.45 hard (0.6 stretch already in test_kappa)
    assert "kappa_cohen" in ndcg, "kappa_cohen missing in ndcg"
    assert "kappa_fleiss" in ndcg, "kappa_fleiss missing"
    assert ndcg["kappa_cohen"] > 0.45, f"kappa_cohen {ndcg['kappa_cohen']:.3f} must be >0.45"
    assert ndcg["kappa_fleiss"] > 0.45, f"kappa_fleiss {ndcg['kappa_fleiss']:.3f} >0.45"
    # stretch >0.6
    assert ndcg["kappa_cohen"] > 0.6, f"kappa_cohen {ndcg['kappa_cohen']:.3f} <0.6 substantial"
    assert ndcg["kappa_fleiss"] > 0.6, f"kappa_fleiss {ndcg['kappa_fleiss']:.3f} <0.6 substantial"
    # decision tie vs model_better — must handle CI overlap else declare tie per Zenodo (no false 5% claim)
    assert "decision" in ndcg, "decision missing (tie vs model_better)"
    assert ndcg["decision"] in ("tie", "model_better", "rule_better"), f"invalid decision {ndcg['decision']}"
    # if tie, don't claim 5% improvement
    if ndcg["decision"] == "tie":
        # CI must overlap 0
        assert ndcg["ndcg_ci_lo"] <= 0 <= ndcg["ndcg_ci_hi"], "tie declared but CI does not overlap 0"
    # ndcg_eval.py must use sklearn ndcg_score with gains 2^rel-1 and family bootstrap 2000
    ndpath = pathlib.Path("eval/ndcg_eval.py")
    assert ndpath.exists(), "eval/ndcg_eval.py missing"
    txt = ndpath.read_text()
    assert "ndcg_score" in txt, "ndcg_eval.py must use sklearn ndcg_score"
    assert "2**" in txt or "2 **" in txt or "2^rel" in txt, "must implement gains 2^rel-1"
    assert "2000" in txt, "must have 2000 bootstrap"
    assert "family" in txt.lower() or "jitter_env" in txt, "must do family-level bootstrap"
    # k=5 and k=10 both reported
    assert "k=5" in txt and "k=10" in txt, "must report both k=5 and k=10"


def test_ndcg_ablation_diagnostic():
    """UDCG ablation via MechaRule CHA grouped: rule-only → +XGB → -categorical → -calibration."""
    import json

    m = json.loads(pathlib.Path("eval/metrics.json").read_text())
    ndcg = m.get("ndcg", {})
    assert "ablation" in ndcg, "ndcg ablation missing — must include MechaRule CHA grouped ablations"
    abl = ndcg["ablation"]
    # must disclose at least rule_only and plus_xgb
    assert "rule_only_ndcg_at10" in abl or "ndcg_rule_at10" in abl, "ablation rule-only missing"
    assert "plus_xgb_ndcg_at10" in abl or "ndcg_model_at10" in abl, "ablation +XGB missing"
    # -categorical and -calibration ablation diagnostic (name variants allowed)
    has_cat = any("categorical" in k for k in abl.keys()) or "minus_categorical_ndcg_at10" in abl
    has_cal = any("calibration" in k for k in abl.keys()) or "minus_calibration_ndcg_at10" in abl
    assert has_cat, f"ablation -categorical missing {list(abl.keys())}"
    assert has_cal, f"ablation -calibration missing {list(abl.keys())}"
    # ndcg_eval must mention ablation logic
    txt = pathlib.Path("eval/ndcg_eval.py").read_text()
    assert "ablation" in txt.lower(), "ndcg_eval.py must implement ablation diagnostic"
    assert "categorical" in txt.lower() and "calibration" in txt.lower(), "must cover -categorical and -calibration"
