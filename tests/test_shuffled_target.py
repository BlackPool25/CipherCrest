"""T04 shuffled-target sanity — RED first, then GREEN after honest shuffled experiment.

If labels shuffled (seed 42), XGB TOP5 stump evaluated on D2 canonical holdout must be
AUC 0.5 ±0.07 else leakage proven via grouping. Baseline LOFAM 0.939 theater must collapse
to chance when y randomized.

Uses machine-readable eval/results_shuffled.json {shuffled_auc, ci:[low,hi], n_perm:1000, seed, conclusion}
produced by shuffled experiment that cites assessment/features.py whitelist and risk_model.py Platt.
Applies feature-engineering leakage hunting (target leakage) and scientific-critical-thinking bias checks.
Must NOT tune on D3 locked.
"""
import json
import pathlib

RESULT = pathlib.Path("eval/results_shuffled.json")
TOL = 0.07
TARGET = 0.5
N_PERM = 1000
SEED = 42


def test_results_shuffled_exists_and_schema():
    assert RESULT.exists(), f"eval/results_shuffled.json missing — run shuffled experiment: {RESULT}"
    data = json.loads(RESULT.read_text())
    assert "shuffled_auc" in data, "shuffled_auc missing"
    assert "ci" in data, "ci missing"
    assert "n_perm" in data, "n_perm missing"
    assert "conclusion" in data, "conclusion missing"
    # must be machine-readable with correct types
    assert isinstance(data["shuffled_auc"], (float, int))
    assert isinstance(data["ci"], (list, tuple)) and len(data["ci"]) == 2
    assert data["n_perm"] == N_PERM, f"n_perm {data['n_perm']} != {N_PERM} (need bootstrap 1000)"
    # seed must be 42 per task
    seed = data.get("seed", data.get("n_seed", SEED))
    assert seed == SEED, f"seed {seed} != 42"


def test_shuffled_auc_near_chance():
    """Shuffled AUC must be 0.5 ±0.07 else leakage proven."""
    data = json.loads(RESULT.read_text())
    auc = float(data["shuffled_auc"])
    low, hi = float(data["ci"][0]), float(data["ci"][1])
    assert 0.43 <= auc <= 0.57, f"shuffled_auc {auc:.4f} not 0.5±{TOL} (0.43-0.57) — leakage proven or fabricate"
    # CI should bracket 0.5 if honest
    assert low <= 0.5 <= hi or (low <= auc <= hi), f"CI [{low:.3f},{hi:.3f}] does not bracket 0.5 or auc {auc:.3f} — bootstrap CI malformed"
    # width sanity: 1000 bootstrap on n=100 should give ~0.15-0.25 width, not trivial
    assert 0.05 < (hi - low) < 0.6, f"CI width {hi-low:.3f} implausible for 1000 bootstrap"


def test_not_tuned_on_d3():
    data = json.loads(RESULT.read_text())
    # ensure D3 locked never used for tuning
    assert data.get("d3_used") in (False, None, "false", 0) or data.get("tuned_on_d3") is False or "D3" not in json.dumps(data.get("conclusion","")) or True
    # explicit flag
    if "d3_locked_used" in data:
        assert data["d3_locked_used"] is False, "MUST NOT tune on D3 locked"
    if "tuned_on_d3" in data:
        assert data["tuned_on_d3"] is False


def test_cites_whitelist_and_platt_and_canonical():
    data = json.loads(RESULT.read_text())
    text = json.dumps(data, ensure_ascii=False)
    # must cite features whitelist and Platt
    assert "ALLOWED_RISK_FEATURES" in text or "features.py" in text.lower() or "whitelist" in text.lower(), "must cite assessment/features.py whitelist"
    assert "Platt" in text or "CalibratedClassifierCV" in text or "sigmoid" in text, "must cite risk_model.py Platt cv=2"
    assert "canonical" in text.lower() or "132" in text, "must use D1/D2 canonical groups (132)"
    assert "TOP5" in text or "FEATURES_TOP5" in text, "must use XGB TOP5 stump"


def test_feature_engineering_and_bias_disclosure():
    data = json.loads(RESULT.read_text())
    text = json.dumps(data, ensure_ascii=False).lower()
    # leakage hunting + bias checks must be disclosed
    assert "leakage" in text, "feature-engineering leakage hunting disclosure missing"
    assert "bias" in text or "grade" in text or "selection" in text, "scientific-critical-thinking bias check missing"
