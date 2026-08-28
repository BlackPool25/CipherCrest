"""T4 baseline characterization — captures pre-fix state vs 4-exp harness expectation (TDD).

Before fix: risk_model.py was lean wrapper with no FOUR_EXPS, no n_exps in metrics_honest.json,
splits.json groups_by_env used family string, eval/run_ablation had 6 configs (not 4).
We characterize baseline so failing-first proof asserting n_exps==4 fails before fix.
"""
import json
import pathlib


def test_baseline_characterization_before_fix():
    """Pass on old code — captures previous theater/lean mismatch before T4."""
    # risk_model exists but no FOUR_EXPS yet, no canonical grouping enforcement
    rm_txt = pathlib.Path("assessment/risk_model.py").read_text()
    # Before T4, file contained family_id marker (should be removed after)
    # Characterize: it was a thin re-export, not 4-exp harness
    assert "train_and_evaluate" in rm_txt
    # metrics_honest had no n_exps key
    mh = json.loads(pathlib.Path("eval/metrics_honest.json").read_text())
    assert "gap" in mh  # gap exists but n_exps missing before T4
    # splits had canonical metadata but groups_by_env still present
    splits = json.loads(pathlib.Path("assessment/splits.json").read_text())
    assert len(splits["all_environment_ids"]) == 500
    assert splits.get("canonical_n_groups") == 132
    abl_txt = pathlib.Path("eval/run_ablation.py").read_text()
    assert "FOUR_EXPS" in abl_txt or "full_28" in abl_txt or "FEATURES_28" in abl_txt


def test_failing_first_proof_n_exps_4_must_fail_before_fix():
    """Failing-first proof: expects exactly 4 exps. Before fix this FAILS (gap exposed)."""
    # After T4, metrics_honest must have n_exps==4
    mh = json.loads(pathlib.Path("eval/metrics_honest.json").read_text())
    # This assertion SHOULD FAIL before fix (since n_exps absent), PASS after fix
    assert mh.get("n_exps") == 4, f"n_exps {mh.get('n_exps')} !=4 — T4 not yet applied"
    # Also FOUR_EXPS in risk_model must be exactly 4
    rm_txt = pathlib.Path("assessment/risk_model.py").read_text()
    assert "FOUR_EXPS" in rm_txt, "FOUR_EXPS missing"
    assert rm_txt.count("family_id") == 0, "family_id forbidden"
    assert "canonical_cluster_id" in rm_txt, "must use canonical_cluster_id"
    assert "GroupKFold" in rm_txt, "must use GroupKFold"
    # Platt only
    assert "sigmoid" in rm_txt.lower() or "Platt" in rm_txt
    assert "isotonic" not in rm_txt.lower()
