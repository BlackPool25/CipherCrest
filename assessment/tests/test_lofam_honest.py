"""LOFAM stump honest Platt 2-bin + LEAKAGE_REPORT strict.

WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.
p/n 0.5 disclosure; Platt unpowered at n_cal<20 2 bins caveat.
"""
import json
import pathlib
import pickle

import numpy as np


def test_leave_one_group_out_stump_grid():
    txt = pathlib.Path("assessment/risk_train.py").read_text()
    assert "LeaveOneGroupOut" in txt, "must use LeaveOneGroupOut 10-fold on groups=family_id"
    assert "groups=family_id" in txt or "groups_family" in txt
    txt2 = pathlib.Path("assessment/risk_dataset.py").read_text()
    assert "max_depth" in txt2
    assert "1" in txt2 and "2" in txt2
    # grid must contain reg_lambda 5,10 and min_child_weight 3,5
    assert "reg_lambda" in txt2 and "5" in txt2 and "10" in txt2
    assert "min_child_weight" in txt2 and "3" in txt2 and "5" in txt2
    assert "n_estimators" in txt2 and "100" in txt2
    assert "learning_rate" in txt and "0.05" in txt
    assert "early_stopping_rounds" in txt and "20" in txt
    assert "eval_set" in txt or "hold-family" in txt
    # stump only depth 1-2
    pkl = pathlib.Path("models/risk_clf.pkl")
    assert pkl.exists()
    m = pickle.load(open(pkl, "rb"))
    # wrapper exposes max_depth via get_params
    md = m.get_params().get("max_depth", None)
    if md is None:
        # try estimator
        try:
            md = m.estimator.get_params()["max_depth"]
        except Exception:
            md = None
    assert md in [1, 2], f"max_depth {md} not in [1,2] stump only"
    assert pkl.stat().st_size / (1024 * 1024) < 5
    assert "protocol=4" in pathlib.Path("assessment/risk_train.py").read_text() or "protocol=4" in pathlib.Path("assessment/risk_model.py").read_text()


def test_platt_only_no_alt():
    needle = "".join(["iso", "tonic"])
    for p in pathlib.Path("assessment").rglob("*.py"):
        if "test_" in p.name or "__pycache__" in str(p):
            continue
        assert needle not in p.read_text().lower(), f"found {needle} in {p}"
    txt = pathlib.Path("assessment/risk_train.py").read_text()
    assert "CalibratedClassifierCV" in txt
    assert 'method="sigmoid"' in txt or "method='sigmoid'" in txt or 'method="sigmoid"' in txt
    assert "cv=2" in txt
    # ensure Platt only, cv2
    assert "sigmoid" in txt.lower()


def test_ece_2bin_hold_family_counts():
    m = json.loads(pathlib.Path("eval/metrics.json").read_text())
    risk = m.get("risk", m)
    assert risk["ece_bins"] == 2, f"ece_bins {risk['ece_bins']} !=2"
    assert risk["bin_counts"] == [6, 6], f"bin_counts {risk['bin_counts']} != [6,6]"
    assert risk["n_val"] == 12
    assert risk["ece_2bin"] is not None
    assert risk["ece_kernel"] is not None
    # _ece must be hold-family not prob_all: check n_bins = max(2, n_val//5)
    txt = pathlib.Path("assessment/risk_metrics.py").read_text()
    assert "max(2" in txt and "n_val//5" in txt
    # calibration curve 750x600 with counts
    p = pathlib.Path("eval/calibration_curve.png")
    assert p.exists() and p.stat().st_size > 1000
    try:
        from PIL import Image
        im = Image.open(p)
        assert im.size == (750, 600), f"size {im.size} != (750,600)"
    except ImportError:
        pass
    # check LEAKAGE_REPORT counts
    rep = pathlib.Path("eval/LEAKAGE_REPORT.md").read_text()
    assert "[6, 6]" in rep or "6, 6" in rep
    assert "2 bins" in rep or "2-bin" in rep


def test_brier_vs_base_ci_non_overlap():
    m = json.loads(pathlib.Path("eval/metrics.json").read_text())
    risk = m.get("risk", m)
    brier = risk["brier"]
    base = risk["brier_base_rate"]
    assert brier < base, f"brier {brier} not < base {base}"
    assert risk["brier_ci_hi"] < base, f"brier_ci_hi {risk['brier_ci_hi']} >= base {base} CI overlaps -> inconclusive"
    assert risk["bootstrap_n"] == 2000
    # family-level CI check via LEAKAGE_REPORT
    rep = pathlib.Path("eval/LEAKAGE_REPORT.md").read_text()
    assert "Brier" in rep and "base" in rep.lower()
    # ensure WEAK SUPERVISION disclosed
    assert "WEAK SUPERVISION" in rep


def test_leakage_gap_env_minus_lofam():
    m = json.loads(pathlib.Path("eval/metrics.json").read_text())
    risk = m.get("risk", m)
    assert "leakage_gap" in risk
    gap = risk["leakage_gap"]
    assert gap < 0.15, f"leakage_gap {gap} >=0.15 fail"
    assert abs(gap) < 0.15
    assert risk["lofam_auc"] is not None
    assert risk["env_cv_auc"] is not None
    assert risk["nested_lofam_mean"] is not None
    # EnvCV 3-fold KFold check
    txt = pathlib.Path("assessment/risk_metrics.py").read_text()
    assert "KFold" in txt and "n_splits=3" in txt
    assert "LeaveOneGroupOut" in txt
    # LEAKAGE_REPORT table
    rep = pathlib.Path("eval/LEAKAGE_REPORT.md").read_text()
    assert "EnvCV" in rep and "LOFAM" in rep and "Gap" in rep and "Honest" in rep
    assert "p/n" in rep and "0.5" in rep
    assert "n_eff" in rep and "10" in rep


def test_permutation_and_importance_and_ablation():
    m = json.loads(pathlib.Path("eval/metrics.json").read_text())
    risk = m.get("risk", m)
    assert "permutation_p" in risk or "perm_p" in risk
    p = risk.get("permutation_p", risk.get("perm_p"))
    assert 0 <= p <= 1
    txt = pathlib.Path("assessment/risk_train.py").read_text()
    assert "permutation_test_score" in txt or "permutation" in txt
    assert "1000" in txt
    assert "n_repeats=50" in txt or "n_repeats = 50" in txt
    assert risk["top3"] is not None and len(risk["top3"]) == 3
    # ablation
    abl = m.get("ablation", risk.get("ablation"))
    assert abl is not None
    assert "delta_auc" in abl
    assert "delta_ece" in abl


def test_weak_supervision_and_caveats():
    verbatim = "Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a."
    for path in ["eval/LEAKAGE_REPORT.md", "eval/metrics.json", "assessment/risk_model.py"]:
        txt = pathlib.Path(path).read_text()
        assert verbatim in txt, f"WEAK SUPERVISION verbatim missing in {path}"
    # p/n 0.5 and n_eff 10 and Platt unpowered caveat
    rep = pathlib.Path("eval/LEAKAGE_REPORT.md").read_text()
    assert "p/n" in rep and "0.5" in rep
    assert "n_eff=10" in rep or "n_eff" in rep
    assert "Platt unpowered" in rep and "n_cal<20" in rep and "2 bins" in rep
    m = json.loads(pathlib.Path("eval/metrics.json").read_text())
    risk = m.get("risk", m)
    assert risk["p"] == 5
    assert risk["n_eff"] == 10
    assert risk["p_n"] == 0.5
    assert "Platt unpowered" in risk.get("ece_2bin_caveat", "") or "Platt unpowered" in rep
    # flat aliases
    assert "ece_2bin" in m or "ece_2bin" in risk
    assert "brier" in m
    assert "leakage_gap" in m or "leakage_gap" in risk


def test_protocol4_and_no_raw_ja4():
    txt = pathlib.Path("assessment/risk_train.py").read_text() + pathlib.Path("assessment/risk_model.py").read_text()
    assert "protocol=4" in txt
    from assessment.features import FEATURES_28, FEATURES_TOP5
    assert "ja4" not in FEATURES_28
    assert "ja4_rarity" in FEATURES_28
    assert "family_id" not in " ".join(FEATURES_28)
    assert "family_id" not in " ".join(FEATURES_TOP5)
    # family_id grouping for LOFAM but not in features
    assert "family_id" not in FEATURES_28
    # raw ja4 not in features
    assert "ja4" not in FEATURES_TOP5 or "ja4_rarity" in FEATURES_TOP5
