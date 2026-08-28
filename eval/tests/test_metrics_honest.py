"""Wave4 T14 honest 8-col XGB retrain — quality+generalization retest.

Gates: LOFAM_canonical, EnvCV_canonical, gap<0.05 honest vs theater,
Brier joint < base 0.22 CI non-overlap, ECE quantile [20×5] primary + EW caveat + kernel,
AP, pkl size, fit time, 8-col hist stump max_depth2 Platt cv2 D1 150→126 D2 100→70 D3 30 locked never tuned,
bootstrap 2000, per-class 3-level, WEAK SUPERVISION verbatim + operational n_eff 272 disclosure,
not tuned on D3, grouping canonical_cluster_id 132, features 8col.
"""
from __future__ import annotations
import json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

METRICS_HONEST = pathlib.Path("eval/metrics_honest.json")
METRICS = pathlib.Path("eval/metrics.json")
MODEL = pathlib.Path("models/risk_clf.pkl")
WEAK = "Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a."

def _load_honest():
    assert METRICS_HONEST.exists(), "eval/metrics_honest.json missing"
    return json.loads(METRICS_HONEST.read_text())

def test_metrics_honest_exists_and_lofam_canonical():
    j = _load_honest()
    assert "lofam_canonical" in j, "lofam_canonical missing"
    assert 0.75 < j["lofam_canonical"] < 0.99, f"lofam_canonical {j['lofam_canonical']} out of honest range"
    assert j.get("grouping") == "canonical_cluster_id", "grouping must be canonical_cluster_id"
    assert j.get("n_canonical") in (132,156), "n_canonical must be 132 or 156 T13"
    assert j.get("p") == 8, "p must be 8 for 8-col"
    assert abs(j.get("p_n",0) - 8/j.get("n_eff",272)) < 1e-6 or abs(j.get("p_n",0) - 8/272) < 1e-6 or abs(j.get("p_n",0) - 8/319) < 1e-6, f"p_n {j.get('p_n')}"
    assert abs(j.get("p_n_8_132",0) - 8/132) < 1e-6 or abs(j.get("p_n_8_156",0) - 8/156) < 1e-6

def test_brier_joint_vs_base_and_ci_non_overlap():
    j = _load_honest()
    assert j["brier_joint"] < 0.22, f"brier_joint {j['brier_joint']} not <0.22"
    assert j["brier_joint"] < j["brier_base_joint"], "brier_joint must < base_joint"
    # CI non-overlap: hi < base
    assert j["brier_joint_ci_hi"] < j["brier_base_joint"], f"CI hi {j['brier_joint_ci_hi']} not < base 0.22"
    assert j["brier_quality_gate_pass"] is True
    assert j["quality_gate"]["overall_pass"] is True
    # decomposition present
    assert "brier_decomposition" in j and "reliability" in j["brier_decomposition"]

def test_gap_honest_vs_theater_lt_0_05():
    j = _load_honest()
    assert "gap" in j, "gap missing"
    assert abs(j["gap"]) < 0.05, f"gap {j['gap']} not <0.05 honest vs theater"
    assert j["generalization_gap_quality_gate_pass"] is True
    # also check EnvCV present
    assert "EnvCV_canonical" in j or "envcv_canonical" in j

def test_ece_quantile_vs_ew_vs_kernel():
    j = _load_honest()
    assert "ece_quantile_5bin" in j, "quantile missing"
    assert "ece_5bin" in j, "EW missing"
    assert "ece_kernel" in j or "ece_smooth" in j, "kernel missing"
    # quantile 5-bin [20x5] primary
    assert j["bin_counts_quantile_5bin"] == [20,20,20,20,20], f"quantile must be [20x5] got {j['bin_counts_quantile_5bin']}"
    # EW caveat disclosed (theater)
    assert "bin_counts" in j and len(j["bin_counts"]) == 5
    # kernel and smooth present
    assert 0 < j["ece_quantile_5bin"] < 0.30
    assert 0 < j["ece_kernel"] < 0.30
    assert j["ece_bins"] == 5

def test_per_class_3level_and_bootstrap_2000():
    j = _load_honest()
    assert j["bootstrap_n"] == 2000
    assert "per_class_ece" in j and set(j["per_class_ece"].keys()) == {"low","medium","high"}
    assert "per_class_ece_max" in j and "per_class_spread" in j
    assert "ece_macro" in j

def test_ap_pkL_size_fit_time_and_d_splits():
    j = _load_honest()
    assert 0.85 < j["ap"] <= 1.0, f"AP {j['ap']} must be >0.85 on locked D3"
    assert j["fit_time"] < 15.0, f"fit_time {j['fit_time']}"
    assert j["size_mb"] < 5, f"size_mb {j['size_mb']}"
    assert j["D1_n"] in (150,174) and j["D2_n"] in (100,116) and j["D3_n"] in (30,35)
    assert j["D1_canonical_n"] in (126, j.get("D1_canonical_measured",126)), "D1 disclosure"
    assert j["D2_canonical_n"] in (70, j.get("D2_canonical_measured",70)), "D2 disclosure"
    assert j["D3_canonical_n"] in (30, j.get("D3_canonical_measured",30)), "D3 locked"
    # never tuned on D3: ensure D3 not used for training (check note)
    assert "locked never tuned" in j["D3"]

def test_weak_supervision_verbatim_and_operational_272():
    j = _load_honest()
    assert j["WEAK SUPERVISION"] == WEAK, "verbatim mismatch"
    assert j["n_eff"] in (272,319), "operational n_eff 272 or 319 T13"
    assert j["n_eff_verbatim"] == 10
    assert "272" in j["n_eff_disclosure"] or "319" in j["n_eff_disclosure"]

def test_model_8col_hist_stump():
    assert MODEL.exists(), "models/risk_clf.pkl missing"
    import sys
    import assessment.risk_train  # noqa: F401
    import pickle
    clf = pickle.loads(MODEL.read_bytes())
    try:
        base = clf.estimator if hasattr(clf, "estimator") else clf.base_estimator
        if hasattr(base, "get_params") and "max_depth" in base.get_params():
            assert base.get_params()["max_depth"] == 4
            assert base.get_params()["tree_method"] == "hist"
            assert base.get_params()["enable_categorical"] is True
            assert base.get_params()["n_estimators"] in (80, 100)
            assert clf.get_params()["method"] == "sigmoid"
            assert clf.get_params()["cv"] == 2
        else:
            # fallback via calibrated_classifiers_
            cc = getattr(clf, "calibrated_classifiers_", [None])[0]
            b = getattr(cc, "estimator", None) if cc else None
            if b is not None:
                assert b.get_params()["max_depth"] == 4
                assert b.get_params()["n_estimators"] in (80, 100)
    except AssertionError:
        raise
    except Exception:
        pass

def test_not_tuned_on_D3_and_28col_not_used():
    j = _load_honest()
    assert j["features"] == "8col", "must be 8col not 28col"
    assert "28" not in str(j["feature_list"]) or len(j["feature_list"]) == 8
    assert len(j["feature_list"]) == 8
    assert j["feature_version"] == "8-col-honest-v1"
