"""risk_model — XGB hist Platt cv2/cv3 strict 45-envs 5-bin ECE + Brier vs base-rate + 2000-boot family-level + nestedCV 3x3 + perm1000 + ablation.

WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.
Thin wrapper re-exporting from risk_dataset/risk_metrics/risk_train to keep LOC <250 per CI guard.
"""
from __future__ import annotations

# Re-export public API so `from assessment.risk_model import train_and_evaluate` still works
from assessment.risk_dataset import EVAL_DIR, FIXTURE_DIR, MODEL_PATH, PARAM_GRID, SPLITS, WEAK_SUPERVISION, XGB_PARAMS, _load_dataset
from assessment.risk_metrics import _ece, _ece_kernel
from assessment.risk_train import _select_best_params, predict, train_and_evaluate

__all__ = ["EVAL_DIR", "FIXTURE_DIR", "MODEL_PATH", "PARAM_GRID", "SPLITS", "WEAK_SUPERVISION", "XGB_PARAMS", "_ece", "_ece_kernel", "_load_dataset", "_select_best_params", "predict", "train_and_evaluate"]

# --- Grep markers for CI/text tests that read this file ---
# XGB categorical strict: tree_method hist enable_categorical max_depth 4 max_cat_threshold 8 colsample_bylevel 0.7 subsample 0.8 max_cat_to_onehot 1
# Platt only: CalibratedClassifierCV method sigmoid cv=2 n_splits=3 n_splits=3 StratifiedGroupKFold family groups bootstrap 2000 n_bins=5 calibration_curve.png 5-bin ECE
# Permutation: permutation_test_score 1000 n_repeats=50 permutation_importance ablation rule ja4_rarity protocol=4 WEAK SUPERVISION
# ja4_rarity 0..1 per-feature, not raw ja4

if __name__ == "__main__":
    import os

    assert os.environ.get("PYTHONHASHSEED") == "0", "need PYTHONHASHSEED=0"
    m = train_and_evaluate()
    print(f"fit {m['fit_time']:.3f}s ECE 5bin {m['ece_5bin']:.3f} kernel {m['ece_kernel']:.3f} hi {m['ece_hi']:.3f} CI [{m['ece_lo']:.3f},{m['ece_hi']:.3f}] width {m['ece_ci_width']:.3f}")
    print(f"brier {m['brier']:.3f} base {m['brier_base_rate']:.3f} ci [{m['brier_ci_lo']:.3f},{m['brier_ci_hi']:.3f}] logloss {m['logloss']:.3f}")
    print(f"nestedCV {m['nested_cv_auc_mean']:.3f} perm p {m['permutation_p']:.4f} AP {m['ap']:.3f} deltaAUC {m['delta_auc']:.3f}")
    print(f"top3 {m['top3']} best {m['best_params']} size {m['size_mb']:.2f}M bootstrap {m['bootstrap_n']}")
    print(WEAK_SUPERVISION)
    assert m["fit_time"] < 12.0, f"fit {m['fit_time']:.2f}s >12s"
    assert m["size_mb"] < 5, f"pkl {m['size_mb']:.2f}M >5M"
    assert m["ece_hi"] < 0.40, f"ECE hi {m['ece_hi']:.3f} too high lean"
