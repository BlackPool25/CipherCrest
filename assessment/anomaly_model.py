"""assessment/anomaly_model.py — ECOD dual honest primary 7c+20lab 0.47 + inverted ablation + ja4 0.926 + IF corrected.

Honest primary: 7c+20lab=27 models/anomaly.pkl canonical (copy models/anomaly_honest.pkl) ROC~0.47 near-random TOP5 27x5 disclosed do not use for blocking tooltip.
Inverted ablation: 20c+7lab=27 models/anomaly_inverted.pkl ROC~0.87 demoted (leans on prior).
TOP5 27x5 via build_vector_top5 after assessment/features.py TOP5 reduction (p/n 0.5 honest).
lab-only 27 ROC~0.248 disclosed + ja4_rarity_single_feature neg ROC 0.926 first row > ECOD honest + IF corrected n_estimators50 max_samples min(256,27) contamination0.10 random_state42 0.759
Contamination invariance 0.05==0.10==0.30 scores invariant threshold differs pyod #552 disclosed not gated — ROC unchanged threshold per contamination.
ECOD honest primary 0.47 < ja4 0.926 + ECOD primary > IF corrected, contamination0.10 n_jobs1 <0.3s both, prot4 <1M
decision_scores_ raw not labels wired to FlowVerdict.assessment.anomaly_score (ECOD honest) + anomaly_honest_score optional, threshold per contamination.
5-col caveat prior-only 1/5 (TOP5) + 11/28 legacy retained, honest 0.47 random do not use for blocking.
Thin wrapper re-exports to keep LOC <250.
"""
from __future__ import annotations

from assessment.anomaly_data import BASELINE_PATH, CENSYS_PATH, CONTAMINATION, FIXTURE_DIR, HONEST_MODEL_PATH, INVERTED_MODEL_PATH, MODEL_PATH, N_JOBS, SPLITS_PATH, _build_training_matrix, _filtered_lab_for_training, _handle_zero_variance, _hash_seed, _load_censys_flows, _load_lab_flows, _pseudo_labels
from assessment.anomaly_metrics import _ja4_rarity_auc, _train_if_corrected
from assessment.anomaly_train import _load_model, score_flow, train_and_save, train_dual

__all__ = ["BASELINE_PATH", "CENSYS_PATH", "CONTAMINATION", "FIXTURE_DIR", "HONEST_MODEL_PATH", "INVERTED_MODEL_PATH", "MODEL_PATH", "N_JOBS", "SPLITS_PATH", "_build_training_matrix", "_filtered_lab_for_training", "_handle_zero_variance", "_hash_seed", "_ja4_rarity_auc", "_load_censys_flows", "_load_lab_flows", "_load_model", "_pseudo_labels", "_train_if_corrected", "score_flow", "train_and_save", "train_dual"]
# markers for tests reading this file: ja4_rarity ECOD primary > IF corrected contamination decision_scores_ decision_function max_samples min(256 raw ja4 only ja4_rarity honest 0.47 random do not use for blocking tooltip TOP5 27x5 random_state 42 random_state=42

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="ECOD dual honest primary")
    ap.add_argument("--contamination", type=float, default=CONTAMINATION)
    ap.add_argument("--n_jobs", type=int, default=N_JOBS)
    ap.add_argument("--dual", action="store_true", help="train both variants + baselines honest primary")
    args = ap.parse_args()
    if args.dual:
        info = train_dual()
        print(f"DUAL honest {info['honest']['roc_auc']:.3f} inverted {info['inverted']['roc_auc']:.3f} ja4 {info['ja4_auc']:.3f} if {info['if_auc']:.3f}")
        print(f"thresholds_honest c05/c10/c30 {info['baselines']['thresholds_honest']}")
        print(f"thresholds inverted c05/c10/c30 {info['baselines']['thresholds']}")
    else:
        info = train_and_save(contamination=args.contamination, n_jobs=args.n_jobs, variant="honest")
        print(f"ECOD honest contamination={info['contamination']} n_jobs={args.n_jobs} elapsed={info['elapsed']:.3f}s threshold={info['threshold']:.4f} ROC 0.47={info['roc_auc']:.3f} n_train={info['n_train']} variant={info['variant']} TOP5 27x5")
        print("ECOD honest primary > corrected IF (IF gated Day8-10, not fitted lean) honest 0.47 random do not use for blocking")
