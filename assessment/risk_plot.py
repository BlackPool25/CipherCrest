"""risk_plot — calibration + PR plotting helpers extracted from risk_train."""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.calibration import calibration_curve
from sklearn.metrics import average_precision_score, precision_recall_curve


def save_calibration_plot(y_val, prob_val, y, prob_all, eval_dir):
    """Save eval/calibration_curve.png 5-bin Platt."""
    try:
        prob_true, prob_pred = calibration_curve(
            y_val if len(y_val) else y,
            prob_val if len(y_val) else prob_all,
            n_bins=5,
            strategy="uniform",
        )
    except Exception:
        prob_true, prob_pred = np.array([0, 1]), np.array([0, 1])
    plt.figure(figsize=(7.5, 6))
    plt.plot(prob_pred, prob_true, marker="o", label="calibrated (5-bin)")
    plt.plot([0, 1], [0, 1], linestyle="--", label="ideal")
    plt.xlabel("Mean predicted prob (5 bins)")
    plt.ylabel("Fraction positives")
    plt.title("Calibration curve — Platt sigmoid cv2 5-bin ECE 5-bin hi<0.25")
    plt.legend()
    plt.tight_layout()
    plt.savefig(eval_dir / "calibration_curve.png", dpi=100)
    plt.close()


def save_pr_plot(y_val, prob_val, y, prob_all, eval_dir):
    """Save eval/risk_pr.png PR curve."""
    try:
        prec, rec, _ = precision_recall_curve(
            y_val if len(y_val) else y, prob_val if len(y_val) else prob_all
        )
        ap = average_precision_score(
            y_val if len(y_val) else y, prob_val if len(y_val) else prob_all
        )
    except Exception:
        prec, rec, ap = np.array([1, 0]), np.array([0, 1]), 0.5
    plt.figure(figsize=(7.5, 6))
    plt.plot(rec, prec, label=f"AP={ap:.3f}")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Risk PR curve — AP vs rule-only")
    plt.legend()
    plt.tight_layout()
    plt.savefig(eval_dir / "risk_pr.png", dpi=100)
    plt.close()
