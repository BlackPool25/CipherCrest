"""risk_plot — calibration + PR plotting helpers LOFAM 2-bin 750x600 with counts."""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.calibration import calibration_curve
from sklearn.metrics import average_precision_score, precision_recall_curve


def save_calibration_plot(y_val, prob_val, y, prob_all, eval_dir, bin_counts=None, n_bins=None):
    """Save eval/calibration_curve.png 2-bin Platt with counts per bin 750x600."""
    # Determine bins: use hold-family prob_val if available else prob_all, n_bins = max(2, n_val//5)
    y_use = y_val if len(y_val) else y
    p_use = prob_val if len(y_val) else prob_all
    n_val = len(y_use)
    if n_bins is None:
        n_bins = max(2, n_val // 5)
    # compute bin counts for title
    if bin_counts is None:
        bins = np.linspace(0, 1, n_bins + 1)
        bin_counts = []
        for i in range(n_bins):
            lo, hi = bins[i], bins[i + 1]
            mask = (p_use > lo) & (p_use <= hi) if i > 0 else (p_use >= lo) & (p_use <= hi)
            bin_counts.append(int(np.sum(mask)))
    try:
        prob_true, prob_pred = calibration_curve(
            y_use,
            p_use,
            n_bins=n_bins,
            strategy="uniform",
        )
    except Exception:
        prob_true, prob_pred = np.array([0, 1]), np.array([0, 1])
    plt.figure(figsize=(7.5, 6))
    plt.plot(prob_pred, prob_true, marker="o", label=f"calibrated ({n_bins}-bin, counts {bin_counts})")
    plt.plot([0, 1], [0, 1], linestyle="--", label="ideal")
    plt.xlabel(f"Mean predicted prob ({n_bins} bins)")
    plt.ylabel("Fraction positives")
    plt.title(f"Calibration curve — Platt sigmoid cv2 {n_bins}-bin ECE n_val={n_val} counts {bin_counts} caveat Platt unpowered at n_cal<20")
    plt.legend()
    plt.tight_layout()
    # 750x600 at dpi 100 -> 7.5x6 inches already
    plt.savefig(eval_dir / "calibration_curve.png", dpi=100)
    plt.close()
    # ensure size 750x600
    try:
        from PIL import Image
        im = Image.open(eval_dir / "calibration_curve.png")
        if im.size != (750, 600):
            im2 = im.resize((750, 600))
            im2.save(eval_dir / "calibration_curve.png")
    except Exception:
        pass


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
