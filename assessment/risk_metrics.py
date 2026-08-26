"""risk_metrics — ECE 5-bin / kernel, helpers."""
from __future__ import annotations
import numpy as np
from sklearn.calibration import calibration_curve

def _ece(y_true, y_prob, n_bins=5):
    bins = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        lo, hi = bins[i], bins[i + 1]
        mask = (y_prob > lo) & (y_prob <= hi) if i > 0 else (y_prob >= lo) & (y_prob <= hi)
        if np.sum(mask) == 0:
            continue
        acc = np.mean(y_true[mask])
        conf = np.mean(y_prob[mask])
        ece += abs(acc - conf) * np.sum(mask) / len(y_true)
    return float(ece)

def _ece_kernel(y_true, y_prob):
    prob_true, prob_pred = calibration_curve(y_true, y_prob, n_bins=5, strategy="uniform")
    if len(prob_true) == 0:
        return _ece(y_true, y_prob, n_bins=5)
    weights = np.histogram(y_prob, bins=5, range=(0, 1))[0] / len(y_true)
    w = weights[: len(prob_true)]
    if np.sum(w) == 0:
        return _ece(y_true, y_prob, n_bins=5)
    w = w / np.sum(w) if np.sum(w) > 0 else w
    ece_k = float(np.sum(np.abs(prob_true - prob_pred) * w))
    if ece_k == 0:
        return _ece(y_true, y_prob, n_bins=5)
    return ece_k
