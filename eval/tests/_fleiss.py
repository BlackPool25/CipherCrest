"""Vendored pure-numpy Fleiss' kappa — no statsmodels wheel offline.

Implements fleiss_kappa(table) where table is (N subjects, k categories)
counts of raters per category. Pure numpy, <30 LOC.
Reference: Fleiss 1971, Landis & Koch κ>0.6 substantial.
"""
from __future__ import annotations

import numpy as np


def fleiss_kappa(table: np.ndarray) -> float:
    """Compute Fleiss' kappa for N subjects, k categories, n raters.

    Args:
        table: (N, k) int array where table[i,j] = #raters assigning subject i to category j.
               Each row must sum to n (constant raters per subject).

    Returns:
        Fleiss kappa float in (-∞,1]. 1 = perfect agreement, 0 = chance, <0 worse than chance.
        Returns 1.0 if Pe==1 (all same category), NaN if N<2 handled as 0.
    """
    t = np.asarray(table, dtype=float)
    if t.ndim != 2 or t.shape[0] < 2:
        return float("nan")
    n = float(t[0].sum())
    if n <= 1:
        return float("nan")
    N, _k = t.shape
    # proportion of assignments to each category
    p_j = t.sum(axis=0) / (N * n)
    # per-subject agreement
    P_i = (np.sum(t * t, axis=1) - n) / (n * (n - 1))
    P_bar = float(np.mean(P_i))
    P_e = float(np.sum(p_j * p_j))
    if abs(1.0 - P_e) < 1e-12:
        return 1.0 if abs(P_bar - 1.0) < 1e-12 else 0.0
    return float((P_bar - P_e) / (1.0 - P_e))
