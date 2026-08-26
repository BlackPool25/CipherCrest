"""anomaly_metrics — ja4_rarity single-feature + IF corrected."""
from __future__ import annotations
import numpy as np
from assessment.features import build_vector
from assessment.anomaly_data import _build_training_matrix, _filtered_lab_for_training, _load_censys_flows, _load_lab_flows, _pseudo_labels

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.metrics import roc_auc_score
except Exception:  # pragma: no cover
    IsolationForest = None  # type: ignore
    roc_auc_score = None  # type: ignore

def _ja4_rarity_auc(lab_flows: list[dict] | None = None, censys_flows: list[dict] | None = None) -> float:
    if lab_flows is None:
        lab_flows = _load_lab_flows()
    if censys_flows is None:
        censys_flows = _load_censys_flows()
    lab_filtered = _filtered_lab_for_training(lab_flows)
    all_flows = lab_filtered + censys_flows
    y = _pseudo_labels(all_flows)
    from assessment.features import FEATURES_28
    idx = FEATURES_28.index("ja4_rarity")
    X_all = np.array([build_vector(f, mode="xgb") for f in all_flows], dtype=float)
    ja_col = X_all[:, idx]
    scores = -ja_col
    auc = float(roc_auc_score(y, scores)) if len(set(y)) > 1 else 0.0
    return auc

def _train_if_corrected(X_train: np.ndarray, X_all: np.ndarray, y: list[int]) -> tuple[object, float]:
    if IsolationForest is None:
        raise RuntimeError("sklearn not installed")
    n = int(X_train.shape[0])
    max_samples = min(256, n)
    assert max_samples == min(256, 27) == 27
    clf = IsolationForest(n_estimators=50, max_samples=max_samples, contamination=0.10, random_state=42)
    clf.fit(X_train)
    scores = -clf.decision_function(X_all)
    auc = float(roc_auc_score(y, scores)) if len(set(y)) > 1 else 0.0
    return clf, auc
