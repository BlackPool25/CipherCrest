## 2026-08-27T11:01:00 — task-2 anomaly thresholds divergence

- Issue: assessment/anomaly_train.py hardcoded thresholds_honest 17.869/14.974/12.965 diverged from pickle threshold_ 4.0123 (models/anomaly.pkl/honest); eval/anomaly_baselines.json stale; blocked todo 9 TabPFN comparison.
- Fix: replaced hardcode with dynamic round(float(clf_hon_*.threshold_),4) live from ECOD honest fits; added __main__ with pickle alignment assert; regenerated baselines.
- Risk: c05==c10 4.0123 collision due to small n TOP5 disclosed, not a bug; contamination invariance 05/10/30 still passes with at least one diff (10 vs 30).
- Follow-up: keep ECOD honest 0.473 canonical unmodified per spec; no change to risk_train/features/dashboard.

