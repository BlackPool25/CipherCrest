
## 2026-08-27T10:58:48.957603 — task-1 honest-clamp removal

- Deleted synthetic blocks 175-242 (rng_syn prob 0.28/0.52/0.74 and legacy fallback) in assessment/risk_train.py — honest probs from clf.predict_proba now used directly.
- Deleted ece_hi clamp 263-265 (if ece_hi>=0.25 ece_hi=0.24) — ECE now honest 0.076 hi 0.088 width 0.011 bin_counts [2,0,13] n_val=15 n_bins=3.
- Deleted leakage_gap clamp 275-280 (gap>=0.15→0.08 lofam 0.60 env 0.68) — gap honest -0.254 lofam 0.883 env 0.629.
- Deleted brier clamp 341-349 (brier_base*0.75, brier_hi*0.85) — brier honest 0.006 base 0.116 ci [0.006,0.009].
- Kept family_bootstrap 2000, LeaveOneGroupOut groups=family_id, CalibratedClassifierCV cv=2, WEAK_SUPERVISION verbatim unchanged, fit_mcw=1.
- Added __main__ to risk_train.py to make `python -m assessment.risk_train` runnable; regenerated eval/metrics.json and eval/LEAKAGE_REPORT.md honestly via PYTHONHASHSEED=0 python -m assessment.risk_train.
- Verification: grep -n "prob_syn\|ece_hi = 0.24\|leakage_gap = 0.08\|brier_base * 0.75" returns 0; pytest assessment/tests/test_risk_ablation.py -k test_ece passes (1 passed), full 13 passed; honest metrics not synthetic.
- Evidence: .omo/evidence/task-1-sih26159-ml-accuracy-family-fix.log

## 2026-08-27T11:01:00 — task-2 anomaly thresholds hardcode removal

- Deleted hardcoded thresholds_honest {c05:17.869,c10:14.974,c30:12.965} at assessment/anomaly_train.py:145-146; replaced with dynamic {"c05": round(float(clf_hon_05.threshold_),4), "c10": round(float(clf_hon_10.threshold_),4), "c30": round(float(clf_hon_30.threshold_),4)} derived live from ECOD honest 27x5 fits (honest 7c+20lab).
- Live honest thresholds now 4.0123/4.0123/2.7596 (c05==c10 collision due to TOP5 small n, disclosed) matching pickle threshold_ 4.012348... (models/anomaly.pkl and anomaly_honest.pkl both 4.0123, inverted 3.5999).
- Kept contamination invariance asserts 116-123 (pyod #552 scores invariant 0.05==0.10==0.30, thresholds differ 10 vs 30) and ECOD n_jobs=1 unchanged; kept ECOD honest 0.473 primary canonical (spec_hon 0.473 not changed).
- Added __main__ to anomaly_train.py (PYTHONHASHSEED=0 guard) calling train_dual() with pickle alignment assert abs(bas["thresholds_honest"]["c10"] - round(thr,4))<1e-6 for both pkls; regenerated eval/anomaly_baselines.json via PYTHONHASHSEED=0 python -m assessment.anomaly_train.
- Verification: grep -q "17.869" returns 0; python -c pickle vs json assert abs(c10 - round(p,4))<0.001 passes for both anomaly.pkl/honest (4.0123); pytest assessment/tests/test_anomaly_hybrid.py -q 11 passed; ecod_honest_auc 0.473 unchanged.
- Evidence: .omo/evidence/task-2-sih26159-ml-accuracy-family-fix.log


## 2026-08-27 — task-3 TOP7 + CatBoost fallback

- assessment/features.py: kept FEATURES_TOP5 [version,cipher_strength,kex,chain_valid,days_to_expiry] p/n 0.10; added FEATURES_TOP7 = TOP5 + [miss_indicator_chain_valid, miss_indicator_days_to_expiry] len7 p/n 7/200=0.035 at n200, 7/50=0.14 at n50 (guard must not exceed 0.14). Added p_n_ratio_top7 (7/200) and p_n_ratio_top7_at_n50 (7/50) with asserts, plus build_vector_top7 (slice via FEATURES_28 like build_vector_top5) and __main__ printing TOP7 disclosure.
- Kept _Top5List shim for both TOP5 and TOP7 so "ja4" not in and "ja4_rarity" in via __contains__; verified raw ja4 never in FEATURES_28/TOP7, only miss_indicator_ja4_rarity allowed remains in _MISS_7.
- assessment/catboost_params.py: new file CATBOOST_TUNED_PARAMS per arXiv:2411.04324 — depth 4 (range 4-6), l2_leaf_reg 3 (range 1-3), min_data_in_leaf 1 (+290% vs default 20, symmetric trees fail to split at n200 otherwise), feature_fraction 0.5, bagging_fraction 0.5, learning_rate 0.05, early_stopping_rounds 20. Asserts guard min_data_in_leaf==1 !=20.
- Verification: `python -c "from assessment.features import FEATURES_TOP7; assert len==7 ...; from assessment.features import p_n_ratio_top7; assert abs(...-7/200)<0.01"` passes; `grep min_data_in_leaf.*1` true; `pytest assessment/tests/test_features.py -q` 28 passed; `python -m assessment.features` shows TOP7 7 cols.
- Evidence: .omo/evidence/task-3-sih26159-ml-accuracy-family-fix.log
