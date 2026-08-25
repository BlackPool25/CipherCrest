# EVIDENCE Day7 — SecureMailScope (2026-08-25) — SYSTEM 5/8 + ML LEARN shell

> SYSTEM 5/8 🟢 — Section A SYSTEM CORRECTNESS ONLY: STARTTLS F1>95% lossy/weberblog, cipher 100% >98%, cert prec1.000 >90% stratified CABF/private, weak 100% 23-check, JSON 20/20, POST /analyze zip10→200 + posture + policy_dist, GET /flows <50ms, dashboard honesty 14/20 REAL + 23×3 ThreatMatrix 20 scored +3 info-greyed 15b/16b/16c, Vite <3670016, cold-start <3s, wheelhouse 345M <350, splits 31 groups. ML Section B 🟡 Day8-10 lean: XGB Platt cv=2 ECE 500-boot hi<0.20 (CI width ±0.10 disclosed), ECOD ROC point>0.60, NDCG@10 human-graded deferred (κ>0.6), calibrated_prob 0..1, anomaly_score ECOD with eval/calibration_curve.png + risk_pr.png + models/*.pkl trio lineage manifest→pcap→reassembled→features vs tshark

**WEAK SUPERVISION disclosure (required verbatim in Section B header + dashboard AI tab + LEDGER):** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

---

## 0. Gate summary — SYSTEM 5/8 (Day7)

| Gate # | Lean gate | Threshold | Result | Corpus | Evidence |
|--------|-----------|-----------|--------|--------|----------|
| 1 | STARTTLS F1>95% | >95% | 🟢 100% (1.0 clean, 0.897 jittered logged) | lossy/weberblog + clean | test_reassembly.py |
| 2 | cipher 100% | >98% | 🟢 100% 9/9 | real pcaps vs manifest | test_handshake cipher exact |
| 3 | cert prec1.000 CABF | >90% | 🟢 1.000 | limbo CABF 12 | test_chain_limbo |
| 4 | cert prec1.000 private | >90% | 🟢 1.000 | limbo private 8 | test_chain_limbo |
| 5 | weak 100% | 100% | 🟢 7/7 100% | 03-10+09 23-check | test_rules weak recall |
| + | JSON 20/20 | 20/20 | 🟢 20/20 | FlowVerdict | test_schema |
| + | 14/20 REAL | 14/20 | 🟢 14/20 REAL +3 info | dashboard honesty | CoverageTable |

**Section B ML 🟡 in-progress — Day8-10 lean:** XGB Platt cv=2 ECE 500-boot hi 0.115 <0.20 (CI width ±0.10 disclosed, 500 lean vs 1000 stretch), ECOD ROC point>0.60, calibrated_prob 0..1 (max predict_proba), anomaly_score ECOD decision_scores, eval/calibration_curve.png 10 bins + eval/risk_pr.png AP 1.00, models/risk_clf.pkl 0.12M <5M, models/anomaly.pkl wiring. Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

---

## 1. Risk model lean — XGB Platt cv2

- TRAIN: 31 envs (10 base +21 jitter) via build_vector(mode='xgb') 28-col, binary label High/Critical=1 else 0, n_eff=10 disclosed, D1 12 / D2 8 grouped StratifiedGroupKFold 5-fold outer, Platt inner cv2
- XGBClassifier(tree_method='hist', device='cpu', enable_categorical=True, max_depth=4, n_estimators=80, reg_alpha=1.0, reg_lambda=2.0, subsample=0.8, colsample_bytree=0.8, random_state=42) + CalibratedClassifierCV(estimator, method='sigmoid', cv=2) — Platt only, no isotonic
- FIT lean 0.06s <1s, PYTHONHASHSEED=0 OMP_NUM_THREADS=6, enable_categorical requires pandas DataFrame[col].astype('category'), calibrated_prob max predict_proba
- ECE 500-boot family-level (resample families n_eff=10): ECE hi 0.115 <0.20, CI [0.082,0.115] width 0.033 disclose ±0.10, calibration_curve 10 bins
- permutation importance n_repeats=10 top3 version/cipher_strength/kex coherent vs score.py
- artefacts: models/risk_clf.pkl 0.12M <5M, eval/calibration_curve.png, eval/risk_pr.png

---

## 2. Lineage

manifest.json → pcap → reassembled → features vs tshark 4-prefs parity, shared/ja4_rarity GREASE 16, ALLOWED_RISK_FEATURES ja4 not in ja4_rarity in
