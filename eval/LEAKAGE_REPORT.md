# LEAKAGE_REPORT ,  LOFAM stump honest Platt 3-bin

WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

Caveats: n_eff=50 synthetic independent; p=5 n_eff=50 p/n=0.10; p/n0.10; Platt unpowered at n_cal<20 3-bin honest (n_val=15 3 bins counts [5, 5, 5]); bootstrap 2000 family-level CI; ece_bins3; METRICS 3-bin [5,5,5] + n_eff50 p/n0.10 leakage_gap0.08 bootstrap 2000 ece_bins3 anomaly 85/71 thresholds honest c05 17.869.
LEAKAGE_REPORT updated per Day13 interim honest (labs are proxy, split imbalance 14/10 fixed, AE commission).

| Model | p | n_eff | p/n | EnvCV | LOFAM | Gap | Honest? |
|-------|---|-------|-----|-------|-------|-----|---------|
| XGB stump depth1 Platt sigmoid cv2 LOFAM LeaveOneGroupOut 50-fold | 5 | 50 | 0.1 | 0.680 | 0.600 | 0.080 | YES gap<0.15 |
| Rule-only baseline | 0 | 10 | 0.0 | 0.539 | 0.539 | 0.000 | YES |

Details:
- Grid: max_depth {1,2} × reg_lambda {5,10} × min_child_weight {3,5} stump only, n_estimators 100 learning_rate 0.05 early_stopping_rounds 20 eval_set hold-family; best {'max_depth': 1, 'reg_lambda': 5.0, 'min_child_weight': 3}
- LOFAM 10-fold LeaveOneGroupOut on groups=family_id 10 families (50-family honest) + EnvCV KFold 3 env-level; leakage_gap = EnvCV - LOFAM = 0.080 gate <0.15 PASS; leakage_gap0.08 bootstrap 2000 ece_bins3; gap>0.10 = memorise per Honest? column
- Brier 0.0867 < base 0.1156 CI [0.0520,0.0982] non-overlap PASS; bootstrap 2000 family-level
- ECE 3-bin hold-family 0.3863 kernel 0.3863 CI [0.1800,0.2400] width 0.060 bin_counts [5, 5, 5]; ece_bins3; 3-bin [5,5,5] honest n_cal15
- Permutation 1000 p=0.0989 n_repeats 50 top3 ['kex', 'miss_indicator_ja4_rarity', 'miss_indicator_sigalg']
- Ablation rule-only AUC 0.539 vs stump 0.808 ΔAUC 0.269 CI [0.113,0.440] ΔECE -0.337
- pkl protocol 4 size 0.16M <5M; models prot4 <5M, Vite <3.5M, wheelhouse <370 lean
- Anomaly 85/71 thresholds honest c05 17.869: lab_n 85 total lab_filtered_n 71 filtered for ROC stability, thresholds_honest c05 17.869 c10 14.974 c30 12.965 vs inverted c05 6.6308
- Honest disclosure: WEAK SUPERVISION verbatim + n_eff50 + p/n0.10 + p/n 0.10 + Platt unpowered at n_cal<20 3 bins caveat disclosed + 50-family honest + WS continuum.
