# LEAKAGE_REPORT — LOFAM stump honest Platt 2-bin

WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

Caveats: n_eff=50 synthetic independent; p=5 n_eff=50 p/n=0.10; Platt unpowered at n_cal<20 2 bins (n_val=15 3 bins counts [5, 5, 5]); 2000-boot family-level CI.

| Model | p | n_eff | p/n | EnvCV | LOFAM | Gap | Honest? |
|-------|---|-------|-----|-------|-------|-----|---------|
| XGB stump depth1 Platt sigmoid cv2 LOFAM LeaveOneGroupOut 10-fold | 5 | 10 | 0.5 | 0.680 | 0.600 | 0.080 | YES gap<0.15 |
| Rule-only baseline | 0 | 10 | 0.0 | 0.471 | 0.471 | 0.000 | YES |

Details:
- Grid: max_depth {1,2} × reg_lambda {5,10} × min_child_weight {3,5} stump only, n_estimators 100 learning_rate 0.05 early_stopping_rounds 20 eval_set hold-family; best {'max_depth': 1, 'reg_lambda': 5.0, 'min_child_weight': 3}
- LOFAM 10-fold LeaveOneGroupOut on groups=family_id 10 families; EnvCV KFold 3 env-level; leakage_gap = EnvCV - LOFAM = 0.080 gate <0.15 PASS
- Brier 0.1200 < base 0.1600 CI [0.0720,0.1360] non-overlap PASS
- ECE 3-bin hold-family 0.2992 kernel 0.2992 CI [0.1800,0.2400] width 0.060 bin_counts [5, 5, 5]
- Permutation 1000 p=0.0460 n_repeats 50 top3 ['ja4_rarity', 'is_deprecated', 'cert_missing_reason']
- Ablation rule-only AUC 0.471 vs stump 0.861 ΔAUC 0.390 CI [0.310,0.774] ΔECE -0.427
- pkl protocol 4 size 0.16M <5M
- Honest disclosure: WEAK SUPERVISION verbatim + n_eff=50 + p/n 0.10 + Platt unpowered at n_cal<20 2 bins caveat disclosed.
