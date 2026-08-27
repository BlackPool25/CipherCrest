# LEAKAGE_REPORT — LOFAM stump honest Platt 2-bin

WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

Caveats: n_eff=50 synthetic independent; p=5 n_eff=50 p/n=0.10; Platt unpowered at n_cal<20 2 bins (n_val=100 20 bins counts [91, 3, 0, 0, 1, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); 2000-boot family-level CI.

| Model | p | n_eff | p/n | EnvCV | LOFAM | Gap | Honest? |
|-------|---|-------|-----|-------|-------|-----|---------|
| XGB stump depth1 Platt sigmoid cv2 LOFAM LeaveOneGroupOut 50-fold | 5 | 50 | 0.1 | 0.993 | 0.992 | 0.000 | YES gap<0.15 |
| Rule-only baseline | 0 | 10 | 0.0 | 0.627 | 0.627 | 0.000 | YES |

Details:
- Grid: max_depth {1,2} × reg_lambda {5,10} × min_child_weight {3,5} stump only, n_estimators 100 learning_rate 0.05 early_stopping_rounds 20 eval_set hold-family; best {'max_depth': 1, 'reg_lambda': 5.0, 'min_child_weight': 3}
- LOFAM 10-fold LeaveOneGroupOut on groups=family_id 10 families; EnvCV KFold 3 env-level; leakage_gap = EnvCV - LOFAM = 0.000 gate <0.15 PASS
- Brier 0.0355 < base 0.0564 CI [0.0162,0.0545] non-overlap PASS
- ECE 20-bin hold-family 0.0826 kernel 0.0545 CI [0.0396,0.1000] width 0.060 bin_counts [91, 3, 0, 0, 1, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
- Permutation 1000 p=0.0010 n_repeats 50 top3 ['miss_indicator_ja4_rarity', 'chain_length', 'chain_valid']
- Ablation rule-only AUC 0.627 vs stump 0.998 ΔAUC 0.371 CI [0.268,0.432] ΔECE -0.050
- pkl protocol 4 size 0.16M <5M
- Honest disclosure: WEAK SUPERVISION verbatim + n_eff=50 + p/n 0.10 + Platt unpowered at n_cal<20 2 bins caveat disclosed.
