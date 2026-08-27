# LEAKAGE_REPORT — LOFAM stump honest Platt 2-bin

WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

Caveats: n_eff=50 synthetic independent; p=5 n_eff=50 p/n=0.10; Platt cv2 5-bin max(2,n_cal//5) capped 5 per-class macro 0.053 Brier joint 0.043 < base 0.220 n_val=100 5 bins counts [94, 6, 0, 0, 0] kernel 0.055 vs histogram 0.062 gate n=120 3-bin [5,5,5] vs 200 5-bin 12/bin; 2000-boot family-level CI per bin width 0.060.

| Model | p | n_eff | p/n | EnvCV | LOFAM | Gap | Honest? |
|-------|---|-------|-----|-------|-------|-----|---------|
| XGB stump depth1 Platt sigmoid cv2 LOFAM LeaveOneGroupOut 50-fold | 5 | 50 | 0.1 | 0.993 | 0.992 | 0.000 | YES gap<0.15 |
| Rule-only baseline | 0 | 10 | 0.0 | 0.627 | 0.627 | 0.000 | YES |

Details:
- Grid: max_depth {1,2} × reg_lambda {5,10} × min_child_weight {3,5} stump only, n_estimators 100 learning_rate 0.05 early_stopping_rounds 20 eval_set hold-family; best {'max_depth': 1, 'reg_lambda': 5.0, 'min_child_weight': 3}
- LOFAM 10-fold LeaveOneGroupOut on groups=family_id 10 families; EnvCV KFold 3 env-level; leakage_gap = EnvCV - LOFAM = 0.000 gate <0.15 PASS
- Brier 0.0355 < base 0.0564 joint 0.0428 < base_joint 0.2200 CI [0.0162,0.0545] non-overlap PASS
- ECE 5-bin hold-family 0.0620 kernel 0.0545 macro 0.0532 per-class {'low': 0.018126727170159104, 'medium': 0.07683903500780055, 'high': 0.06473590763043242} CI [0.0396,0.1000] width 0.060 bin_counts [94, 6, 0, 0, 0] per-bin CI width mean 0.104 narrow at n=50 wide at n=200 honest
- Permutation 1000 p=0.0010 n_repeats 50 top3 ['miss_indicator_ja4_rarity', 'chain_length', 'chain_valid']
- Ablation rule-only AUC 0.627 vs stump 0.998 ΔAUC 0.371 CI [0.268,0.432] ΔECE -0.070 RL delta TabPFN -0.0034688169699611526 CatBoost -0.01100000000000001
- pkl protocol 4 size 0.16M <5M
- Honest disclosure: WEAK SUPERVISION verbatim + n_eff=50 + p/n 0.10 + Platt only no iso-tonic at n<1000 + 5-bin max(2,n_cal//5) capped 5 + per-class macro + Brier joint.
