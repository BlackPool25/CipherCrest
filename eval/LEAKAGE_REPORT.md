# LEAKAGE_REPORT — LOFAM stump honest Platt EW+quantile+SmoothECE

WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

Caveats: n_eff=50 synthetic independent; p=5 n_eff=50 p/n=0.10; Platt cv2 5-bin EW max(2,n_cal//5) capped 5 gated 3 (downgraded min_count 0<12 ->3 bins) per-class macro 0.024 max 0.036 min 0.005 spread 0.030 Brier joint 0.062 < base 0.220 n_val=100 EW5 counts [99, 1, 0, 0, 0] quantile5 [91, 0, 0, 0, 9] gated [100, 0, 0] kernel SmoothECE 0.0349 (bandwidth 0.0150 Silverman) vs EW hist 0.0398 vs quantile 0.0711 skew |EW-quantile|=0.0313 SKEW debiased 0.0080 O(n^-1/3) brier UNC 0.0564 REL 0.0062 RES 0.0089 Smooth within CI True quantile within CI True gate n=120 3-bin [5,5,5] vs 200 5-bin 12/bin; 2000-boot family-level CI per bin width 0.060 mean_ci_width nan NaN for empty bins honest; disclosure [94,6,0,0,0] kernel 0.054 vs hist 0.062 per spec example + current honest.

| Model | p | n_eff | p/n | EnvCV | LOFAM | Gap | Honest? |
|-------|---|-------|-----|-------|-------|-----|---------|
| XGB stump depth1 Platt sigmoid cv2 LOFAM LeaveOneGroupOut 50-fold | 5 | 50 | 0.1 | 0.993 | 0.992 | 0.001 | YES gap<0.15 |
| Rule-only baseline | 0 | 10 | 0.0 | 0.627 | 0.627 | 0.000 | YES |

Details:
- Grid: max_depth {1,2} × reg_lambda {5,10} × min_child_weight {3,5} stump only, n_estimators 100 learning_rate 0.05 early_stopping_rounds 20 eval_set hold-family; best {'max_depth': 1, 'reg_lambda': 5.0, 'min_child_weight': 3}
- LOFAM 10-fold LeaveOneGroupOut on groups=family_id 10 families; EnvCV KFold 3 env-level; leakage_gap = EnvCV - LOFAM = 0.001 gate <0.15 PASS
- Brier 0.0532 < base 0.0564 joint 0.0622 < base_joint 0.2200 CI [0.0188,0.0842] non-overlap INCONCLUSIVE at n_eff=50 decomposition UNC 0.0564 REL 0.0062 RES 0.0089 Brier=REL-RES+UNC
- ECE EW 5-bin 0.0398 quantile5 0.0711 Smooth 0.0349 debiased 0.0080 macro 0.0239 per-class {'low': 0.005361443105489616, 'medium': 0.030424411222748932, 'high': 0.0357858543282387} max 0.0358 CI [0.0117,0.0722] width 0.060 EW counts [99, 1, 0, 0, 0] quantile counts [91, 0, 0, 0, 9] gated [100, 0, 0] per-bin CI width mean nan NaN for empty honest skew 0.0313 flag True Smooth within CI True
- Permutation 1000 p=0.0010 n_repeats 50 top3 ['chain_length', 'is_aead', 'cipher_strength']
- Ablation rule-only AUC 0.627 vs stump 0.988 ΔAUC 0.361 CI [0.267,0.432] ΔECE -0.093 RL delta TabPFN -0.0034688169699611526 CatBoost -0.01100000000000001
- pkl protocol 4 size 0.16M <5M
- Honest disclosure: WEAK SUPERVISION verbatim + n_eff=50 + p/n 0.10 + Platt only no iso-tonic at n<1000 + 5-bin EW max(2,n_cal//5) gated min>=12 else 3 + quantile-5 + SmoothECE Silverman Nadaraya-Watson + ECE_debias O(n^-1/3) + brier_decomposition UNC-RES+REL + per-class max/spread + empty-theater NaN width.
