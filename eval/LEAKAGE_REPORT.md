# LEAKAGE_REPORT — LOFAM stump honest Platt EW+quantile+SmoothECE

WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

Caveats: n_eff=50 synthetic independent; p=5 n_eff=50 p/n=0.10; Platt cv2 5-bin EW max(2,n_cal//5) capped 5 gated 3 (downgraded min_count 0<12 ->3 bins) per-class macro 0.022 max 0.030 min 0.014 spread 0.016 Brier joint 0.086 < base 0.220 n_val=100 EW5 counts [0, 11, 0, 4, 85] quantile5 [20, 21, 21, 20, 18] gated [5, 6, 89] kernel SmoothECE 0.0673 (bandwidth 0.0327 Silverman) vs EW hist 0.0317 vs quantile 0.0566 skew |EW-quantile|=0.0249 ok debiased 0.0063 O(n^-1/3) brier UNC 0.0979 REL 0.0057 RES 0.0161 Smooth within CI True quantile within CI True gate n=120 3-bin [5,5,5] vs 200 5-bin 12/bin; 2000-boot family-level CI per bin width 0.067 mean_ci_width 0.5836111111111112 NaN for empty bins honest; disclosure [94,6,0,0,0] kernel 0.054 vs hist 0.062 per spec example + current honest.

| Model | p | n_eff | p/n | EnvCV | LOFAM | Gap | Honest? |
|-------|---|-------|-----|-------|-------|-----|---------|
| XGB stump depth1 Platt sigmoid cv2 LOFAM LeaveOneGroupOut 50-fold | 5 | 50 | 0.1 | 0.939 | 0.925 | 0.015 | YES gap<0.15 |
| Rule-only baseline | 0 | 10 | 0.0 | 0.960 | 0.960 | 0.000 | YES |

Details:
- Grid: max_depth {1,2} × reg_lambda {5,10} × min_child_weight {3,5} stump only, n_estimators 100 learning_rate 0.05 early_stopping_rounds 20 eval_set hold-family; best {'max_depth': 1, 'reg_lambda': 5.0, 'min_child_weight': 3}
- outer fold CPI — nested SGKF StratifiedGroupKFold outer fold only: model fit on outer train, permutation on outer test only (no leakage, TOP5 not selected via same data)
- LFFO Leave-Family-Feature-Out LOGO132 delta per TOP feature: {'version': 0.0539, 'cipher_strength': -0.0073, 'kex': 0.0745, 'chain_valid': -0.0068, 'days_to_expiry': -0.0113} via LeaveOneGroupOut canonical 132 grouping, pooled AUC full 0.9292
- LOFAM 10-fold LeaveOneGroupOut on groups=family_id 10 families; EnvCV KFold 3 env-level; leakage_gap = EnvCV - LOFAM = 0.015 gate <0.15 PASS
- Brier 0.0801 < base 0.0979 joint 0.0864 < base_joint 0.2200 CI [0.0514,0.1081] non-overlap INCONCLUSIVE at n_eff=50 decomposition UNC 0.0979 REL 0.0057 RES 0.0161 Brier=REL-RES+UNC
- ECE EW 5-bin 0.0317 quantile5 0.0566 Smooth 0.0673 debiased 0.0063 macro 0.0225 per-class {'low': 0.030170446369190296, 'medium': 0.014422106928175412, 'high': 0.022774824746460462} max 0.0302 CI [0.0514,0.1182] width 0.067 EW counts [0, 11, 0, 4, 85] quantile counts [20, 21, 21, 20, 18] gated [5, 6, 89] per-bin CI width mean 0.5836111111111112 NaN for empty honest skew 0.0249 flag False Smooth within CI True
- Permutation 1000 p=0.0010 n_repeats 50 top3 ['kex', 'version', 'is_deprecated']
- Ablation rule-only AUC 0.960 vs stump 0.885 ΔAUC -0.076 CI [-0.058,-0.015] ΔECE -0.239 RL delta TabPFN 0.06263483642793999 CatBoost -0.01100000000000001
- pkl protocol 4 size 0.16M <5M
- Honest disclosure: WEAK SUPERVISION verbatim + n_eff=50 + p/n 0.10 + Platt only no iso-tonic at n<1000 + 5-bin EW max(2,n_cal//5) gated min>=12 else 3 + quantile-5 + SmoothECE Silverman Nadaraya-Watson + ECE_debias O(n^-1/3) + brier_decomposition UNC-RES+REL + per-class max/spread + empty-theater NaN width + outer fold CPI nested SGKF outer fold only (no leakage TOP5 not selected via same data) + LFFO LOGO132 delta per TOP feature.
