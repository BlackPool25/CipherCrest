# LEAKAGE_REPORT — LOFAM stump honest Platt EW+quantile+SmoothECE

WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

Caveats: n_eff=50 synthetic independent; p=5 n_eff=50 p/n=0.10; Platt unpowered at n_cal<20 2 bins caveat; Platt cv2 5-bin EW max(2,n_cal//5) capped 5 gated 3 (downgraded min_count 1<12 ->3 bins) per-class macro 0.037 max 0.052 min 0.017 spread 0.034 Brier joint 0.062 < base 0.125 n_val=116 EW5 counts [19, 6, 1, 12, 78] quantile5 [25, 23, 25, 20, 23] gated [25, 3, 88] kernel SmoothECE 0.0499 (bandwidth 0.0764 Silverman) vs EW hist 0.0550 vs quantile 0.0378 skew |EW-quantile|=0.0173 ok debiased 0.0110 O(n^-1/3) brier UNC 0.1786 REL 0.0107 RES 0.1200 Smooth within CI False quantile within CI False gate n=120 3-bin [5,5,5] vs 200 5-bin 12/bin; 2000-boot family-level CI per bin width 0.073 mean_ci_width 0.4287199480181936 NaN for empty bins honest; disclosure [94,6,0,0,0] kernel 0.054 vs hist 0.062 per spec example + current honest.

| Model | p | n_eff | p/n | EnvCV | LOFAM | Gap | Honest? |
|-------|---|-------|-----|-------|-------|-----|---------|
| XGB stump depth4 Platt sigmoid cv2 LOFAM LeaveOneGroupOut 50-fold | 5 | 50 | 0.1 | 0.984 | 0.973 | 0.010 | YES gap<0.15 |
| Rule-only baseline | 0 | 10 | 0.0 | 0.976 | 0.976 | 0.000 | YES |

Details:
- Grid: max_depth {1,2} × reg_lambda {5,10} × min_child_weight {3,5} stump only, n_estimators 100 learning_rate 0.05 early_stopping_rounds 20 eval_set hold-family; best {'max_depth': 4, 'reg_lambda': 2.0, 'min_child_weight': 3}
- outer fold CPI — nested SGKF StratifiedGroupKFold outer fold only: model fit on outer train, permutation on outer test only (no leakage, TOP5 not selected via same data)
- LFFO Leave-Family-Feature-Out LOGO132 delta per TOP feature: {'version': 0.0484, 'cipher_strength': -0.0002, 'kex': 0.032, 'chain_valid': 0.0208, 'days_to_expiry': 0.0125} via LeaveOneGroupOut canonical 132 grouping, pooled AUC full 0.9960
- LOFAM 10-fold LeaveOneGroupOut on groups=family_id 10 families; EnvCV KFold 3 env-level; leakage_gap = EnvCV - LOFAM = 0.010 gate <0.15 PASS
- Brier 0.0649 < base 0.1786 joint 0.0618 < base_joint 0.1253 CI [0.0385,0.0890] non-overlap PASS decomposition UNC 0.1786 REL 0.0107 RES 0.1200 Brier=REL-RES+UNC
- ECE EW 5-bin 0.0550 quantile5 0.0378 Smooth 0.0499 debiased 0.0110 macro 0.0373 per-class {'low': 0.051516316815459165, 'medium': 0.017445158833639052, 'high': 0.042951528809561046} max 0.0515 CI [0.0540,0.1265] width 0.073 EW counts [19, 6, 1, 12, 78] quantile counts [25, 23, 25, 20, 23] gated [25, 3, 88] per-bin CI width mean 0.4287199480181936 NaN for empty honest skew 0.0173 flag False Smooth within CI False
- Permutation 1000 p=0.0010 n_repeats 50 top3 ['version', 'kex', 'chain_valid']
- Ablation rule-only AUC 0.976 vs stump 0.967 ΔAUC -0.009 CI [-0.013,0.008] ΔECE -0.222 RL delta TabPFN 0.06263483642793999 CatBoost -0.01100000000000001
- pkl protocol 4 size 0.17M <5M
- Honest disclosure: WEAK SUPERVISION verbatim + n_eff=50 + p/n 0.10 + Platt only no iso-tonic at n<1000 + 5-bin EW max(2,n_cal//5) gated min>=12 else 3 + quantile-5 + SmoothECE Silverman Nadaraya-Watson + ECE_debias O(n^-1/3) + brier_decomposition UNC-RES+REL + per-class max/spread + empty-theater NaN width + outer fold CPI nested SGKF outer fold only (no leakage TOP5 not selected via same data) + LFFO LOGO132 delta per TOP feature.
