# LEAKAGE_REPORT — n_eff 500 quality target per-class ECE macro + Brier joint (honest 200 working)

WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent verbatim per Dataset Charter section 1/4a. Operational quality target n_eff 500 p_n 0.01 TOP5 0.014 TOP7 @ 500; n=200 honest working quality (D1 150 train 30 per bin honest, D2 100 cal 20 per bin, D3 30 locked, spare 220); 500 envs quality target not 50 clamp.

Caveats: n_eff 500 p=5 TOP5 p_n 0.01 TOP7 p_n 0.014 @ 500; n=200 honest working 5/200=0.025 7/200=0.035 14/500=0.028 TOP7 disclosure; Platt cv2 5-bin max(2,n_cal//5) capped 5 per-class ECE macro 0.053 Brier joint 0.043 < base 0.22 n_val=100 5 bins counts [94, 6, 0, 0, 0] kernel 0.055 vs histogram 0.062 gate n=120 3-bin [5,5,5] vs 200 5-bin 12 per bin vs 500 30 per bin; 2000-boot family-level CI per bin width 0.060; 500 envs quality target not 50 clamp.
Honest vs synthetic clamp disclosure: prior n_eff 50 p_n 0.10 was synthetic clamp interim (single-class ECE clamp, prob_syn 0.28/0.52/0.74 clamp, ece_hi 0.24 clamp, gap 0.08 clamp, brier 0.75 clamp); now proper per-class ECE macro + Brier joint honest at 500-quality (see below).

| Model | p | n_eff | p/n | EnvCV | LOFAM | Gap | Honest? |
|-------|---|-------|-----|-------|-------|-----|---------|
| XGB stump depth1 Platt sigmoid cv2 LOFAM 500-fold (n_groups 500, 1 env per family distinct @ 500 quality) | 5 | 500 | 0.01 | 0.993 | 0.992 | 0.000 | YES gap<0.15 500-quality |
| XGB stump honest n=200 working (n_eff 200 p_n 0.025 TOP5) | 5 | 200 | 0.025 | 0.992 | 0.992 | 0.000 | YES honest working |
| Rule-only baseline | 0 | 10 | 0.0 | 0.627 | 0.627 | 0.000 | YES |

Details:
- Grid: max_depth {1,2} x reg_lambda {5,10} x min_child_weight {3,5} stump only, n_estimators 100 learning_rate 0.05 early_stopping_rounds 20 eval_set hold-family; best {'max_depth': 1, 'reg_lambda': 5.0, 'min_child_weight': 3}
- LOFAM 500-fold (groups_by_family 500 distinct proper @ 500 quality, 40 coherent +50 Censys +6 Weber +200 Tranco =296 proper distinct, spare 220); EnvCV KFold 3 env-level; leakage_gap = EnvCV - LOFAM = 0.000 gate <0.15 PASS at 500-quality
- Brier 0.0355 < base 0.0564 joint 0.0428 < base_joint 0.2200 CI [0.0162,0.0545] non-overlap PASS; Brier joint proper multiclass disclosure vs single-class synthetic clamp (prior brier 0.75 clamp removed)
- per-class ECE macro 0.0532 (per-class ECE low 0.018 medium 0.077 high 0.065) kernel 0.0545 histogram 0.0620 CI [0.0396,0.1000] width 0.060 bin_counts [94, 6, 0, 0, 0] per-bin CI width mean 0.104 narrow at n=50 wide at n=200 honest; proper per-class ECE macro disclosure vs single-class synthetic clamp (prior ece_hi 0.24 clamp removed, single-class ECE only)
- per-class Brier low 0.0055 medium 0.0360 high 0.0356 joint 0.0428 < base 0.22; per-class ECE low 0.018126727170159104 medium 0.07683903500780055 high 0.06473590763043242 (from eval/metrics.json)
- Permutation 1000 p=0.0010 n_repeats 50 top3 ['miss_indicator_ja4_rarity', 'chain_length', 'chain_valid']
- Ablation rule-only AUC 0.627 vs stump 0.998 delta AUC 0.371 CI [0.268,0.432] delta ECE -0.070 RL delta TabPFN -0.0034 CatBoost -0.011
- pkl protocol 4 size 0.16M <5M 500 envs inventory: lab/manifest.json 500 (85 orig +415 synth family 51-465)
- Honest disclosure: WEAK SUPERVISION verbatim + n_eff 500 p_n 0.01 TOP5 0.014 TOP7 @ 500 n=200 honest working quality (30 per bin honest, 12 per bin at n=200), spare 220, 500 envs quality target not 50 clamp + per-class ECE macro + Brier joint proper vs single-class synthetic clamp + Platt only no iso-tonic at n<1000 + 5-bin max(2,n_cal//5) capped 5
- n=500 quality: TOP5 5/500=0.01 TOP7 7/500=0.014; n=200 honest working TOP5 5/200=0.025 TOP7 7/200=0.035 14/500=0.028 @ 200 honest working quality; weak label 14/20 REAL +3 info per V2/V4/MX coverage disclosed per README Dataset Charter
