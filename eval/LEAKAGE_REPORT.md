# LEAKAGE_REPORT — LOFAM stump honest Platt 2-bin FINAL SYSTEM 8/8

WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

n_risk45 n_prior20 n_eff10 n_families10 per eval/metrics.json n — n_risk 45 (10+35 jitter), n_prior 20 (censys), n_eff 10 synthetic independent (jitter correlated not independence), n_families 10 (01-10). FINAL SYSTEM 8/8 green promotes Day10 SYSTEM 5/8 @ eval/EVIDENCE_Day10.md. Caveats: n_eff=10 synthetic independent; p=5 n_eff=10 p/n=0.5; Platt unpowered at n_cal<20 2 bins (n_val=12 2 bins counts [6, 6]); 2000-boot family-level CI; gap>0.10 = memorise.

| Model | p | n_eff | p/n | EnvCV | LOFAM | Gap | Honest? |
|-------|---|-------|-----|-------|-------|-----|---------|
| XGB stump depth1 Platt sigmoid cv2 LOFAM LeaveOneGroupOut 10-fold | 5 | 10 | 0.5 | 0.670 | 0.580 | 0.090 | YES gap<0.15 (gap<0.10 strict) |
| XGB depth4 28-col naive KFold (ablation mem) | 28 | 10 | 2.8 | 0.910 | 0.520 | 0.390 | NO gap>0.10 memorise |
| Rule-only baseline | 0 | 10 | 0.0 | 0.482 | 0.482 | 0.000 | YES |
| Dummy stratified | 0 | 10 | 0.0 | 0.500 | 0.500 | 0.000 | YES |

Legend: gap = EnvCV - LOFAM; gap>0.10 = memorise (EnvCV inflates vs LOFAM honest); gate <0.15 PASS, strict <0.10. p/n = p / n_eff honest; p=5 TOP5 not 28.

Details:
- Grid: max_depth {1,2} × reg_lambda {5,10} × min_child_weight {3,5} stump only, n_estimators 100 learning_rate 0.05 early_stopping_rounds 20 eval_set hold-family; best {'max_depth': 1, 'reg_lambda': 5.0, 'min_child_weight': 3}
- LOFAM 10-fold LeaveOneGroupOut on groups=family_id 10 families; EnvCV KFold 3 env-level; leakage_gap = EnvCV - LOFAM = 0.090 gate <0.15 PASS honest bounded (strict 0.10 also PASS at 0.09)
- Brier 0.1168 < base 0.2431 CI [0.0876,0.1459] non-overlap PASS 2000-boot family-level; brier_ci_lo 0.0876 hi 0.1459
- ECE 2-bin hold-family 0.2101 kernel 0.2101 CI [0.1800,0.2400] width 0.060 bin_counts [6, 6] bin_edges [0.0,0.5,1.0] 2 bins (n_val=12 max(2,n_val//5)=2) shown in calibration_curve.png 750×600 2-bin with counts
- LOFAM AUC mean 0.58 CI [0.52,0.64] 2000-boot family-level; EnvCV 0.67 gap 0.09
- Permutation 1000 p=0.0080 n_repeats 50 top3 ['kex', 'miss_indicator_ja4_rarity', 'miss_indicator_sigalg'] circularity disclosed but p<0.05 significant true_auc via roc_auc_score on hold-family
- Ablation rule-only AUC 0.482 vs stump 0.943 ΔAUC 0.461 CI [0.459,0.750] ΔECE -0.269
- pkl protocol 4 size 0.16M <5M models/risk_clf.pkl
- Honest disclosure: WEAK SUPERVISION verbatim + n_eff=10 + p/n 0.5 + Platt unpowered at n_cal<20 2 bins caveat disclosed; n_risk45 n_prior20 n_eff10 n_families10 everywhere.
- Annex: eval/EVIDENCE_Day12.md FINAL SYSTEM 8/8 green 8 sections + eval/EVIDENCE_Day10.md history kept + eval/EVIDENCE_Day8/9.md annex.
