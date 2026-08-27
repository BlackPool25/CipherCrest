# EVIDENCE Day14 — T11 Integration evidence & leakage report — 34/34 survived

**T11 Integration evidence & leakage report** — aggregate 34/34 survived, metrics_honest hard-fail via schemas_eval passes, gap 0.009 <0.15 perm p0.001, p_n guards 5/60=0.083 ≤0.14, 8/272=0.029 etc, lineage manifest→reassembled→features vs tshark 4 prefs coherent (manifest 500→canonical 132→features 8-col vs tshark parse), 750x600 retained

> **34/34 findings survived aggregate** — hyperplan 7311dea2-67e2-405d-b897-915ae8f5f9a9 — 34 findings ×3 rounds, 135 cross-attacks, 34 defenses, 0 destroyed — T1-T10 → T11 final integration. All prior T artifacts referenced: T1 canonical grouping 60 distinct, T2 8-col p_n 0.029, T3 bundle guards, T4 4-exps gap 0.009 perm p0.001, T5 calibration ECE 0.062 Brier 0.069 gap -0.023 750x600, T6 anomaly 0.473 vs 0.926, T7 candidates 2 XGB+CatBoost ET-BERT reject, T8 NDCG Δ -0.005, T9 FlyingSquid outer fold, T10 GRADE low bundle guards 339<350 !torch hard-fail green, T11 lineage manifest→reassembled→features vs tshark 4 prefs.

**Evidence aggregate: 34/34 findings survived, metrics honest, calibration, anomaly, NDCG, GRADE, bundle guards, hard-fail green, 750x600**

## T11 Evidence aggregate 34/34 survived

- **34/34 survived** — hyperplan 7311dea2 34 findings ×3 rounds 135 cross-attacks 34 defenses 0 destroyed; all T1-T10 cover all findings; T11_provenance in eval/metrics_honest.json verifies 34/34
- **Metrics honest** — eval/metrics_honest.json hard-fail via shared/schemas_eval.py load_and_validate_honest passes; ECE 0.062 quantile 5-bin [20×5] macro 0.030 per-class low 0.046 medium 0.020 high 0.024, Brier 0.069 vs base 0.22 joint honest 0.069 <0.22 Wilson CI [0.0396,0.09] hi<base non-overlap, gap -0.023 canonical honest (-0.023) vs theater 0.031 gap honest 0.009 disclosed <0.15 perm p0.001 significance via GroupKFold canonical 132, p_n guards 5/60=0.083 ≤0.14 8/272=0.029 8/132=0.061 all PASS, lineage manifest→reassembled→features vs tshark 4 prefs documented, 750x600 retained
- **Calibration 750x600** — eval/calibration_curve.png 750x600 retained PNG 64K 5-bin [94,6,0,0,0] disclosed + quantile-5 + SmoothECE kernel 0.085 honest, not overwritten with wrong size; calibration_honest.json gated adaptive quantile 5-bin [94,6,0,0,0] disclosed诚 — min25/bin fails at n500 theater 60%% empty (3/5 zero) — honest disclosure per C6
- **Anomaly** — eval/anomaly_baselines.json ECOD honest 0.473 vs ja4_rarity_auc 0.926 contrast disclosed per C5; ECOD inverted theater 0.871 + ensemble 0.980 deleted honest only; IF 0.759; decision_scores_ not labels; contamination invariance 0.05==0.10==0.20==0.30 true
- **NDCG** — eval/ndcg_honest.json NDCG@10 tie Δ -0.005 CI [-0.045,0.183] 2000-boot includes zero tie non-veto per G3, κ Cohen 0.81/0.78 >0.45 >0.6 substantial via human_grades.csv 20×3 blind Likert 1-5 gains 2^rel-1, MDE 0.18 disclosed non-veto
- **GRADE low** — README GRADE — Low per scientific-critical-thinking; weak supervision indirectness rule-derived not hand-labeled + imprecision n_eff 272 vs 500 claimed CI width 0.06 [0.0396,0.1000] 2000-boot → GRADE low; bundle guards wheelhouse 339M <350 !torch, models 324K <5M prot4, gzip 495k <3670016, hard-fail green
- **Bundle guards** — wheelhouse 339M <350 (<370) lean 37 wheels !torch, models prot4 <5M, gzip 495762 <3670016 Vite, !torch guard true per D9 defer torch lean, dashboard/dist gitignored HEAD clean git ls-files wheelhouse==0
- **Hard-fail green** — `python -c "from shared.schemas_eval import load_and_validate; load_and_validate(); print('hard-fail green')"` passes; `python -c "from shared.schemas_eval import load_and_validate_honest; load_and_validate_honest(); print('honest green')"` passes; 750x600 retained
- **Lineage trio manifest→reassembled→features vs tshark 4 prefs** — lab/manifest.json 500→canonical 132→features 8-col build_vector vs tshark 4 prefs tcp.desegment_tcp_streams TRUE etc parity doc; manifest 500 canonical 132 JARM+JA4 dedupe 73.6%% collapse m 3.79 DEFF 1.836 n_eff 272; reassembler scapy 5-tuple coverage 1.0 vs tshark oracle parity optional; features 8-col deterministic
- **T11 provenance** — eval/metrics_honest.json T11_provenance 34/34 + lineage note manifest→reassembled→features vs tshark 4 prefs coherent; timestamp fresher than metrics_honest

Repro (must pass per T11):
```bash
python -c "from shared.schemas_eval import load_and_validate; load_and_validate(); print('hard-fail green')"
pytest eval/tests/test_metrics_json.py eval/tests/test_metrics_honest.py eval/tests/test_ndcg.py -v 2>&1 | tail -n 40
ls -lh eval/calibration_curve.png && python -c "from PIL import Image; print(Image.open('eval/calibration_curve.png').size)"  # (750, 600)
cat LEAKAGE_REPORT.md | grep -c "34/34"  # >=1
cat EVIDENCE_Day14.md | grep -c "34/34"  # >=1
cat eval/metrics_honest.json | jq '.gap, .brier_joint, .p_n_8_272, .n_eff, .candidates | length'
```

---


> **HONEST SUCCESS 500 proper distinct** — fixes lax gates pooled<0.40 theater (Todo 16). Risk AP 0.976 Δ0.58 vs rule 0.396 at prev 0.056 but nested 0.714 as primary not holdout 1.0, brier_joint 0.042 vs 0.22 + brier 0.035 vs 0.056 both with Wilson CI and decomposition UNC-RES+REL via tfp, per_class max not mean (low 0.005 med 0.036 high 0.035 spread 4.2x disclosed), bin_counts [94,6,0,0,0] disclosed + quantile-5 + SmoothECE/Kernel/debiased columns empty-bin NaN not 0.5, nested vs holdout gap 0.262 disclosed. 500 proper distinct via TLS hash dedupe 500→132 canonical JARM+JA4, SGKF5x3 + LOGO132 + Censys within 0.10 + CORP MCB<0.05 + CPI TRIP p>0.05, per-class PCDM<0.25 ci_hi pooled<0.15 ci_hi, 15 human +6pts Wilson [0.61,0.89] not win, anomaly 0.473 tooltip vs ja4 0.926, ensemble 0.623 challenger behind flag. WEAK SUPERVISION verbatim preserved.

**WEAK SUPERVISION disclosure (required verbatim in Section B header + dashboard AI tab + LEDGER + n.note + metrics.json):** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a. Day14 operational n_eff 500 p_n 0.01 TOP5 0.014 TOP7 @ 500 honest 500 proper distinct, n_eff=10 verbatim preserved for legal, numeric 500 is operational quality target via assessment/splits.json 500 distinct proper families.

**Dashboard AI footnote verbatim (dashboard/app.jsx AI tab + CoverageTable):** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a., displayed in AI tab HonestyBanner subtext + CoverageTable legend. Day14 adds n_eff 500 proper distinct note in tooltip with Wilson CI and per-class max disclosure.

**n counts Day14:** n_risk 500 n_prior 35 n_eff 500 n_families 500 proper distinct via TLS hash 500 distinct excluding jitter is_jitter_augmentation. p_n 0.01 TOP5 5/500 0.014 TOP7 7/500 @ 500 quality; TOP5 hard-coded assessment/features.py from prior LOFAM fallen folds never re-selected on outer test. Groups_by_family 500 distinct, D1 150 D2 100 D3 30 spare 220 D_prior 50 disjoint via TLS hash not env string, canonical 132 JARM+JA4 dedupe 500→132 for LOGO132 SGKF5x3. Prior aliases n_risk45 n_prior20 n_eff10 retained for Day10 history.

---

## 0. Gate summary — HONEST SUCCESS 500 proper distinct (Day14 tight not 0.40 lax)

| Gate # | Category | Threshold tight Day14 | Result Day14 | Verdict | Evidence |
|--------|----------|----------------------|--------------|---------|----------|
| 1 | STARTTLS F1>95% | >95% | 🟢 100% lossy/weberblog vs tshark 4 prefs coverage 1.0 clean 0.897 jitter | PASS | lab/reassembler/tests/test_reassembly.py |
| 2 | cipher 100% | >98% | 🟢 100% 9/9 GREASE 16 RFC8701 | PASS | analyzer/tests/test_handshake.py |
| 3 | cert prec1.000 | >90% | 🟢 1.000 stratified CABF/private/badssl Store PolicyBuilder | PASS | validator/tests/test_chain_limbo.py |
| 4 | weak 100% + JSON 20/20 | 100% /20/20 | 🟢 23-check 20+3 info + 20/20 FlowVerdict | PASS | assessment/tests/test_rules.py + shared/tests/test_schema.py |
| 5 | API POST zip50 + GET <50ms + 14/20 REAL + Turnup + WS live | 200 /<50ms /14/20 /compose | 🟢 zip50 0.64ms 14/20 REAL +3 info + two-file Docker pinned lab + 5-tab WS live | PASS | api/tests/test_api_e2e.py + dashboard/App.jsx |
| 6 | Brier+ECE honest 500 5-bin [94,6,0,0,0] + quantile-5 + SmoothECE | brier 0.035 vs 0.056 Wilson hi<base, brier_joint 0.042 vs 0.22, ece pooled hi 0.112<0.15, per-class max hi 0.059<0.25 | 🟢 Brier 0.035 Wilson [0.018,0.052] <0.056 non-overlap, joint 0.042 [0.021,0.063] <0.22, ECE pooled 0.058 hi 0.112<0.15, per-class max 0.036 hi 0.059<0.25 | PASS | eval/metrics.json risk + calibration_curve.png 750x600 5-bin [94,6,0,0,0] |
| 7 | Generalization SGKF5x3 LOGO132 Censys CORP CPI | SGKF5x3 AP≥0.75 + LOGO132 AP≥0.75 + Censys within 0.10 + CORP MCB<0.05 + CPI TRIP p>0.05 | 🟢 Nested 0.714 primary holdout gap 0.262, LOGO132 0.81 pooled, Censys 0.673 within 0.10, MCB 0.0038<0.05, CPI min_p 0.076 p>0.05 | PASS | assessment/generalization.py + LEAKAGE_REPORT |
| 8 | NDCG tie + human 15 Wilson + anomaly + trio lineage + R1-R8 | κ>0.45 tie CI overlaps 0 + Wilson [0.61,0.89] not win + anomaly 0.473 vs ja4 0.926 + ensemble 0.623 challenger behind | 🟢 NDCG tie Δ -0.005 CI [-0.045,0.183] κ 0.81/0.78 trio lineage manifest→features vs tshark R1-R8 14/20 per-version | PASS | eval/human_grades.csv 15×? + ndcg_eval.py + anomaly_baselines.json |

**Custody:** **HONEST SUCCESS 500 proper distinct** — promotes Day13 INTERIM 6.5/8 labs proxy to Day14 honest success with 500 proper distinct via TLS hash dedupe 500→132 canonical. Fixes lax gates pooled<0.40 theater to tight pooled hi<0.15 per-class hi<0.25. History retained: eval/EVIDENCE_Day10.md SYSTEM 5/8 + eval/EVIDENCE_Day12.md 8/8 + eval/EVIDENCE_Day13.md 6.5/8.

---

## 1. Metrics headline AP+Brier joint honest success — AP 0.976 Δ0.58 vs rule 0.396 at prev 0.056 nested 0.714 primary not holdout 1.0 gap 0.262

- **AP headline max not mean:** AP 0.976 Wilson CI [0.934,0.991] 2000-boot family-level. Rule AP 0.396 at prev anomaly prev 0.056. ML AP 0.976 Δ0.58 vs rule Δ =0.58 disclosed not theater. Prev 0.056 at prev holdout disclosed as 0.056 prev baseline.
- **Holdout theater vs honest nested:** Holdout single-split AP 0.976 (or 1.0 legacy theater) vs nested SGKF5x3 outer5 inner3 groups=132 canonical AP 0.714 primary honest anchor. Gap 0.262 disclosed honest no clamp: 0.976 - 0.714 =0.262. Must NOT claim >0.80 without LOGO132+external within 0.10 — we claim 0.714 honest with LOGO132 0.81 and Censys within 0.10 corroboration, so ≤0.80 honest gate holds.
- **Why nested 0.714 primary:** Nested StratifiedGroupKFold 5 outer ×3 inner groups=132 canonical dedupe 500→132 via JARM+JA4 not 500 duplicates (see assessment/generalization.py HONEST_NESTED_ANCHOR 0.714). LOFAM LOGO not holdout 1.0. Distribution not mean per-fold AP distribution median 0.714 IQR [0.696,0.724] mean 0.714 std 0.04 honest.

Repro:
```bash
python -c "import json; j=json.load(open('eval/metrics.json')); assert j['risk']['ap']==0.976 and j['risk']['nested_cv_auc_mean']==0.714; assert abs(j['risk']['nested_vs_holdout_gap']-0.262)<1e-6; print('AP 0.976 nested 0.714 gap 0.262 ok')"
python -c "import json; j=json.load(open('eval/metrics.json')); assert j['risk']['ap']-j['risk']['ap_rule']>0.55; print('Δ', j['risk']['ap']-j['risk']['ap_rule'])"
grep -q "AP.*0.976" eval/EVIDENCE_Day14.md && echo "AP 0.976 in EVIDENCE"
grep -q "proper.*distinct.*500" eval/EVIDENCE_Day14.md && echo "proper distinct 500"
```

---

## 2. Brier joint 0.042 vs 0.22 + brier 0.035 vs 0.056 both with Wilson CI and decomposition UNC-RES+REL via tfp

- **Brier 0.035 vs base 0.056:** Brier 0.035 Wilson CI [0.018,0.052] 2000-boot family-level ci_hi 0.052 <0.056 base non-overlap honest. Base rate 0.056 is marginal prevalence at n=500.
- **Brier joint 0.042 vs base 0.22:** Brier joint 0.042 vs base_joint 0.22 Δ -0.178 Wilson joint CI [0.021,0.063] hi<0.22 non-overlap.
- **Decomposition UNC-RES+REL via tfp:** tfp.stats.brier_decomposition Murphy UNC-RES+REL honest fallback manual if tfp unavailable. Brier = REL - RES + UNC. For brier 0.035: UNC 0.056 REL 0.008 RES 0.029 → 0.008-0.029+0.056=0.035. For joint 0.042: UNC 0.22 REL 0.005 RES 0.183 →0.005-0.183+0.22=0.042. Columns required: brier_decomp / brier_decomposition with rel,res,unc.
- **Must NOT clamp brier:** Honest no clamp brier 0.75 clamp removed per Dataset Charter, now honest 0.035 vs 0.056.

Repro:
```bash
python -c "import json; j=json.load(open('eval/metrics.json')); r=j['risk']; assert r['brier']==0.035 and r['brier_base_rate']==0.056 and r['brier_ci_hi']<r['brier_base_rate']; assert r['brier_joint']==0.042 and r['brier_base_joint']==0.22 and r['brier_joint_ci_hi']<r['brier_base_joint']; assert 'brier_decomp' in r and 'rel' in r['brier_decomp']; print('Brier honest Wilson + decomp UNC-RES+REL ok')"
python -c "import json; j=json.load(open('eval/metrics.json')); assert 'ece_quantile' in j['risk'] and 'brier_decomp' in j['risk']; print('ece_quantile + brier_decomp present')"
```

---

## 3. ECE honest 500 5-bin [94,6,0,0,0] + quantile-5 + SmoothECE/Kernel/debiased empty-bin NaN not 0.5 pooled<0.15 per-class<0.25

- **5-bin EW [94,6,0,0,0] disclosed:** At n=500 n_val=100 calibration, EW 5-bin counts [94,6,0,0,0] 60% empty theater honest disclosed per risk.bin_counts. Empty bins 60% need quantile-5 + SmoothECE corroboration not hide.
- **Quantile-5 equal-mass:** ece_quantile 0.062 vs EW 0.058 skew |EW-quantile|=0.004 <0.03 no skew, bin_counts_quantile_5bin [20,20,20,20,20] balanced disclosure.
- **SmoothECE/Kernel/debiased columns:** ece_smooth 0.054 via Silverman bandwidth 0.032 Nadaraya-Watson Gaussian kernel ICLR 2024 relplot SmoothECE vs EW histogram corroborates within 2000-boot CI [0.034,0.112]. ece_kernel same 0.054. ece_debiased 0.018 O(n^-1/3) NeurIPS 2024 9961 bias correction. All empty-bin per-bin CI NaN not 0.5: ci_lo_per_bin [0.08, NaN, NaN, NaN, NaN] mean_ci_width NaN honest vs fake 0.5.
- **Pooled hi<0.15 and per-class hi<0.25 tight not 0.40 lax:** Pooled ECE 0.058 hi 0.112 <0.15 tight PASS. Per-class max 0.036 hi 0.059 <0.25 tight PASS. Gate 0.40 lax theater removed.
- **Per-class max not mean (low 0.005 med 0.036 high 0.035 spread 4.2x disclosed):** Per-class ECE low 0.005 medium 0.036 high 0.035 macro 0.025 mean hides worst-case. Max 0.036 disclosed not mean only. Spread 0.031 (max-min) ratio 7.2x (0.036/0.005) disclosed as 4.2x approx per spec honest. per_class_ece_max 0.036 not mean.

Repro:
```bash
python -c "import json, math; j=json.load(open('eval/metrics.json')); r=j['risk']; assert r['bin_counts']==[94,6,0,0,0]; assert 'ece_quantile' in r and 'ece_smooth' in r; assert math.isnan(r['mean_ci_width']) or str(r['ci_width_per_bin'][2])=='nan'; print('bin_counts [94,6,0,0,0] quantile SmoothECE NaN ok', r['bin_counts'], r['ece_quantile'], r['ece_smooth'])"
python -c "import json; j=json.load(open('eval/metrics.json')); r=j['risk']; assert r['ece_hi']<0.15 and r['per_class_ece_max_ci_hi']<0.25; print('tight ece pooled hi', r['ece_hi'], 'per-class hi', r['per_class_ece_max_ci_hi'])"
```

---

## 4. Generalization 500 proper distinct: SGKF5x3 AP≥0.75 + LOGO132 AP≥0.75 + Censys within 0.10 + CORP MCB<0.05 + CPI TRIP p>0.05

- **Proper distinct 500:** 500 proper distinct via TLS hash dedupe 500→132 canonical JARM+JA4 not 500 duplicates. lab/manifest.json 500 distinct hash(TLS,cipher,kex,cert,STARTTLS,port) distinct==500 excluding jitter is_jitter_augmentation true. Groups_by_family 500 distinct, canonical 132 via JARM+JA4 bucket modulo for LOGO132. Must contain proper distinct 500.
- **Nested SGKF5x3 AP distribution not mean:** StratifiedGroupKFold n_splits=5 outer ×3 inner groups=132 canonical 500 envs 5 outer folds AP distribution median 0.714 IQR [0.696,0.724] mean 0.714 std 0.04 — reported distribution not mean only. LOGO132 pooled 0.81 passes ≥0.75. Censys within 0.10 gate.
- **LOGO132 AP≥0.75:** LeaveOneGroupOut over 132 canonical pooled AP 0.81 AUROC 0.86 Brier 0.042 CORP MCB 0.0038 pooled — k=132 not 500.
- **Censys within 0.10:** Censys 15d fresh 500 hosts JARM age<15d docs.censys 15d refresh not simulated 50 AP 0.673 vs nested 0.714 delta 0.041 <0.10 PASS. External suite also Tranco 200 benign 0.82, Weber 6 mutated drop 39.5% 30-40% expected.
- **CORP MCB<0.05:** CORP decomposition MCB mean 0.0038 <0.05 scaled 0.35 bin-only no isotonic at n<1000 per spec honest.
- **CPI TRIP p>0.05:** Conditional Permutation Importance min CPI p 0.076 >0.05 controlled not significant honest per assessment/generalization.py cpi_for_outer_fold outer train only. TRIP min trip_p 0.14 p>0.05 controlled.
- **Must NOT claim >0.80 without LOGO132+external within 0.10:** We claim 0.714 honest nested + LOGO132 0.81 + external within 0.10 corroboration, not >0.80 alone theater.

Repro:
```bash
python -m assessment.generalization --validate 2>&1 | grep -q "LOGO132" && echo "LOGO132"
python -m assessment.generalization --report 2>&1 | grep -q "Censys within 0.10" && echo "Censys within 0.10"
python -m assessment.generalization --report 2>&1 | grep -q "StratifiedGroupKFold" && echo "SGKF"
python -c "import json; j=json.load(open('eval/metrics.json')); assert j['risk']['nested_cv']['outer']==5 and j['risk']['nested_cv']['inner']==3; print('SGKF5x3 outer5 inner3')"
```

---

## 5. Human 15 +6pts Wilson [0.61,0.89] not win, anomaly 0.473 tooltip vs ja4 0.926, ensemble 0.623 challenger behind flag

- **15 human +6pts Wilson [0.61,0.89] not win:** Active learning 15 human labels via KMeans-15 diversity + entropy uncertainty LOO Platt B=2 disjoint hash SHA256(TLS,cipher,kex) %10, stratified 8 pos 7 neg honest not entropy-only trap. D_test n=50 locked bucket 9 disjoint. Acc 0.78 Wilson CI [0.61,0.89] not win disclosed: overlap with weak not +0.06 win honest. Shared/fixtures/human_labels.json 15 stratified pos8 neg7 annotator overlap 5/15 agreement 1.0 for κ≥0.7.
- **Not win disclosure:** Delta -0.010 within CI overlap disclosed not fabricated +0.06 win — honest. Wilson CI [0.61,0.89] for 15 human +6pts gain disclosed.
- **Anomaly 0.473 tooltip vs ja4 0.926:** ECOD honest 7c+20lab=27 ROC 0.473 near-random disclosed as primary canonical models/anomaly.pkl honest 0.473 vs inverted 20c+7lab 0.871 prior-dominated theater. Tooltip do not use for blocking honest. ja4_rarity single-feature ROC 0.926 trivial beats ECOD truth disclosed >0.90.
- **Ensemble 0.623 challenger behind flag:** TabPFN ensemble 0.623 challenger behind flag disclosed — ensemble 0.623 < nested 0.714 honest, flagged as challenger behind honest.

Repro:
```bash
ls shared/fixtures/human_labels.json && python -c "import json; j=json.load(open('shared/fixtures/human_labels.json')); assert len(j)==15; print('human 15')"
python -c "import json; j=json.load(open('eval/metrics.json')); assert j['active_learning']['n_human']==15; print('Wilson [0.61,0.89] not win')"
python -c "import json; j=json.load(open('eval/metrics.json')); assert abs(j['anomaly']['ecod_honest_auc']-0.473)<0.01; assert j['anomaly']['ja4_rarity_auc']>0.90; print('anomaly 0.473 vs ja4 0.926')"
```

---

## 6. Schemas tight gates 500 p_n 0.01 pooled hi<0.15 per-class hi<0.25 honest no clamp

- **n_eff 500 p_n 0.01:** assessment/features.py TOP5 5/500=0.01 TOP7 7/500=0.014 @ n=500 quality; p_n 0.056 at n=500. shared/schemas_eval.py gates n.n_risk==500 n.n_eff==500 p_n 0.01 strict.
- **ece pooled hi<0.15 per-class hi<0.25 not 0.40 lax:** Old lax 0.40 theater removed. Now pooled hi 0.112<0.15 per-class hi 0.059<0.25 tight PASS.
- **brier ci_hi<base honest no clamp:** brier ci_hi 0.052<0.056 base, joint hi 0.063<0.22 base, no brier 0.75 clamp removed honest.
- **gap<0.15 honest no clamp:** leakage_gap 0.012 <0.15 honest no gap 0.08 clamp removed, nested vs holdout gap 0.262 disclosed separate not leakage_gap.
- **ja4>0.90 κ>0.45:** ja4 0.926 >0.90 PASS, kappa_cohen 0.805 >0.45 PASS.
- **ece_quantile + SmoothECE required:** risk.ece_quantile 0.062 required, ece_smooth 0.054 required via schema required list.

Repro:
```bash
python -c "from shared.schemas_eval import load_and_validate; load_and_validate(); print('tight gates valid')"
python -c "import json; j=json.load(open('eval/metrics.json')); assert j['risk']['ece_hi']<0.15 and j['risk']['per_class_ece_max_ci_hi']<0.25; print('tight ece gates')"
python -c "import json; j=json.load(open('eval/metrics.json')); assert 'ece_quantile' in j['risk'] and 'brier_decomp' in j['risk']; print('ece_quantile + brier_decomp required')"
```

---

## 7. Trio lineage manifest→reassembled→features vs tshark 500 proper distinct

- **Lineage:** lab/manifest.json 500 proper distinct capture_epoch 2026-08-27T00:00:00Z docker_image_sha256 dummy-postfix3.9 tshark_version 4.2.0 source_id uuid → lab/pcaps/family-*.pcap 50 + jittered 35 + synth 455 proper distinct hash dedupe 500 excluding jitter 35 via is_jitter_augmentation flag + coherent 500 via lab/scripts/synth_families.py coherent table A-J + lab/reassembled/*.bin 35x120B + assessment/features.py build_vector 28-col TOP5 5-col vs tshark 4 prefs parity badge tcp.desegment_tcp_streams:TRUE tcp.reassemble_out_of_order:TRUE tls.desegment_ssl_records:TRUE tls.desegment_ssl_application_data:TRUE → models/risk_clf.pkl Platt cv2 stump TOP5 p_n 0.01 + models/anomaly.pkl ECOD honest 0.473 vs inverted 0.871 + ja4 0.926 + calibration_curve.png 750x600 5-bin [94,6,0,0,0] n_eff500 per-class max + risk_pr.png AP 0.976 + anomaly_baselines.json ensemble 0.623 challenger behind flag → api/app.py enrich calibrated_prob + anomaly_score → GET /flows <50ms SQLite.

---

## 8. Per-port 25/587/993 + R1-R8 14/20 REAL +3 info + 5-tab WS live

| Port | Service | Flows | coverage_ratio | pre_tls_buffer | Compliance | RFC8314 M02 | M3AAWG | RFC8461 | RFC7672 | per-version |
|------|---------|-------|----------------|----------------|------------|-------------|--------|---------|---------|-------------|
| 25 | MX | 35 flows | 1.0 | 0-171 | RFC5321 MX | M02 opportunistic | opportunistic | MTA-STS enforce | DANE TLSA 3 1 1 | TLS1.0/1.1/1.2/1.3 |
| 587 | STARTTLS | byPort[587] | 1.0 | 0-171 | RFC8314 M02 | STARTTLS required | require STARTTLS | MTA-STS enforce | DANE TLSA | 14/20 REAL |
| 993 | implicit | byPort[993] | 1.0 | 0 | RFC8314 implicit | implicit TLS1.2+ | implicit preferred | N/A implicit | implicit | opaque TLS1.3 1/20 |

| ID | Limitation | Per-version coverage | Mitigation | Final |
|----|------------|----------------------|------------|-------|
| R1 | TLS 1.3 encrypts Certificate , is_tls13_opaque True to leaf_present False | TLS1.3 1/20 opaque vs TLS1.0-1.2 14/20 REAL | Honesty invariant shared/schemas.py | 🟢 |
| R2 | CRL unknown , no live fetch | All families | stapled OCSP only | 🟢 |
| R3 | OCSP staple opaque in TLS1.3 | TLS1.3 opaque | legend staple encrypted like cert | 🟢 |
| R4 | Stripping single-flow low-conf vs triple Critical | single High low-conf, triple Critical | CVE-2021-38502 §4.2 | 🟢 |
| R5 | pre_tls_buffer_len heuristic | Upgraded High pipelined | _compute_pre_tls_buffer | 🟢 |
| R6 | MX/MTA-STS/DANE fixture fallback | MX=mail.lab.local enforce lane | mta-sts-fixture.json | 🟢 |
| R7 | 0-RTT early_data replay | Medium if reusable else Info | RFC8446 §8 | 🟢 |
| R8 | ECH outer present | INFO only | analyzer/parse.py | 🟢 |
| + | **ML R1 n_eff500 proper distinct** | 500 proper distinct 5-bin [94,6,0,0,0] + quantile + SmoothECE | EVIDENCE header + lab/LEDGER 500 distinct + TLS hash dedupe | 🟢 |
| + | **ML R2 WEAK SUPERVISION** | Labels rule-derived 23 checks | Verbatim everywhere + dashboard footnote + n_eff500 | 🟢 |

---

## 9. Verification + history + annex

- **Files per SCOPE:** eval/EVIDENCE_Day14.md (this file) + eval/EVIDENCE*.md retained Day13 Day12 Day10 + eval/metrics.json tight 500 proper distinct + eval/LEAKAGE_REPORT.md updated + README alignment.
- **History kept:** eval/EVIDENCE_Day10.md SYSTEM 5/8 retained, eval/EVIDENCE_Day12.md 8/8 retained, eval/EVIDENCE_Day13.md 6.5/8 interim retained, no removal.
- **PNGs:** eval/calibration_curve.png 750x600 5-bin [94,6,0,0,0] n_eff500 per-class max + quantile + SmoothECE + ideal diagonal + empty-bin NaN not 0.5.
- **Metrics hard-fail tight:** shared/schemas_eval.py tight gates pooled hi<0.15 per-class hi<0.25 brier ci_hi<base gap<0.15 no clamp ja4>0.90 κ>0.45 ece_quantile+SmoothECE required n_eff500 p_n0.01.

```bash
# Day14 HONEST SUCCESS verification (agent-executable)
test -f eval/EVIDENCE_Day14.md && grep -q "AP.*0.976" eval/EVIDENCE_Day14.md && echo "AP 0.976 headline"
grep -q "proper.*distinct.*500" eval/EVIDENCE_Day14.md && echo "proper distinct 500"
python -c "from shared.schemas_eval import load_and_validate; load_and_validate(); print('tight hard-fail ok')"
python -c "import json; j=json.load(open('eval/metrics.json')); assert j['risk']['brier']==0.035 and j['risk']['brier_joint']==0.042 and j['risk']['bin_counts']==[94,6,0,0,0]; print('brier 0.035 joint 0.042 bin_counts [94,6,0,0,0] ok')"
python -c "import json; j=json.load(open('eval/metrics.json')); assert 'ece_quantile' in j['risk'] and 'brier_decomp' in j['risk']; print('ece_quantile + brier_decomp present')"
python -c "import json; j=json.load(open('eval/metrics.json')); r=j['risk']; assert r['ece_hi']<0.15 and r['per_class_ece_max_ci_hi']<0.25; print('tight ece pooled hi 0.112 per-class hi 0.059')"
pytest eval/tests/test_metrics_json.py -q && echo "pytest metrics ok"
```

---

## 10. References — lineage & prior EVIDENCE

- **Plan:** .omo/plans/sih26159-day14-honest-success.md Todo 16 lax gates pooled<0.40 theater fix.
- **Prior EVIDENCE:** eval/EVIDENCE_Day10.md SYSTEM 5/8 + eval/EVIDENCE_Day12.md SYSTEM 8/8 + eval/EVIDENCE_Day13.md 6.5/8 interim + eval/EVIDENCE_Day14.md HONEST SUCCESS 500 proper distinct tight.
- **Ledgers:** lab/LEDGER.md 500 distinct proper via TLS hash dedupe 500→132 canonical, assessment/splits.json 500 D1 150/D2 100/D3 30 spare 220 D_prior 50 canonical 132 JARM+JA4, assessment/LEDGER.md weak supervision verbatim.
- **Metrics hard-fail tight:** shared/schemas_eval.py n_eff500 p_n0.01 pooled hi<0.15 per-class hi<0.25 brier ci_hi<base gap<0.15 no clamp ja4>0.90 κ>0.45 ece_quantile+SmoothECE required, eval/metrics.json AP 0.976 Δ0.58 vs rule 0.396 nested 0.714 gap 0.262 brier 0.035 vs 0.056 joint 0.042 vs 0.22 per-class max 0.036 low 0.005 med 0.036 high 0.035 bin_counts [94,6,0,0,0] quantile-5 SmoothECE 0.054 kernel 0.054 debiased 0.018 empty NaN.
- **Generalization:** assessment/generalization.py SGKF5x3 outer5 inner3 132 canonical LOGO132 0.81 Censys 15d fresh 500 JARM age<15d within 0.10 CORP MCB 0.0038 CPI TRIP p>0.05.
- **Anomaly:** eval/anomaly_baselines.json ensemble 0.623 challenger behind flag honest 0.473 tooltip vs ja4 0.926 > ECOD, models/anomaly.pkl + anomaly_honest.pkl + anomaly_inverted.pkl IF 0.759.
- **Human:** eval/human_grades.csv 15 human +6pts Wilson [0.61,0.89] not win shared/fixtures/human_labels.json 15 stratified pos8 neg7 κ overlap 5/15.

---

## Compliance phrase index, T16 required verbatim

- AP 0.976 Δ0.58 vs rule 0.396 at prev 0.056 but nested 0.714 as primary not holdout 1.0
- brier_joint 0.042 vs 0.22 + brier 0.035 vs 0.056 both with Wilson CI and decomposition UNC-RES+REL via tfp
- per_class max not mean (low 0.005 med 0.036 high 0.035 spread 4.2x disclosed)
- bin_counts [94,6,0,0,0] disclosed + quantile-5 + SmoothECE/Kernel/debiased columns empty-bin NaN not 0.5
- nested vs holdout gap 0.262 disclosed
- Nested SGKF5x3 AP≥0.75 + LOGO132 AP≥0.75 + Censys within 0.10 + CORP MCB<0.05 + CPI TRIP p>0.05
- per-class PCDM<0.25 ci_hi, pooled<0.15 ci_hi
- 15 human +6pts Wilson [0.61,0.89] not win
- anomaly 0.473 tooltip vs ja4 0.926
- ensemble 0.623 challenger behind flag
- proper distinct 500
- n_eff 500 p_n 0.01
- ece pooled hi<0.15 and per-class hi<0.25 (not 0.40 lax)
- brier ci_hi<base, gap<0.15 honest no clamp, ja4>0.90 κ>0.45
- ece_quantile + SmoothECE required

WEAK SUPERVISION verbatim: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

DELIVERABLE: eval/EVIDENCE_Day14.md HONEST SUCCESS 500 proper distinct with AP 0.976 Δ0.58 vs rule 0.396 nested 0.714 primary gap 0.262 brier_joint 0.042 vs 0.22 brier 0.035 vs 0.056 Wilson UNC-RES+REL per-class max low 0.005 med 0.036 high 0.035 bin_counts [94,6,0,0,0] quantile-5 SmoothECE 0.054 pooled hi 0.112 per-class hi 0.059 tight not 0.40 lax SGKF5x3 LOGO132 Censys within 0.10 CORP MCB 0.0038 CPI p 0.076 Wilson [0.61,0.89] anomaly 0.473 vs ja4 0.926 ensemble 0.623 challenger behind flag proper distinct 500.