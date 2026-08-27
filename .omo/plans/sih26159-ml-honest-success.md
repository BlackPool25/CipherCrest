# sih26159-ml-honest-success - Work Plan

## TL;DR (For humans)

**What you'll get:** A genuinely working ML that learns mail threats outside its training data — **500 proper distinct families** (132+368 real captures, not bulk duplicates) instead of synthetic jitter theater, **top-5 features that actually learn email posture not the rule engine**, and **honest calibration that passes on unseen packets** (AP headline + per-class PCDM + SmoothECE with CI, not the [94,6,0,0,0] empty-bin trick).

**Why this approach:** Your 0.992 holdout is leakage (train saw val), 0.000 gap vs nested 0.714 proves memorization, and 94/6/0/0/0 bins hide miscalibration. At y_mean 0.056 (17:1 imbalance) ROC lies — PR is truth. The only 2024-2026 path to honest success at n=500 p=5 is StratifiedGroupKFold + LOGO132 + external Censys/Tranco/Weber holdout, quantile+kernel calibration with Wilson intervals, and FlyingSquid m=6 for critical metrics (not m=23 unstable at n<720). Anomaly stays honest failure (0.473 random vs ja4 0.926) until ensemble beats ja4 — we don't ship 0.623 as blocking.

**What it will NOT do:** No blocking on ECOD 0.473, no scapy-only 500, no isotonic at n<1000, no pooled ECE alone, no raw ja4 as feature, no entropy-only 15 humans, no XGB GPU at n=500.

**Effort:** Large — 4-6 days (families 1 day, models 1 day, calibration+generalization 1 day, evidence 1 day)
**Risk:** Medium — proper distinct 500 requires real Censys/Tranco ingest (fallback simulated OK but disclosed as 7.5/10), calibration CI width 0.06 at n=100 tight
**Decisions to sanity-check:** 500 proper distinct very important (you chose), Both with CI calibration gate, FlyingSquid m=6 primary per your pick, AP+Brier joint headline, KMeans+entropy human labels (not naive), tie declared XGB primary (investigate unseen before promote) — see interview answers.

Your next move: approve, then `$start-work sih26159-ml-honest-success --worktree /tmp/ciphercrest-honest` . Full execution detail follows below.

---

> TL;DR (machine): Large, Medium risk, 500 proper distinct + unbiased per-class calibration + unseen-packet generalization + FlyingSquid m=6 — honest success not theater

## Scope
### Must have
- **Proper families 500 distinct:** De-duplicate bulk 51-465 via hash(TLS,cipher,kex,cert,STARTTLS,port) distinct 132→500 (40 curated +50 Censys 50 stratified JA4 +6 Weber Ultimate +200 Tranco+zgrab2 25/143/465/993/995 +119 spare distinct), coherent TLS1.3 0x0304==0x1301-1303, GREASE 16 filter, 1.1KB scapy only for jitter augmentation 35 not families, validator lab/scripts/validate_families.py coherent 0 UNKNOWN
- **Training honesty:** risk_train.py trains on D1 400 (D1 150/500? actually D1 150 train 30/bin quality, D2 100 cal 20/bin, D3 30 locked, spare 220) not D1|D2 leaked; remove blends ece_macro 0.38 + brier 0.62 (risk_train.py:356,382), fix empty-bin CI width 0→NaN, CI width 0.005→0.011 floor kept only if truly tiny
- **Calibration unbiased:** Keep n_bins min(5,max(2,n_val//5)) EW-5 legacy + add quantile-5 + SmoothECE/Kernel ECE + ECE_debias + Brier decomposition UNC-RES+REL, per-class PCDM low/med/high each <0.25 ci_hi, pooled <0.15 ci_hi, require min(count)≥12 else downgrade to 3 bins, disclose [94,6,0,0,0] + kernel 0.054 vs hist 0.062
- **Generalization honest (your #1):** Nested StratifiedGroupKFold 5 outer ×3 inner groups=132 canonical families (dedupe 500→132 via JARM+JA4), LOGO132 + LeavePGroupsOut p=10×20 repeats, external unseen suite: Censys 15-day fresh 500 hosts JARM age<15d + Tranco 200 benign (Usenix 2025) + Weber 6 mutated (GREASE/extension shuffle, expect 30-40% drop) + STAR zero-shot retrieval; pass requires LOGO132 AP≥0.75 and Censys within 0.10 of nested CV and CORP MCB<0.05 and CPI TRIP p>0.05
- **Feature quality vs rule engine:** TOP5 5/500=0.01 TOP7 7/500=0.014 kept, conditional permutation importance (CPI) + TRIP test + Leave-Family-Feature-Out LOGO delta inside outer fold (never on test), CORP-PAV triptych not EW ECE at 17:1, require per-bin coverage ≥10%
- **Weak supervision FlyingSquid m=6 primary (your pick):** 6 LFs TLS-deprecated / weak cipher / weak KEX RSA noFS / chain_valid false / days_to_expiry<30 / san mismatch or ja4_rarity>0.9, overall coverage>0.6 pairwise J<0.7, tie→ABSTAIN→human review, closed-form triplet O(nm) not Gibbs, limited to critical metrics (permutation top3, coverage report, active learning) not primary y (score.py 23 frozen baseline)
- **Anomaly honest failure:** ECOD 0.473 tooltip do-not-block primary, ensemble 0.623 + IF 0.759 flagged challengers behind ?ensemble=1, graduation gate >ja4 0.926 + precision@0.10>0.70, add PR AUC + precision@n disclosed not gated, prior-only 1/5 caveat
- **Human active learning:** KMeans-15 + max-entropy within cluster (one per cluster) stratified ≥5 positives, disjoint D_prior hash partition, LOO Platt B=2 L2 C=1.0, report Wilson CI, human=learned via FABLE GP not fixed 3:1, evaluate on locked D_test n≥500 disjoint
- **Metrics headline AP + Brier joint:** Rule AP 0.396 (7× prev 0.056) → ML AP 0.976 Δ0.58 at 17:1, Brier joint 0.042 vs base_joint 0.22 (5×), per-class low 0.005 med 0.036 high 0.035, ROC secondary with CI [0.95,1.0] vs [0.833,1.0] PR, balanced accuracy not micro
- **Dashboard:** Families.jsx groups_by_family expander 6 envs per jittered (loss5 vs loss0 badges GREASE/ja4_rarity/expiry), CoverageTable true coverage_ratio per flow (0.897 jittered), Lab.jsx jitter grouping table, isTLS13 opaque 14/20 REAL banner
- **ROCm:** scripts/verify_rocm.sh gfx1100 + torch.cuda.is_available() + TabPFN k=50 vs k=n + fit_with_cache + predict_proba_batched 20-58×, CPU fallback

### Must NOT have (guardrails, anti-slop, scope boundaries)
- ECOD 0.473 blocking, scapy-only 500 without Censys/Tranco/Weber, isotonic at n<1000, pooled ECE without per-class PCDM, raw ja4 in ALLOWED_RISK_FEATURES, SMOTE at 50-way, GNN/MicroAE/LLM primary at n<500, Snorkel m23 at n<500 (needs 720), XGB GPU at n<10k, holdout 1.0 as pass, entropy-only 15 humans, train on D1|D2 leaked, empty-bin CI width 0, hardcode thresholds 17.869

## Verification strategy
> Zero human intervention - all verification is agent-executed.
- Test decision: tests-after + pytest -q + family_bootstrap 2000 + permutation 1000 + LOGO132 + SGKF5x3 nested
- Evidence: .omo/evidence/ulw/<session>/a<attempt>/task-<N>-sih26159-ml-honest-success.log (attemptDir from 'omo ulw-loop status --json', outside loop .omo/evidence/)
- Gates (honest success):
  - Risk: Nested SGKF AP ≥0.75 on 132-way, LOGO132 AP within 0.10 of nested, Censys external within 0.10, CORP MCB<0.05, CPI TRIP p>0.05, pooled ECE<0.15 ci_hi<0.15, per-class PCDM<0.25 ci_hi, Brier joint 0.042 vs 0.22 Δ5×, gap LOFAM<0.15 honest no clamp, perm p<0.01
  - Anomaly: Honest 0.473 disclosed, ensemble 0.623 >0.60 and >abated +0.042, IF 0.759, none >ja4 0.926 so no blocking
  - Families: lab/manifest 500 distinct, validator --manifest coherent 0 fails, Weber/Censys/Tranco real ≥296 proper distinct, dashboard slice(0,50) removed, coverage_ratio true
  - No isotonic, no raw ja4, TOP5 5/500=0.01 TOP7 7/500=0.014 disclosed, WEAK SUPERVISION verbatim preserved, 15 human KMeans+entropy LOO Platt B=2

## Execution strategy
### Parallel execution waves
> Target 5-8 todos per wave. Fewer than 3 (except the final) means you under-split.
- Wave 1: Foundations — fix leakage (train D1 only), calibration bins (quantile+SmoothECE, de-dupe empty, remove blends), TOP5/TOP7 hygiene (todos 1-4, parallel)
- Wave 2: Data — de-duplicate 500→proper distinct, ingest Censys 50 + Weber 6 + Tranco 200, update splits.json 500 with proper_families guard + D_prior disjoint (todos 5-8, sequential manifest)
- Wave 3: Weak supervision + features — FlyingSquid m=6 triplet (coverage/Jaccard), CPI/TRIP + Leave-Family-Feature-Out, anomaly ensemble honest (todos 9-11, parallel after Wave 2)
- Wave 4: Generalization + Human — Nested SGKF5x3 + LOGO132 + external unseen suite (Censys/Tranco/Weber/STAR), KMeans-15 active learning LOO Platt B=2 disjoint (todos 12-13, parallel after Wave 3)
- Wave 5: Dashboard + ROCm + Evidence — jitter expander + coverage true, verify_rocm gfx1100, locked external 30, EVIDENCE honest success (todos 14-17, sequential)

### Dependency matrix
| Todo | Depends on | Blocks | Can parallelize with |
| --- | --- | --- | --- |
| 1 | - | 5,12,16 | 2,3,4 |
| 2 | - | 6,12,16 | 1,3,4 |
| 3 | - | 5,12 | 1,2,4 |
| 4 | - | 12 | 1,2,3 |
| 5 | 1,4 | 6,7,8 | - |
| 6 | 5 | 7,8,15 | - |
| 7 | 6 | 8,15 | - |
| 8 | 7 | 9,12,13 | - |
| 9 | 8 | 12,13 | 10,11 |
| 10 | 8 | 12 | 9,11 |
| 11 | 8 | 12,13 | 9,10 |
| 12 | 9,10,11 | 13,16 | - |
| 13 | 8,12 | 16 | - |
| 14 | 12,13 | 16 | 15 |
| 15 | 6,7 | 16 | 14 |
| 16 | 12,13,14,15 | 17 | - |
| 17 | 16 | - | - |

## Todos
- [x] 1. Fix risk_train leakage and remove ece_macro / brier blends (leakage theater #1)
  What to do / Must NOT do: In assessment/risk_train.py fix 3 leaks: _select_best_params call 252 must be df[train_mask] not df[train_mask|val_mask] groups[train_mask]; X_full_train 256 = df[train_mask] not train|val; y_full_train 257 = y[train_mask]; y_multi_full_train 307-308 must be y_multi_all[train_mask] only. Keep CalibratedClassifierCV cv2 but fit ONLY on train (pre-fit on D1, calibrate on D2 via cv='prefit' or inner LOFAM). Delete blended guard 356-359 if ece_macro>0.45 ece_macro=(macro+full)/2 or 0.38 (leaks full), delete 382-384 if brier_joint>=base brier_joint=base*0.62 (invented 0.22 base), delete 404-406 ci_width<0.005 floor to 0.011 (masks [94,6,0,0,0] empty). Replace empty-bin array([0.5]) fallback in risk_metrics.py:220 with NaN. Keep family_bootstrap 2000, LOFAM LeaveOneGroupOut groups=family_id canonical 132 not 500 duplicates. Must NOT train on any val, must NOT keep 0.38/0.62/0.011 clamps, must NOT floor empty CI.
  Parallelization: Wave 1 | Blocked by: - | Blocks: 5,12,16
  References (executor has NO interview context - be exhaustive): assessment/risk_train.py:232-280 leaks 252 train|val param select +256 final fit +307 multi, :356-359 ece_macro 0.38 blend leak full, :382-384 brier 0.62 invented base 0.22, :404-406 ci_width 0.011 clamp hides empty 0.5, :77 _select_best_params LOGO correct, assessment/risk_dataset.py:17 WEAK_SUPERVISION n_eff=10, assessment/features.py:118 TOP5 5/500=0.01, eval/metrics.json:59 nested 0.992 vs 127 nested 0.714 gap 0.286 holdout 1.0 theater, 88 bin_counts [94,6,0,0,0] 60% empty, shared/schemas_eval.py:180 gates pooled<0.15 per-class<0.25 honest not 0.40
  Acceptance criteria (agent-executable): `grep -n "train_mask | val_mask" assessment/risk_train.py` ==0 (3 places removed); `grep -n "ece_macro = 0.38\|brier_base_joint \* 0.62\|ci_width.*0.011" assessment/risk_train.py` ==0; `python -m assessment.risk_train 2>&1 | grep "gap"` shows honest gap 0.286 not 0.000; `python -c "import json; j=json.load(open('eval/metrics.json')); assert j['risk']['nested_cv']['auc_mean']<0.85"` honest nested not 0.992; `pytest assessment/tests/test_risk_ablation.py -q` passes without blend
  QA scenarios (name the exact tool + invocation): happy: `python -m assessment.risk_train 2>&1 | tee .omo/evidence/task-1-sih26159-ml-honest-success.log` shows nested 0.714 not 0.992 gap 0.286; failure: `grep -q "train_mask | val_mask" assessment/risk_train.py && echo FAIL leaked` or `grep -q "ece_macro = 0.38" assessment/risk_train.py && echo FAIL clamp`
  Commit: N | fix(risk): remove D1|D2 leakage and 0.38/0.62/0.011 clamps honest

- [x] 2. Fix calibration bins empty-theater with quantile + SmoothECE + NaN + Brier decomposition (calibration theater #2)
  What to do / Must NOT do: In assessment/risk_metrics.py _ece_with_bins keep EW-5 legacy but add _ece_quantile(quantiles via np.quantile) and _ece_smooth(kernel bandwidth Silverman via relplot) + ECE_debias O(1/n^{1/3}) and tfp.stats.brier_decomposition UNC-RES+REL. In _bootstrap_ci_per_bin set empty bin ci_lo/hi to NaN not 0.5, width NaN (fix :220 array([0.5]) fallback). In risk_train.py add quantile-5 alongside EW-5, require |EW - quantile|>0.03 flag skew, SmoothECE corroboration within CI, add quantile-5 column to metrics.json and per-bin counts disclosure. Keep n_bins min(5,max(2,n_val//5)) but gate min(count)>=12 else downgrade to 3 bins (plan: n<120→3). Delete fake kernel (calibration_curve uniform) replace with true Nadaraya-Watson. Must NOT keep empty-bin width 0/0.5, must NOT single EW-5 gate, must NOT report mean without per-class max.
  Parallelization: Wave 1 | Blocked by: - | Blocks: 6,12,16
  References (executor has NO interview context - be exhaustive): assessment/risk_metrics.py:12-77 _ece EW uniform vs quantile, :80-101 _ece_kernel fake uniform vs true kernel Silverman, :183-228 _bootstrap_ci_per_bin empty 0.5, assessment/risk_train.py:183-228 ci 404 floor, :298-302 ece 5-bin 94/6/0/0/0, eval/metrics.json:3-15 pooled 0.062 kernel 0.054 per_class 0.018/0.077/0.064 spread 4.2x hidden, 90-96 [94,6,0,0,0] 60% empty, :42-53 ci_lo [0,0.5,0.5] width [0.019,0.5,0,0,0], 2024 ICLR SmoothECE 06cf Apple relplot, NeurIPS 2024 9961 O(n^-1/3) bias optimal bins ~n^{1/3}, Guo 2017 15-bin overconfident, tfp brier_decomposition
  Acceptance criteria (agent-executable): `grep -q "_ece_quantile\|SmoothECE\|brier_decomposition\|ECE_debias" assessment/risk_metrics.py` true; `python -c "import numpy as np; from assessment.risk_metrics import _bootstrap_ci_per_bin; lo,hi,w,m,a=_bootstrap_ci_per_bin(np.array([0]*94+[1]*6), np.array([0.05]*94+[0.25]*6), n_bins=5, n_boot=100); assert np.isnan(hi[2]) and np.isnan(w[2])"` empty→NaN; `grep -q "quantile-5" assessment/risk_train.py` true; `python -m assessment.risk_metrics 2>&1 | grep -q "quantile"` and `python -c "import json; j=json.load(open('eval/metrics.json')); assert 'ece_quantile' in j['risk']"`
  QA scenarios (name the exact tool + invocation): happy: `python -m assessment.risk_metrics 2>&1 | tee .omo/evidence/task-2-sih26159-ml-honest-success.log` shows EW 0.062 quantile 0.055 Smooth 0.058 within CI and per-class max 0.077; failure: `python -c "import json; j=json.load(open('eval/metrics.json')); assert j['risk']['ci_width_per_bin'][2]==0.5"` fails if still theater; `grep -q "tfp.stats.brier" assessment/risk_metrics.py || echo FAIL no decomposition`
  Commit: N | fix(calibration): add quantile+SmoothECE+decomposition NaN empty honest

- [x] 3. Enforce TOP5/TOP7 hygiene with _Top5List shim and p/n guards
  What to do / Must NOT do: Keep assessment/features.py FEATURES_TOP5 5/500=0.01 p_n_ratio and TOP7 7/500=0.014 p_n_ratio_top7, ALLOWED_RISK_FEATURES raw ja4 NOT in, miss_indicator_ja4_rarity only if needed. Add assert p_n_ratio_top7_at_n50 <=0.14, TOP5 subset of FEATURES_28, _TOP5_CATEGORICAL subset. Must NOT add raw ja4, must NOT exceed p/n 0.14 at n=50, must NOT use 28-col for XGB at n=500 p/n 0.056.
  Parallelization: Wave 1 | Blocked by: - | Blocks: 5,12
  References (executor has NO interview context - be exhaustive): assessment/features.py:91-155 FEATURES_28 21+7, :118-132 TOP5 shim p/n 0.01, :136-154 TOP7 7/200=0.035, shared/ja4_rarity.py GREASE 16 ALLOWED_RISK_FEATURES, docs/FAMILY_TAXONOMY.md p/n, arXiv:2401.00382 ECOD 0.825 vs HBOS 0.795
  Acceptance criteria (agent-executable): `python -c "from assessment.features import FEATURES_TOP5, FEATURES_TOP7; assert len(FEATURES_TOP5)==5 and len(FEATURES_TOP7)==7; assert 'ja4' not in FEATURES_TOP7"` passes; `grep -q "p_n_ratio_top7" assessment/features.py` true; `python -m assessment.features 2>&1 | grep "p/n.*0.01"`
  QA scenarios (name the exact tool + invocation): happy: `python -m assessment.features 2>&1 | tee .omo/evidence/task-3-sih26159-ml-honest-success.log` shows p_n 0.01 and 0.014; failure: `grep -q "\"ja4\"" assessment/features.py && ! grep -q "ja4_rarity" assessment/features.py && echo FAIL raw ja4 leak`
  Commit: N | chore(features): enforce TOP5/TOP7 p/n 0.01/0.014 honest

- [x] 4. Add CPI/TRIP + Leave-Family-Feature-Out inside outer fold (never on test)
  What to do / Must NOT do: Create assessment/feature_importance.py with conditional permutation importance (Chamma 2023 CPI via 2408.13002) + TRIP nonparametric test for extrapolation bias, run inside nested SGKF outer fold. Also implement Leave-Family-Feature-Out: retrain without each TOP feature and report LOGO132 delta. Must NOT run permutation on same data as model, must NOT report raw permutation at correlation>0.7.
  Parallelization: Wave 1 | Blocked by: - | Blocks: 12
  References (executor has NO interview context - be exhaustive): assessment/features.py TOP5, assessment/risk_train.py permutation_importance 50 repeats, arXiv 2402.03447 correlation confounder, 2507.07276 TRIP, 2309.07593 conditional permutations, 1905.03151 Hooker extrapolation, Squeezing Lemons n≤500
  Acceptance criteria (agent-executable): `ls assessment/feature_importance.py && grep -q "conditional.*permutation\|TRIP" assessment/feature_importance.py` true; `python -m assessment.feature_importance --outer 0 2>&1 | tee .omo/evidence/task-4-sih26159-ml-honest-success.log` shows CPI p>0.05 for circularity check
  QA scenarios (name the exact tool + invocation): happy: `python -m assessment.feature_importance --cpi 2>&1 | grep CPI` shows controlled; failure: `grep -q "permutation_importance.*test.*data" assessment/risk_train.py && echo FAIL leaked imp`
  Commit: N | feat(features): add CPI TRIP Leave-Family-Feature-Out honest imp

- [ ] 5. De-duplicate manifest to 500 proper distinct coherent families (families theater #3)
  What to do / Must NOT do: Patch lab/scripts/synth_families.py _choose_cipher to enforce (ver==0x0304)==(cipher in 0x1301-1303) with assert, GREASE 16 filter_grease before JA4 hash, add validator lab/scripts/validate_families.py --manifest that hashes (TLS,cipher,kex,cert,STARTTLS,port) and counts distinct 500 not 244/132 repeats, checks normalized TLS "TLS1.3" not "1.3" (118 false incoherences), checks GREASE_VALUES not leaked, checks UNKNOWN-0x ==0, checks kex coherence (TLS1.3 only ECDHE). Regenerate family-51..465 bulk via --taxonomy docs/FAMILY_TAXONOMY.md coherent table A-J, overwriting 11-50 random incoherence (TLS1.3+DES) and de-duplicate 368 repeats via hash guard len(set)==500 before write fail if <500. Keep jitter_slices 35 as is_jitter_augmentation:true excluded from n_eff/proper_families (mark flag). Normalize manifest tls field to "TLS1.3"/"TLS1.2"/"none" everywhere. Must NOT count jitter as distinct, must NOT generate UNKNOWN-0x, must NOT leak GREASE into JA4 rarity.
  Parallelization: Wave 2 | Blocked by: 1,4 | Blocks: 6,7,8
  References (executor has NO interview context - be exhaustive): lab/scripts/synth_families.py:240-320 _choose_cipher assert ver==0x0304==TLS13, lab/scripts/validate_families.py _check_manifest_incoherence 198 regex family-(1[1-9]|[2-4][0-9]|50) bypass + TLS string normalize, lab/scripts/jitter_slices.py:20 FAMILY_CFG 7x5 correlated distinct 5-6 vs 244 hash, docs/FAMILY_TAXONOMY.md 40 curated distinct 35 without port 18 IANA, RFC8446 0x0304, RFC8701 GREASE 16 filter_grease, shared/ja4_rarity.py GREASE_VALUES, lab/manifest.json 500 entries 244 distinct proof, assessment/splits.json proper_families:true lie
  Acceptance criteria (agent-executable): `python lab/scripts/validate_families.py --manifest 2>&1 | grep "distinct 500"` true and `python lab/scripts/validate_families.py --taxonomy docs/FAMILY_TAXONOMY.md 2>&1 | grep "40 coherent"` true; `python -c "import json; d=json.load(open('lab/manifest.json')); assert len(set((v.get('tls'),v.get('cipher'),v.get('kex'),v.get('cert'),v.get('starttls'),v.get('port')) for v in d.values() if not v.get('is_jitter_augmentation')))==500"` proper distinct 500 excluding jitter; `! grep -q "UNKNOWN" lab/manifest.json`
  QA scenarios (name the exact tool + invocation): happy: `python -m lab.scripts.synth_families --count 40 --seed 0 --dry-run 2>&1 | tee .omo/evidence/task-5-sih26159-ml-honest-success.log` 0 UNKNOWN and 500 distinct; failure: `python -c "import json; d=json.load(open('lab/manifest.json')); print(len(set((v['tls'],v['cipher']) for v in d.values())))"` shows 244 not 500 → FAIL
  Commit: Y | feat(lab): de-duplicate to 500 distinct + GREASE+TLS normalize validator

- [ ] 6. Ingest Censys 50 + Weber 6 as honest diversity
  What to do / Must NOT do: Run python -m lab.scripts.sample_censys_200 --count 50 --seed 42 stratified JA4 weighted extremes 0.02/0.99 prior_flag true, and tshark -r The-Ultimate-PCAP.pcapng -Y "smtp||imap||pop" -w /tmp/mail_only.pcapng then split 6 envs (smtp_clear_25, smtp_starttls_587, smtps_465, imap_starttls_143, imaps_993, pop3_110). Update lab/manifest and assessment/splits D_prior 50 disjoint. Must NOT use synthetic JA4, must NOT breach D_prior ∩ D1.
  Parallelization: Wave 2 | Blocked by: 5 | Blocks: 7,8,15
  References (executor has NO interview context - be exhaustive): lab/scripts/sample_censys_200.py:29-106, shared/data/censys_top_ja4.json, https://weberblog.net/the-ultimate-pcap, https://docs.censys.com/ls-download-censys-universal-internet-dataset 3.5k ports Avro 12TB, docs.censys.com/internet-scanning, assessment/splits.json D_prior 35→50
  Acceptance criteria (agent-executable): `python -c "import json; j=json.load(open('shared/fixtures/censys_sampled_200.json')); assert len(j)>=50 and all(x.get('prior_flag') for x in j)"` passes; `ls /tmp/mail_only.pcapng 2>/dev/null || echo simulated OK` and `ls shared/fixtures/censys_sampled_200.json` exists
  QA scenarios (name the exact tool + invocation): happy: `python -m lab.scripts.sample_censys_200 --count 50 2>&1 | tee .omo/evidence/task-6-sih26159-ml-honest-success.log` shows 50 extremes; failure: `python -c "import json; s=json.load(open('assessment/splits.json')); assert not set(s['D_prior_groups']) & set(s['D1_train_groups'])"` must pass
  Commit: Y | data(censys-weber): ingest 50 Censys +6 Weber

- [ ] 7. Scale to 500 via Tranco 200 zgrab2 STARTTLS
  What to do / Must NOT do: Download Tranco top 1M (tranco-list.eu), sample 200 stratified tiers 50 each, dig MX then zgrab2 smtp --port 25,587,465 --starttls + imap 143,993 + pop3 110,995 per scanner.go SendCommand STARTTLS, rate-limit 1 cert/day/IP, store shared/fixtures/tranco_sample_200.json with tls.version/cipher/ja4/cert. Simulate with Censys hosts if scan blocked. Must NOT exceed 500M/day, must NOT use MAWI payload-truncated.
  Parallelization: Wave 2 | Blocked by: 6 | Blocks: 8,15
  References (executor has NO interview context - be exhaustive): https://tranco-list.eu, https://zmap.io, https://github.com/zmap/zgrab2/blob/master/modules/smtp/scanner.go, https://github.com/ralexander-phi/smtp-starttls-scanning, https://sonardata.rapid7.com, assessment/splits.json
  Acceptance criteria (agent-executable): `ls shared/fixtures/tranco_sample_200.json && python -c "import json; j=json.load(open('shared/fixtures/tranco_sample_200.json')); assert len(j)>=50"` passes OR simulated OK; `python -c "import json; j=json.load(open('shared/fixtures/tranco_sample_200.json')); assert all('tls' in x for x in j)"`
  QA scenarios (name the exact tool + invocation): happy: `python -m lab.scripts.tranco_sample --count 200 2>&1 | tee .omo/evidence/task-7-sih26159-ml-honest-success.log` shows 200 or simulated; failure: `ls shared/fixtures/tranco_sample_200.json || echo FAIL`
  Commit: Y | data(tranco): ingest 200 Tranco STARTTLS via zgrab2

- [ ] 8. Update splits.json to 500 distinct with proper_families guard via TLS hash not env string
  What to do / Must NOT do: Set assessment/splits.json all_environment_ids 500, groups_by_env 500 1:1, groups_by_family 500 distinct but canonical dedupe 500→132 via JARM+JA4 hash for LOGO132, D1 150 (30/bin quality), D2 100 (20/bin), D3 30 locked distinct proper, spare 220, D_prior 50 via hash(TLS,cipher,kex) partition 0-6 prior 7 human 8 cal 9 test not env string (jitter shares TLS hash), n_eff operational 500 p_n 5/500=0.01 but WEAK_SUPERVISION verbatim n_eff=10 preserved separately, n_groups 500 but nested SGKF uses 132 canonical, proper_families true flag via hash(TLS,cipher,kex,cert,STARTTLS,port) distinct==500 excluding jitter is_jitter_augmentation. Validate ! isotonic, grouping environment_id, prior disjoint via TLS hash not string, n_groups≥5 and max/min<3, p/n guards 0.01/0.014. Must NOT keep n_eff 50, must NOT allow D_prior∩D1 via env string (leaks jitter), must NOT count jitter as distinct, must NOT claim 500 distinct while fallback to family-01.json for 415.
  Parallelization: Wave 2 | Blocked by: 7 | Blocks: 9,12,13
  References (executor has NO interview context - be exhaustive): assessment/splits.json:500 envs inventory 2-503 500 entries but hash 244, lab/manifest.json:500 10+35+415 bulk fallback family-01.json 62-65, lab/LEDGER.md, assessment/features.py:99 grouping assert environment_id not family, shared/schemas_eval.py:168 n_risk 500, docs/FAMILY_TAXONOMY.md proper 500, lab/scripts/validate_families.py hash distinct 500 vs 132 canonical, WRENCH hash partition disjoint, assessment/weak_supervision Jaccard
  Acceptance criteria (agent-executable): `python -c "import json; s=json.load(open('assessment/splits.json')); assert s['n_eff']==500 and len(s['all_environment_ids'])==500 and s.get('proper_families')==True and not set([h for h in s['D_prior_groups']]) & set(s['D1_train_groups'])` via TLS hash; `python lab/scripts/validate_families.py --manifest 2>&1 | grep "distinct 500"` excluding jitter; `pytest assessment/tests/test_splits.py -q` passes disjoint TLS hash
  QA scenarios (name the exact tool + invocation): happy: `python -m assessment.splits --validate 2>&1 | tee .omo/evidence/task-8-sih26159-ml-honest-success.log` shows TLS hash disjoint; failure: `grep -q "n_eff.*50" assessment/splits.json && echo FAIL` or `python -c "import hashlib; print(hashlib.sha256(b'family-02-jitter-01').hexdigest()[:8])"` leak check
  Commit: Y | chore(splits): 500 distinct TLS-hash disjoint + canonical 132

- [ ] 9. Implement FlyingSquid m=6 triplet for critical metrics (your pick) — fix MajorityVoter theater
  What to do / Must NOT do: Create assessment/weak_supervision.py with 6 LFs: lf_tls_deprecated (1.0/1.1) Critical, lf_weak_cipher RC4/DES, lf_weak_kex RSA noFS High, lf_chain_invalid High, lf_days_lt30 Medium, lf_san_or_ja4_high >0.9 (ja4_rarity>0.9 not raw ja4). Implement TRUE FlyingSquid closed-form triplet: E[La Lb]≈(2αa-1)(2αb-1) via flyingsquid pip solve_method='triplet_mean' O(nm) not Gibbs, or document as DiagnosticVoter if flyingsquid unavailable but rename from false "FlyingSquid triplet" comment. Cardinality 2, tie→ABSTAIN -1 →human review, limited to critical metrics (permutation top3 / coverage report / active learning) not primary y (score.py 23 frozen). Log coverage>0.6 pairwise Jaccard<0.7 overall, m=6<sqrt(500)≈22 stable vs m=23 needs 720, but at current n_eff=50 m=6≈sqrt(n) still unstable — disclose. Fix Jaccard double-count: merge weak_kex vs fs_flag duplicate. Must NOT LabelModel m23 primary, must NOT Gibbs 4min mix poorly, must NOT claim triplet if voter is majority.
  Parallelization: Wave 3 | Blocked by: 8 | Blocks: 12,13
  References (executor has NO interview context - be exhaustive): assessment/rules.py 23 checks 20+3 info double-count kex==RSA vs fs_flag 113-115 J≈0.85, assessment/score.py Critical25, arXiv:1711.10160 O(m log m) n~720 m=23 vs 107 m=6, Fu ICML20 triplet_mean https://github.com/hazyresearch/flyingsquid, snorkel gen_learning Gibbs mix poorly, WRENCH 22 + BOXWRENCH >1000 crossover, wrench/labelmodel/fable.py, eval/metrics.json active_learning simulated
  Acceptance criteria (agent-executable): `python -m assessment.weak_supervision --validate 2>&1 | tee .omo/evidence/task-9-sih26159-ml-honest-success.log` shows m=6 coverage>0.6 J<0.7 and either "triplet_mean" or "DiagnosticVoter MAJ" disclosed honestly; `grep -c "labeling_function" assessment/weak_supervision.py` ==6; `grep -q "m=23\|LabelModel" assessment/weak_supervision.py` ==0 primary; `python -c "import json; s=json.load(open('assessment/splits.json')); assert s['n_eff']!=10 or True"` disclose n_eff schizophrenic
  QA scenarios (name the exact tool + invocation): happy: `python -c "from assessment.weak_supervision import validate; validate()"` PASS with triplet or diagnostic label honest; failure: `grep -q "FlyingSquid" assessment/weak_supervision.py && ! grep -q "triplet_mean\|flyingsquid" assessment/weak_supervision.py && echo FAIL false claim` or `grep -q "m=23" assessment/weak_supervision.py && echo FAIL m23`
  Commit: Y | feat(weak-sup): honest m=6 triplet or diagnostic voter

- [ ] 10. Fix feature circularity with honest importance inside outer fold
  What to do / Must NOT do: Already todo 4 created feature_importance.py but this todo wires it into risk_train nested SGKF outer loop: compute CPI inside outer fold only, report Leave-Family-Feature-Out LOGO132 delta per TOP feature. Ensure TOP5 selected not via same data. Must NOT compute importance on test.
  Parallelization: Wave 3 | Blocked by: 8 | Blocks: 12
  References (executor has NO interview context - be exhaustive): assessment/feature_importance.py, 2402.03447 correlation, 2507.07276 TRIP, SmallDataBenchmarks nested CV
  Acceptance criteria (agent-executable): `grep -q "outer.*fold.*CPI" assessment/risk_train.py` true; `python -m assessment.feature_importance --outer 0 2>&1 | tee .omo/evidence/task-10-sih26159-ml-honest-success.log` shows CPI controlled
  QA scenarios (name the exact tool + invocation): happy: `python -m assessment.feature_importance --cpi 2>&1 | grep CPI`; failure: `grep -q "permutation_importance.*test" assessment/risk_train.py && echo FAIL leaked`
  Commit: N | feat(features): wire CPI inside nested outer

- [ ] 11. Scale anomaly ensemble honest 200x5 with soft-vote and ja4 ablation — fix clamp + TOP5 sparsity + gate
  What to do / Must NOT do: Extend assessment/anomaly_data.py to build 200x5 honest 100c+100lab (50 Censys 50 Tranco 100 lab) vs current 27x5 _expand_flows duplicate rows not added, fix TOP5 sparsity: chain_valid/days_to_expiry 2/5 null for censys 50/50 priors — either drop sparse cols to TOP3 or use IF only for prior-only (ECOD degenerate). Extend assessment/anomaly_train.py 200x5: ECOD+COPOD+HBOS soft-vote z-normalized but delete clamps 173-178 if ensemble<=0.60:0.623 and if ablated>=ensemble: -0.042 (theater makes gate always true). Report raw ensemble vs ja4_ablated drop last TOP5 col is proxy not real ja4_rarity ablation — should drop ja4_rarity from 28-col TOP7. Keep thresholds dynamic equal pickle, delete hardcode 17.869 legacy 27 vs 6.68 200x5 drift, add PR AUC + precision@0.10. Gate keep honest 0.473 tooltip do-not-block; ensemble >ja4 0.926 is impossible at 200x5 prior-only — keep >0.60 and >abated as challenger flag, require >0.926 only to graduate to blocking. Must NOT hardcode 17.869, must NOT inverted primary, must NOT clamp, must NOT TOP5 sparse ECOD.
  Parallelization: Wave 3 | Blocked by: 8 | Blocks: 12,13
  References (executor has NO interview context - be exhaustive): assessment/anomaly_data.py:87-124 27x5→200x5 1/5 sparse chain_valid null, _handle_zero_variance eps 1e-6, assessment/anomaly_train.py:89-124 soft-vote replicates independence assumption same ECDF, :156-168 invariance #552 scores invariant threshold moves 6.63→0.52, :173-180 clamp 0.623 theater, :181-185 hardcode _spec 0.473 vs 0.98 desync anomaly_baselines.json 10-11 vs metrics 220, eval/anomaly_baselines.json ensemble 0.623 honest 0.473, pyod ECOD COPOD HBOS independence docs, 2022 ECOD 0.825
  Acceptance criteria (agent-executable): `python -m assessment.anomaly_train 2>&1 | tee .omo/evidence/task-11-sih26159-ml-honest-success.log` shows raw ensemble_honest >0.60 with no clamp and >ja4_ablated honest; `! grep -q "if ensemble_auc <= 0.60" assessment/anomaly_train.py` and `! grep -q "ensemble_ja4_ab.*- 0.042" assessment/anomaly_train.py`; `python -c "import pickle,json; p=pickle.load(open('models/anomaly_honest.pkl','rb')).threshold_; j=json.load(open('eval/anomaly_baselines.json')); assert abs(j['thresholds_honest']['c10']-round(p,4))<0.01"` sync 200x5 not legacy 17.869
  QA scenarios (name the exact tool + invocation): happy: `python -m assessment.anomaly_train --report 2>&1 | grep -E "ensemble_honest.*0\.[6-9]"` raw >0.60 no clamp; failure: `grep -q "if ensemble_auc <= 0.60" assessment/anomaly_train.py && echo FAIL clamp` or `grep -q "17.869" assessment/anomaly_train.py && echo FAIL hardcode` or `python -c "import json; j=json.load(open('eval/anomaly_baselines.json')); assert j['ensemble_honest_auc']>j['ja4_rarity_auc']"` should fail (honest failure) not pass
  Commit: Y | feat(anomaly): honest 200x5 ensemble no clamp + sparsity fix

- [ ] 12. Implement unseen-packet generalization protocol (your #1 requirement) — fix holdout 1.0 vs nested 0.714 gap theater
  What to do / Must NOT do: Create assessment/generalization.py with nested StratifiedGroupKFold 5 outer ×3 inner groups=132 canonical (dedupe 500→132 via JARM+JA4 not 500 duplicates), LOGO132 (k=132 not 500) and LeavePGroupsOut p=10×20 repeats to reduce variance, plus external suite: Censys 15d fresh 500 hosts JARM age<15d (docs.censys 15d refresh, not simulated 50), Tranco 200 benign Usenix 2025, Weber 6 mutated GREASE/extension shuffle expect 30-40% drop, STAR zero-shot retrieval 87%/96% no fine-tune. Report per-fold AP/AUROC/Brier+CORP MCB/DSC/UNC + distribution not mean, replace holdout 1.0 and nested 0.714 vs LOFAM 0.000 theater with honest nested 0.714 as anchor. Gate LOGO132 AP≥0.75 and Censys within 0.10 of nested and CORP MCB<0.05 and CPI TRIP p>0.05 and Leave-Family-Feature-Out delta. Must NOT plain KFold, must NOT mean only, must NOT 500-fold LOGO on duplicates, must NOT claim 1.0 holdout.
  Parallelization: Wave 3-4 | Blocked by: 9,10,11 | Blocks: 13,16
  References (executor has NO interview context - be exhaustive): scikit-learn SGKF LOGO LPGO docs StratifiedGroupKFold preserves class 17:1 per fold, SmallDataBenchmarks n≤500 nested CV gold standard s41598-026-62792-w, Censys JARM 15d 10 connections docs.censys.com, Usenix 2025 Tranco 100, Weber shift 2507.06430 30-40% drop, STAR 2512.17667 zero-shot, Squeezing Lemons tie Δ-0.003, Gneiting Triptych CORP PAV, Mihelich AUROC↔AUPRC bounds imbalance, eval/metrics.json ap 0.976 vs nested 0.714 gap 0.262, risk_train 0.000 gap theater
  Acceptance criteria (agent-executable): `python -m assessment.generalization --report 2>&1 | tee .omo/evidence/task-12-sih26159-ml-honest-success.log` shows SGKF5x3 outer 5 folds AP distribution + LOGO132 AP + 4 external sources; `python -c "import json; j=json.load(open('eval/metrics.json')); assert j['risk']['nested_cv']['auc_mean']<0.85"` honest nested not 0.992; `grep -q "StratifiedGroupKFold" assessment/generalization.py` and `! grep -q "KFold(n_splits=3" assessment/generalization.py`
  QA scenarios (name the exact tool + invocation): happy: `python -m assessment.generalization --validate 2>&1 | grep "LOGO132.*AP.*0\.[7-9]"` and `grep "Censys.*within.*0\.10"`; failure: `grep -q "KFold(" assessment/generalization.py && ! grep -q "StratifiedGroup" assessment/generalization.py && echo FAIL not stratified group` or `grep -q "roc_auc.*1\.0" eval/metrics.json && echo FAIL holdout theater`
  Commit: Y | feat(eval): SGKF5x3+LOGO132+Censys/Tranco/Weber+STAR honest

- [ ] 13. Active learning 15 human via KMeans+entropy LOO Platt B=2 disjoint — fix simulated +0.06 and 15 positives theater
  What to do / Must NOT do: Create assessment/active_select.py with KMeans k=15 on build_vector embeddings then max-entropy within each cluster (one per cluster) not entropy-only _select_uncertain 116-142 trap, stratified ≥5 positives AND ≥5 negatives (not 15/15 positives theater), disjoint D_prior hash partition via hashlib.sha256(TLS,cipher,kex) 0-6 prior 7 human 8 cal 9 test (not env string), L2 Logistic Platt B=2 LOO-CV C=1.0 (not B=5 at n=15 degenerates 0.84 positives), evaluate on locked D_test n≥500 disjoint, report Wilson CI [0.61,0.89] for 0.78, human=learned via FABLE GP or w∈[1,5] grid-search LOO Brier not fixed 3:1, store shared/fixtures/human_labels.json with annotator overlap for κ≥0.7 (not round-robin 1 each). Delete simulate delta 0.06 guard 417-428 if not 0.05<=delta<=0.08 delta=0.06, delete skip Platt 375-410 NO-OP, delete weak from same pool 276. Must NOT entropy-only, must NOT B=5, must NOT same pool, must NOT fixed 3:1, must NOT 15/15 positives.
  Parallelization: Wave 4 | Blocked by: 8,12 | Blocks: 16
  References (executor has NO interview context - be exhaustive): WRENCH 22 STENCIL SMI LogDet +10-18% acc +17-40% F1 15-25 exemplars 2402.13468 but needs diversity not entropy, FABLE GP mixture, BOXWRENCH >1000 crossover, ProbCover vs Coreset k-center outlier 2403.03728, Verified Uncertainty 1909.10155 O(B/ε²) B=2 needs n≥30 not 15, Label-Efficient NLL 75 top5>300, GLWS EM disjoint, assessment/active_select.py 116-142 entropy-only, 262 simulated delta, 375 skip Platt, 276 same pool, 205 15/15 positives
  Acceptance criteria (agent-executable): `ls shared/fixtures/human_labels.json && python -c "import json; j=json.load(open('shared/fixtures/human_labels.json')); assert len(j)>=15 and len([x for x in j if x['label']==0])>=5 and len([x for x in j if x['label']==1])>=5 and all('annotator' in x for x in j)"` stratified; `python -m assessment.active_select --select 15 2>&1 | tee .omo/evidence/task-13-sih26159-ml-honest-success.log` shows KMeans-15 + LOO B=2 and Wilson CI overlap disclosed not +0.06 win; `! grep -q "if not 0.05 <= delta" assessment/active_select.py` no simulate
  QA scenarios (name the exact tool + invocation): happy: `python -m assessment.active_select --dry-run 2>&1 | grep "KMeans.*entropy.*LOO.*B=2.*Wilson"`; failure: `grep -q "if not 0.05 <= delta" assessment/active_select.py && echo FAIL simulated` or `python -c "import json; j=json.load(open('shared/fixtures/human_labels.json')); assert sum(1 for x in j if x['label']==1)==15"` → FAIL 15 positives theater
  Commit: Y | feat(active): honest KMeans-15 stratified LOO B=2 Wilson

- [ ] 14. Fix dashboard Families jitter and CoverageTable true ratio
  What to do / Must NOT do: In dashboard/src/pages/Families.jsx replace Object.keys(manifest).slice(0,50) with groups_by_family expander showing 6 envs per jittered families (jitter1..5+loss0) vs 1 for others, GREASE/ja4_rarity/expiry badges, loss5 vs loss0, true coverage_ratio per flow not 1.0; in CoverageTable.jsx fix empty?'—':'1.0' to read f.coverage_ratio per flow (0.897 jittered). Lab.jsx jitter grouping table. Must NOT hide 35 jitter, must NOT hardcode 1.0.
  Parallelization: Wave 5 | Blocked by: 12,13 | Blocks: 16
  References (executor has NO interview context - be exhaustive): dashboard/src/pages/Families.jsx synthesize50 slice(0,50), dashboard/src/components/CoverageTable.jsx:103, dashboard/src/pages/Lab.jsx, lab/reassembler/reassemble.py coverage 1.0/0.897, lab/manifest.json 500, assessment/splits.json groups_by_family
  Acceptance criteria (agent-executable): `grep -q "groups_by_family\|jitter.*expander" dashboard/src/pages/Families.jsx` true and `! grep -q "slice(0,50)" dashboard/src/pages/Families.jsx`; `grep -q "coverage_ratio" dashboard/src/components/CoverageTable.jsx` true; `npm --prefix dashboard run build 2>&1 | tee .omo/evidence/task-14-sih26159-ml-honest-success.log` gzip<3670016
  QA scenarios (name the exact tool + invocation): happy: `curl -s http://localhost:8000/api/flows | jq '.[0].coverage_ratio'` shows 0.897 for jittered; failure: `grep -q "slice(0,50)" dashboard/src/pages/Families.jsx && echo FAIL`
  Commit: Y | fix(dashboard): expose jitter grouping true coverage

- [ ] 15. Verify 7900 GRE ROCm with CPU fallback graceful
  What to do / Must NOT do: Add scripts/verify_rocm.sh checks rocminfo|grep gfx1100 and python -c "import torch; torch.cuda.is_available()" via rocm/pytorch:rocm6.3, verify TabPFN device=cuda:0 fit_with_cache + predict_proba_batched 20-58× vs CPU fallback device=cpu if ROCm absent; ensure api/ml_enrich fallback calibrated_prob None still 200, wheelhouse<350M via Releases for ckpt. Must NOT block CI if ROCm absent, must NOT add torch to wheelhouse lean.
  Parallelization: Wave 5 | Blocked by: 6,7 | Blocks: 16
  References (executor has NO interview context - be exhaustive): https://rocm.docs.amd.com gfx1100, https://github.com/PriorLabs/TabPFN/issues/147, TabPFN classifier device cuda, api/ml_enrich fallback, scripts/turnup.sh
  Acceptance criteria (agent-executable): `bash scripts/verify_rocm.sh 2>&1 | tee .omo/evidence/task-15-sih26159-ml-honest-success.log` shows gfx1100 or CPU fallback OK; `du -m wheelhouse | tail -1 | awk '{print $1}'` <350
  QA scenarios (name the exact tool + invocation): happy: `bash scripts/verify_rocm.sh` exits 0; failure: `pip show torch | grep -q rocm || echo CPU fallback` must not fail build
  Commit: N | chore(rocm): verify 7900 GRE pipeline fallback

- [ ] 16. Metrics headline AP+Brier joint and EVIDENCE honest success — fix lax gates pooled<0.40 theater
  What to do / Must NOT do: Update eval/metrics.json to keep risk ap 0.976 Δ0.58 vs rule 0.396 at prev 0.056 but add nested 0.714 as primary not holdout 1.0, brier_joint 0.042 vs 0.22 + brier 0.035 vs 0.056 both with Wilson CI and decomposition UNC-RES+REL via tfp, per_class max not mean (low 0.005 med 0.036 high 0.035 spread 4.2x disclosed), bin_counts [94,6,0,0,0] disclosed + quantile-5 + SmoothECE/Kernel/debiased columns empty-bin NaN not 0.5, nested vs holdout gap 0.262 disclosed. Generate eval/EVIDENCE_Day14.md 500 proper distinct quality: Nested SGKF5x3 AP≥0.75 + LOGO132 AP≥0.75 + Censys within 0.10 + CORP MCB<0.05 + CPI TRIP p>0.05, per-class PCDM<0.25 ci_hi, pooled<0.15 ci_hi, 15 human +6pts Wilson [0.61,0.89] not win, anomaly 0.473 tooltip vs ja4 0.926, ensemble 0.623 challenger behind flag. Update shared/schemas_eval.py gates: n_eff 500 p_n 0.01, ece pooled hi<0.15 and per-class hi<0.25 (not 0.40 lax), brier ci_hi<base, gap<0.15 honest no clamp, ja4>0.90 κ>0.45, add ece_quantile + SmoothECE required. Must NOT keep 0.40 lax, must NOT mean without max, must NOT claim >0.80 without LOGO132+external within 0.10.
  Parallelization: Wave 5 | Blocked by: 12,13,14,15 | Blocks: 17
  References (executor has NO interview context - be exhaustive): eval/metrics.json ap 0.976 delta 0.58 brier 0.035 vs 0.056 nested 0.714 vs holdout 1.0 gap 0.262 per_class 0.018/0.077/0.064 spread, eval/EVIDENCE_Day13 6.5/8 interim, shared/schemas_eval.py:210 ece<0.40 lax vs 0.15 honest, assessment/generalization.py SGKF, docs/FAMILY_TAXONOMY.md 500 proper, tfp brier_decomposition, relplot SmoothECE, Verified Uncertainty O(B/ε²)
  Acceptance criteria (agent-executable): `python -c "from shared.schemas_eval import load_and_validate; load_and_validate(); print('valid')"` passes with new gates hi<0.15/hi<0.25; `grep -q "AP.*0.976.*Δ0\.58" eval/EVIDENCE_Day14.md` and `grep -q "proper.*distinct.*500" eval/EVIDENCE_Day14.md` and `grep -q "nested.*0\.714" eval/EVIDENCE_Day14.md` true; `python -c "import json; j=json.load(open('eval/metrics.json')); assert 'ece_quantile' in j['risk'] and 'brier_decomp' in j['risk']"` new columns; `pytest eval/tests/test_metrics_json.py -q` passes
  QA scenarios (name the exact tool + invocation): happy: `cat eval/EVIDENCE_Day14.md | grep -E "AP|PCDM|MCB"` shows AP headline max not mean; failure: `grep -q "ece<0\.40" shared/schemas_eval.py && echo FAIL lax gate` or `grep -q "clamp" eval/metrics.json && echo FAIL`
  Commit: Y | docs(evidence): honest AP+Brier joint max + gates hi<0.15/0.25

- [ ] 17. Locked external 30 + sync LEDGER and LEAKAGE_REPORT honest
  What to do / Must NOT do: Generate 30 locked families via lab/scripts/gen_locked_external.py --count 30 --seed 42 distinct taxonomy not jitter, .pcap+.sha256+.locked, update splits D3 10→30, groups_by_family 500 distinct, sync README Quick Start n_risk500 n_prior50 n_eff500, lab/LEDGER.md 500 rows with TLS/cipher/KEX/cert/STARTTLS/pre_tls/MTA-STS columns marking jitter vs distinct proper, eval/LEAKAGE_REPORT.md gap honest no clamp per-class disclosures p/n 7/500=0.014. Must NOT keep 10 locked at 200 scale, must NOT jitter as distinct.
  Parallelization: Wave 5+ | Blocked by: 16 | Blocks: -
  References (executor has NO interview context - be exhaustive): assessment/splits.json D3 10→30, shared/fixtures/locked_external, eval/tests/test_locked_external.py, lab/manifest.json 500, README n_risk85→500, docs/LARGE_FILES.md
  Acceptance criteria (agent-executable): `ls shared/fixtures/locked_external/*.pcap | wc -l` ==30 and `ls shared/fixtures/locked_external/*.sha256 | wc -l` ==30; `pytest eval/tests/test_locked_external.py -q` passes; `grep -q "n_risk500" README.md` true; `cat lab/LEDGER.md | wc -l` >=500
  QA scenarios (name the exact tool + invocation): happy: `sha256sum shared/fixtures/locked_external/*.pcap | sha256sum -c`; failure: `ls shared/fixtures/locked_external/*.locked || echo FAIL marker`
  Commit: Y | chore(eval): locked 30 + LEDGER honest 500

## Final verification wave
> Runs in parallel after ALL todos. ALL must APPROVE. Surface results and wait for the user's explicit okay before declaring complete.
- [ ] F1. Plan compliance audit
  What to do: Verify every todo has exhaustive References (no interview context needed), agent-executable Acceptance, happy+failure QA with evidence path, Commit line; check p_n 0.01 disclosure, no isotonic, no raw ja4, no m23, no GPU XGB at n=500, AP headline, per-class PCDM, LOGO132, proper 500.
  Tool: `grep -c "^- \[ \] [0-9]" .omo/plans/sih26159-ml-honest-success.md` ==17 and `grep -c "^- \[ \] F" .omo/plans/sih26159-ml-honest-success.md` ==4

- [ ] F2. Code quality review
  What to do: Run ruff + basedpyright, verify no blend remains, quantile+SmoothECE added, FlyingSquid m=6, SGKF+LOGO132 exists, TOP7 p/n honest, proper distinct 500, js build ok
  Tool: `pytest assessment/tests/test_features.py assessment/tests/test_splits.py shared/tests/test_ja4_grease.py -q && grep -rq "ece_macro = 0.38" assessment/ && exit 1 || echo clean && grep -rq "brier_base_joint \* 0.62" assessment/ && exit 1 || echo clean`

- [ ] F3. Real manual QA
  What to do: Replay curl pcap, dashboard expander 6 envs, coverage 0.897 true, human_labels.json 15 KMeans, generalization report LOGO132+Censys+Weber
  Tool: `bash scripts/turnup.sh --check && bash scripts/turnup.sh && curl -F pcap=@lab/pcaps/family-11.pcap http://localhost:8000/analyze 2>&1 | tee .omo/evidence/F3.log && echo "dashboard groups_by_family 6 envs" && cat shared/fixtures/human_labels.json | jq length`

- [ ] F4. Scope fidelity
  What to do: Confirm Must NOT violations: no m23 LabelModel primary, no GPU XGB, no scapy-only 500, no isotonic, no raw ja4, no entropy-only humans, no train leakage, no 1.0 holdout pass
  Tool: `grep -rq "LabelModel" assessment/weak_supervision.py && echo FAIL m23 || echo PASS limited; grep -rq "device.*cuda" assessment/risk_train.py && echo FAIL GPU XGB || echo PASS cpu; grep -rq "isotonic" assessment/ && echo FAIL || echo PASS; grep -rq "\"ja4\"" assessment/features.py && echo FAIL raw ja4 || echo PASS ja4_rarity only`

## Commit strategy
- Conventional commits: feat(lab):, feat(weak-sup):, feat(features):, feat(anomaly):, feat(calibration):, feat(generalization):, feat(active):, fix(dashboard):, docs(evidence): per todo Commit line
- Squash wave1 todos 1-4 chore(risk): remove blends honest, wave2 5-8 feat(data): 500 proper distinct, wave3 9-11 feat(ml): FlyingSquid+features+anomaly, wave4 12-13 feat(eval): generalization+active, wave5 14-17 feat(calibration): dashboard+evidence+rocm+locked
- Evidence logs .omo/evidence/task-<N>-sih26159-ml-honest-success.log

## Success criteria
- Honest success (your #1): Nested SGKF5x3 on 132 canonical AP≥0.75, LOGO132 AP≥0.75 and within 0.10 of nested, Censys 500 fresh within 0.10, Weber 6 mutated drop 30-40% disclosed but not blocking, STAR zero-shot reported, CORP MCB<0.05 TRIP p>0.05, Leave-Family-Feature-Out delta honest → proves actually learning features not rule engine
- Families honest: 500 proper distinct hash distinct==500 coherent 40 curated +50 Censys +6 Weber +200 Tranco + jitter 35 as augmentation only, validator --manifest coherent 0 fails
- Calibration honest: EW-5 legacy disclosed [94,6,0,0,0] + quantile-5 + SmoothECE/Kernel within CI, per-class PCDM<0.25 ci_hi, pooled<0.15 ci_hi, Brier joint 0.042 vs 0.22, empty bins NaN not 0.5
- Anomaly honest failure until >ja4: 0.473 tooltip do-not-block, ensemble 0.623 + IF 0.759 flagged challengers behind ?ensemble, require >0.926 to promote
- Weak supervision FlyingSquid m=6 triplet J<0.7 coverage>0.6 limited to critical metrics, primary y remains score.py 23 frozen
- Human honest: KMeans-15 + entropy-per-cluster stratified ≥5 positives disjoint LOO Platt B=2 L2, human learned not fixed 3
- Metrics headline AP 0.976 Δ0.58 at 17:1 not ROC 0.998, Brier joint not binary, per-component quality honest success 7.5-8.5/10 not theater

