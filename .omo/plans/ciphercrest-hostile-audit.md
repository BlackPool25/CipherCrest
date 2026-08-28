# CipherCrest / SecureMailScope — Hostile Empirical ML Audit & Remediation Plan
**Mode:** hyperplan ultrawork — 5-hostile-reviewers adversarial synthesis  
**Date:** 2026-08-27 | **Lead:** Sisyphus (orchestrator) + 5 reviewers (principal-ml-engineer, ml-research-scientist, statistical-reviewer, data-leakage-specialist, security-ml-reviewer)  
**Skills enforced:** ciphercrest-ml-auditor, ml-review, ml-system-design-review, scientific-critical-thinking, experimental-design, statistical-analysis, statistical-power, feature-engineering, model-evaluation-report, scikit-learn  
**Plan status:** DECISION-COMPLETE — executable with zero further interview. Worker executes waves in order; verification per task.

---

## 0. Executive Verdict (synthesized from 5 critiques)

**Current system:** 28-col (21+7 miss), 23-check rule engine (20 scored +3 info-greyed), XGB hist stump `max_depth 2` `n_estimators 80` `enable_categorical True` + Platt cv=2, ECOD/IF, LOFAM LOGO10, EnvCV 3-fold, TOP5/TOP7, n_eff claimed 500 (honest working 200), 500 envs (85 real +415 synthetic families 51-465). Reports: headline LOFAM 0.939 / EnvCV 0.970 / AP 0.987 with Brier 0.069 ECE 0.033 macro 0.030, but also much lower nested/binned reality (see flaws).

**Hostile consensus:** System is **predominantly a rules + ML wrapper**, not independent security discovery. The model **faithfully reproduces `score.py`/`rules.py`** via leakage proxies (JA4, port, TLS cert). Evidence: single-feature `ja4_rarity` AUC 0.926 exceeds honest ECOD ensemble 0.473-0.980 circular contrast, TOP5 0.956 vs 28-col 0.974 (+0.018 delta), perm p=0.001 trivial due to deterministic labels, calibration bins empty 60% [94,6,0,0,0] / [3,3,5,7,82]. `n_eff=500` is **operational quality target**, not independent experimental units — true n_eff ≈85 real families + 1 synthetic epoch (≈132 canonical clusters, 42/100 TLS distinct). Headline ROC-AUC is inflated by pseudoreplication + family leakage (canonical 500→132 contamination, LOGO132 modulo theater, D5 synthetic epoch, simulated external `rng.normal`).

**Final recommendation:** **CONDITIONAL GO with major caveats** — not 8/8, not production promotion as generalizable security engine. Honest claim is **6.5/8 interim** with strong rule engine + weak-supervision wrapper; ML adds ≤0.02 AP over TOP5 and fails ECOD information test. Remediation before any external-facing claim.

**Security ML reviewer:** ECOD honest 0.473 vs inverted 0.871 vs ja4 0.926 proves anomaly detector adds no security novelty beyond JA4 rarity; must not headline 0.980 ensemble (weak-label circular).  
**Statistical reviewer:** Calibration theater — 5 bins with 94 in bin5, 0 in bins3-4 at n=500; kernel vs histogram gap theater; per-class ECE 0.045/0.020/0.024 spread 0.025 but CIs [0,1] per bin; n_cal up to 100 but gated min>=12 else 3 honest still underpowered.  
**Data/leakage:** LOGO132 modulo, D5 synthetic epoch, canonical collapse, simulated external suite = not external; 450/500 families synthesized → 90% synthetic.

---

## 1. Evidence Map (Phase 1 — ciphercrest-ml-auditor)

| Artifact | Path | What it proves | Line/key |
|----------|------|----------------|----------|
| Feature contract | `assessment/features.py:1-120` | 28 =21+7, ALLOWED_RISK_FEATURES whitelist, TOP5 p/n 0.01 @500, TOP7 0.014, XGB_CATEGORICAL_PARAMS hist+enable_categorical | `FEATURES_28`, `assert p_n_ratio 0.01` |
| Rule engine truth | `assessment/rules.py`, `assessment/score.py` | 23 checks, 20 scored +3 info-greyed, deterministic y, WEAK SUPERVISION | `WEAK_SUPERVISION` verbatim |
| Training | `assessment/risk_model.py`, `risk_train.py`, `risk_dataset.py`, `risk_metrics.py` | XGB stump max_depth 2, Platt cv=2, LOGO10, EnvCV 3, bootstrap 2000, ECE bins | `XGB_PARAMS`, `train_and_evaluate()` |
| Splits | `assessment/splits.json` | 500 envs family-01…50 +51-500 synth, D1 150 D2 100 D3 30 spare 220 D_prior50, groups_by_family 500 distinct claimed | `all_environment_ids` |
| Metrics | `eval/metrics.json` | risk: ece 0.033, brier 0.069 base 0.098 joint 0.073, LOFAM 0.939 EnvCV 0.970 gap 0.031, AP 0.987, bins [3,3,5,7,82] 5bin [94,6,0,0,0] quantile [20×5], per_class ECE low 0.045 med 0.020 high 0.024, n_val 100 | whole JSON |
| Calibration plot | `eval/calibration_curve.png` | 750×600 5-bin [94,6,0,0,0] n_eff 500 theater | image |
| Evidence docs | `eval/EVIDENCE_Day13.md` (6.5/8), `EVIDENCE_Day12.md` (8/8), `EVIDENCE_Day10.md` (5/8), `LEAKAGE_REPORT.md` | conflicting claims, honest 500-quality vs synthetic clamps removed | docs |
| Anomaly baselines | `eval/anomaly_baselines.json` | ensemble 0.980 honest vs inverted 0.871 vs ja4 0.926 vs IF 0.759 | json |
| Human labels | `eval/human_grades.csv`, `eval/ndcg_eval.py`, `eval/tests/test_ndcg.py` | NDCG@10 tie Δ -0.005 vs rule κ 0.81/0.78 CI [-0.045,0.183] 2000-boot, n=20×3 | csv |
| External/locked | `shared/fixtures/locked_external/*.pcap` (30), `lab/scripts/gen_locked_external.py` | D3_locked 30 distinct taxonomy not jitter, seed 42 | files |
| Models | `models/risk_clf.pkl` 125K, `anomaly.pkl` 76K, `anomaly_honest.pkl` 76K | Platt cv2, ECOD | pkls |
| API wiring | `api/app.py`, `shared/schemas.py`, `shared/schemas_eval.py` | enrich calibrated_prob/anomaly_score, hard-fail metrics.json | py |
| ML arch doc | `docs/` + `assessment/LEDGER.md` + `.omo/plans/sih26159-*.md` (7 prior) | 50-family honest + 415 synth, TOP5/TOP7, p/n guards | docs |
| Dataset charter | `README.md` Dataset Charter | n_eff 500 target vs n=200 working vs n_eff=10 verbatim legal | README |

**Reproduce command:** `PYTHONHASHSEED=0 python -m assessment.risk_model` → `fit ~12.7s ECE 0.033 Brier 0.069 LOFAM 0.939`

---

## 2. Current-ML Audit (Phases 2-9)

### Dataset
- Rows: 500 envs ×1 flow/env =500 rows. Real: 50 base families ×? Actually 85 orig asserted vs 50 in splits.json — discrepancy. Assessors found 500 distinct `environment_id` but only 85 orig +415 synth families 51-465 → 90% synthetic. Synthetic epoch D5 uses `rng.normal/uniform` simulated external suite, not real captures.
- Canonical clusters: 132 distinct (per statistical reviewer) vs 500 claimed — 368 collapse due to JA4/TLS canonicalization (`lab/reassembler` + `analyzer/parse.py` GREASE filtering).
- Sources: lab/pcaps (synthetic), Censys 50 prior disjoint, Tranco/Weber mentioned but Weber lossy F1>95% not ML source, locked_external 30. Source leakage risk high — synthetic vs real not separated.
- n_eff: Claimed 500 quality target @ p_n 0.01 TOP5; honest working 200 @ TOP5 0.025 TOP7 0.035; legal verbatim n_eff=10 synthetic independent. Statistical: true n_eff ~85 real families +1 synthetic epoch collapses to 132 canonical — not 500 independent units. Pseudoreplication: jittered siblings counted as independent without evidence (experimental-design pseudoreplication fatal).

### Label
- y = rule-derived weak supervision `score.py` 23 checks → risk_level low/med/high via `rules.py` + `policy.py decide() allow/quarantine/block/flag`. No hand-labeled field data. Human grades exist (20×3 blind Likert, κ 0.81/0.78) but not used as y; NDCG tie -0.005 suggests no human gain over rules.
- Direct leakage: features are derived from same inputs as labels (TLS version/cipher/KEX/cert) — label FROM features, circular. Test A must quantify.

### Splits
- Claimed: family-group LOGO10 (10 folds, groups family_id), EnvCV KFold 3, D1 150 train D2 100 val D3 30 locked spare 220 D_prior50 disjoint. Reality: LOGO132 modulo theater — 500→132 canonical collapse means group leakage; jitter variants share family but also share JA4/cipher — env CV still leaks JA4. External 30 locked is synth-epoch simulated, not real external. Temporal holdout absent. Unseen-family holdout leaks canonical.

### Shortcut/Leakage (A-E)
- TOP5 0.956 vs 28-col 0.974 Δ 0.018 minimal gain — rules captured by 5 features.
- ja4_rarity single-feature AUC 0.926 vs ECOD ensemble honest 0.473 (worse) vs inverted 0.871 — single proxy beats ML.
- Port/TLS/version/cert proxies not yet removed empirically — hypothesized similar Δ small (need B-E runs).

### Model
- XGB stump max_depth 2 is correct for p/n 0.01 (ml-review: simple before complex). TabPFN/CatBoost comparison exists: delta TabPFN +0.063 CatBoost -0.011 vs XGB in metrics.json note, but under simulated grouping, not locked — must rerun honest.
- Platt cv=2 at n_cal up to 100, gated 5-bin → still underpowered, kernel 0.085 vs hist 0.033 corroboration within CI but theater.

### Generalization (F-I)
- F: Unseen-family LOFAM 0.939 reported but LOGO132 theater → true unseen-family likely 0.85-0.90 (need honest LOGO132/canonical-group).
- G: Source holdout not real — prior Censys 50 disjoint but cert fields None for 11/28, not scored.
- H: Temporal absent.
- I: Synthetic→real not tested honest — D5 synthetic epoch dominates.

### Calibration (N)
- Brier joint 0.073 < base 0.22, decomposed rel 0.013 res 0.039 unc 0.098 — looks good but bins empty. Quantile 5-bin [20×5] yields ECE 0.062 vs EW 0.033 Δ 0.029 flag >0.03 skew. Kernel 0.085 > hist 0.033. Per-class ECE low 0.045 med 0.020 high 0.024 but per-bin CIs [0,1] — not meaningful at n_val 100.

### Human (J)
- NDCG@10 tie Δ -0.005 CI [-0.045,0.183] overlaps zero; κ high but ranking not improved — ML ranking not human-aligned.

---

## 3. Critical Flaws Ranked (severity: ciphercrest + ml-review + experimental-design)

**CRITICAL-1: Label circularity / rule reproduction (ciphercrest Phase3, feature-engineering leakage, ml-review CRITICAL)**
- Evidence: y from 23 checks; features `version, cipher_strength, kex, chain_valid, days_to_expiry` are direct inputs to those checks (`assessment/rules.py:*)`; TOP5 captures 3 TLS +2 cert checks. ECOD 0.473 < ja4 0.926 proves no novelty. Must run A/B and shuffled-target.
- Impact: Headline 0.939-0.987 is reproduction, not discovery. All downstream claims unproven.

**CRITICAL-2: Pseudoreplication & n_eff inflation (experimental-design #1, statistical-power, scientific-critical-thinking selection bias)**
- Evidence: 500 envs =50 base +450 synth (90% synth, D5 epoch), canonical 500→132, 42/100 TLS distinct, jitter counted as independent, `p_n 0.01 @500` uses inflated denominator. True n_eff ≈85-132. `n_eff=500` vs verbatim `n_eff=10` contradiction undisclosed in gate.
- Impact: CIs, power, TOP5 p/n guard theaters; beats 500 barrier fabricated. All power claims false.

**CRITICAL-3: Group leakage via canonical collapse + simulated external (ciphercrest Phase4, feature-engineering skew)**
- Evidence: splits.json groups_by_family 500 distinct but canonical clustering collapse unhandled; LOGO132 modulo theater; external suite via `rng.normal/uniform` not real; D5 synthetic epoch never held out. EnvCV gap 0.031 leaked JA4 still.
- Impact: LOFAM/EnvCV/report AP not trustworthy for unseen environments.

**HIGH-1: Calibration theater — empty bins (statistical-analysis assumption, model-evaluation-report calibration)**
- Evidence: `bin_counts [3,3,5,7,82]` / `[94,6,0,0,0]` 60% empty, per-bin CI [0,1], quantile vs EW Δ 0.029, kernel 0.085. n_cal 100 → 20 per bin quantile OK but EW 5-bin theater, gated 3-bin at n_cal<12 still underpowered.
- Impact: ECE 0.033 headline meaningless; cannot claim calibrated.

**HIGH-2: Anomaly detection circular & trivial (ml-review Analyze, security ML)**
- Evidence: ensemble 0.980 honest vs ja4 0.926 — ensemble adds 0.054 via weak-label leakage; ECOD honest 0.473 random; inverted 0.871 shows label inversion better than honest. No behavioral/session-only feature ablations run.
- Impact: Anomaly score not security novel, wastes compute, misleading dashboard.

**MEDIUM-1: Model selection not locked — TabPFN/CatBoost delta on simulated splits (ml-system-design-review)**
- Evidence: metrics.json note TabPFN +0.063 CatBoost -0.011 vs XGB but on simulated grouping, not locked D1/D2/D3.
- Impact: Promotion decision unbased; need locked rerun.

**MEDIUM-2: Human ranking no gain (model-evaluation-report slice, scientific-critical-thinking)**
- Evidence: NDCG Δ -0.005 CI includes zero, n=20 underpowered per statistical-power.
- Impact: Claim “active-learning human labels” unsupported.

**LOW: Feature pipeline skew train vs serve not tested (feature-engineering, integration)**
- Evidence: build_vector XGB vs AE modes, miss indicators, categorical native — not equivalence-tested vs api/app.py enrich.
- Impact: Deployment risk.

---

## 4. Memorization / Leakage Assessment (Phase5 + feature-engineering)

- **Direct rule proxies:** TOP5 = direct rule inputs → memorization proven by TOP5 0.956 vs 28 0.974. Removing TOP5 should drop to ~0.6-0.7 if true learning else stay high via proxies.
- **JA4 proxy:** Single ja4_rarity 0.926 — model is JA4 memorizer. Removing JA4 (C) expected drop 0.02-0.05 minimal if truly JA4-driven, larger if other proxies compensate.
- **Port/TLS/cert proxies:** Not yet removed — hypothesized small drop (need B/E).
- **Effort to prove memorization:** Run A-E ablations + shuffled-target (should be 0.5) + permutation_importance already perm p 0.001 but trivial due to deterministic labels.

---

## 5. Data-Quality Assessment (experimental-design + statistical-power)

- Duplicate/near-duplicate rate: canonical 500→132 → 73.6% collapse; TLS distinct 42/100 at 100-sample check → 58% near-duplicate.
- Synthetic vs real: 90% synthetic (450/500), single D5 epoch jitter, not multi-epoch temporal.
- Effective sample size sensitivity: At d=0.5 two-sample, n_eff 132 gives power 0.45 not 0.80; at n=500 power 0.86 — honest power half reported. p_n guard violated if using n_eff true (5/132=0.038 vs 0.01 claimed).
- Missingness: cert fields None for Censys 11/28, censys prior_flag rows disjoint but cert missing handling via miss_indicator leaks missingness pattern.

---

## 6. Reproducible Baseline Results (Phase6)

Current committed metrics (reproduced via `PYTHONHASHSEED=0 python -m assessment.risk_model` + `cat eval/metrics.json`):
```
risk LOFAM 0.939 [env_cv 0.970 gap 0.031] AP 0.987 [0.978,0.996] Brier 0.069 joint 0.073 base 0.22 ECE 0.033 5bin [3,3,5,7,82] [94,6,0,0,0] per-class low 0.045 med 0.020 high 0.024 macro 0.030 kernel 0.085 quantile 0.062
anomaly ensemble honest 0.980 inverted 0.871 ja4 0.926 IF 0.759 ECOD honest 0.473
n_cal 100 n_val 100 bootstrap 2000 perm p 0.001 top3 kex/version/fs_flag fit 12.7s size 0.173M
WEAK SUPERVISION verbatim n_eff=10 legal vs n_eff=500 operational — disclosure required
```
**Baseline locked for comparison:** Use D1 150 train / D2 100 val / D3 30 locked test (seed 42) — DO NOT TUNE ON D3. Group = canonical_cluster_id (132) not family_id. Run `python -m assessment.risk_metrics --splits assessment/splits.json --canonical lab/manifest.json --locked shared/fixtures/locked_external` to reproduce.

---

## 7. Required Adversarial Experiments A-O (experimental-design + statistical-analysis)

Each needs: hypothesis, exact command/code path, dataset/split, result, CI, interpretation, conclusion, next action (ciphercrest execution rule). Minimum experiments:

A. Is ML just reproducing score.py?
   - H0: XGB == rule deterministic baseline (23 checks score). Run `python eval/tests/test_metrics_json.py --compare-rule` + shuffled-target `python -m assessment.risk_train --shuffled-target` (expect AUC 0.5). Metric: delta XGB vs rule AP/ROC.

B. Direct rule-proxy removal:
   - Remove TOP5 direct proxies `version, cipher_strength, kex, chain_valid, days_to_expiry` (and miss indicators) → train on remaining 23 cols. Command: `python -m assessment.risk_train --drop TOP5 --groups canonical`.

C. JA4 removal:
   - Drop `ja4_rarity` + `miss_indicator_ja4_rarity` → 26 cols. Command `--drop ja4_rarity,miss_indicator_ja4_rarity`.

D. Port removal:
   - Drop `port` categorical → 27 cols. `--drop port`.

E. TLS-version/cert-proxy removal:
   - Drop `version, cipher_strength, kex, chain_valid, san_match, days_to_expiry, chain_length, pubkey_bits, sigalg_weak, is_expired, is_self_signed, keysize_weak, cert_missing_reason` + miss indicators → behavioral-only `starttls_mode, fs_flag, handshake_success, is_deprecated, is_aead, alert_after_starttls, pre_tls_buffer_len` (≈7 cols). Tests true behavioral learning.

F. Unseen-family:
   - Honest LeaveOneCanonicalGroupOut (132 groups) not modulo LOGO10. `python -m assessment.risk_metrics --cv logocanonical --n_splits 132`. Also temporal: holdout families 41-50 as unseen family group.

G. Source holdout:
   - Train lab/pcaps synthetic+Tranco, test Censys prior 50 + Weber vs synthetic disjoint. `--source-holdout censys`.

H. Temporal:
   - Split by capture epoch D5 synthetic epoch vs D1 — if no timestamp, simulate temporal by jitter slice index holdout (slices 0-2 train, 3-4 test).

I. Synthetic→real:
   - Train synth 415 only, test real 85 only. `--train synth --test real`.

J. Human alignment:
   - Power-aware NDCG: n=20 insufficient → bootstrap CI already [-0.045,0.183]; need n≥60 per statistical-power (mde). Run `python eval/ndcg_eval.py --bootstrap 5000 --power-analysis` and report NDCG@5,10,20 plus κ.

K. TabPFN vs XGB locked:
   - Same D1/D2/D3 canonical groups, locked test. `python -m assessment.tabpfn_baseline --splits locked --compare xgb`. Report delta + paired DeLong CI.

L. CatBoost vs XGB locked:
   - Same locked. `python -m assessment.catboost_baseline --splits locked`. Expect -0.011 previously on simulated → verify.

M. ECOD information test:
   - ECOD vs ja4_rarity: ensemble vs single-feature gap, conditional value `anomaly | ja4`. Run `python -m assessment.anomaly_model --ablate ja4` and report Δ AUC + per-class.

N. Calibration meaningfulness:
   - Report EW 5-bin [3,3,5,7,82] vs quantile 5-bin [20×5] vs kernel 0.085 vs macro per-class vs Brier decomposition rel/res/unc. Compute bin occupancy, CI per bin, and require min>=12 else downgrade to 3 bins honest. Test Platt before/after.

O. n_eff audit:
   - Compute canonical clusters, TLS distinct, and effective sample via ICC DEFF =1+(m-1)*ICC (ICC from family intraclass). Report n_eff honest vs claimed 500 vs legal 10.

**Discipline per experimental-design:** Train/val/test BEFORE tuning, lock D3, group all jitter variants together (family+canonical), never jitter as independent, preserve seeds, save every result to `eval/results_A-O.json` machine-readable, document flaw if found.

---

## 8. Results of Experiments Actually Run (partial — leakage reviewer + metrics)

From prior run + reviewer probes (must re-run honest before promotion):
- A: TOP5 0.956 vs 28 0.974 Δ 0.018 → heavily rule-reproducing; shuffled not yet run (expected ~0.5 if not leaked via grouping).
- B-E: TOP5 removal not yet; ja4 single 0.926 suggests C drop small; port/TLS/cert proxies hypothesized similar.
- F: LOFAM 0.939 LOGO10 theater; honest LOGO132 expected lower (stat reviewer estimates 0.85-0.90) — needs honest rerun.
- G/H/I: Simulated external via rng.normal/uniform — not real → unproven.
- J: Δ -0.005 CI [-0.045,0.183] overlaps zero — no human gain.
- K/L: TabPFN +0.063 CatBoost -0.011 on simulated — needs locked rerun.
- M: ECOD honest 0.473 < ja4 0.926 → ECOD provides no info beyond JA4.
- N: Bins empty 60% → not meaningful.
- O: 500→132 collapse, n_eff inflated.

**Next:** High-value experiments still required before claims (see Wave1).

---

## 9. Model Comparison (ml-review + model-evaluation-report + scikit-learn)

Under **locked canonical grouping** (132 groups, D1/D2/D3 seeds fixed, bootstrap 2000, primary metric fixed BEFORE results):

| Model | Primary: PR-AUC (real bar = rule 0.95?) | ROC-AUC | Brier | ECE macro | Slice worst | Info |
|-------|------------------------------------------|---------|-------|-----------|-------------|------|
| Floor majority | 0.11 | 0.5 | 0.22 | - | - | |
| Rule 23-check deterministic | ~0.95 (approx via TOP5) | ~0.95 | — | — | — | incumbent |
| XGB TOP5 | 0.956 | — | — | — | — | p/n 0.01 honest |
| XGB 28-col | 0.974 | 0.939-0.970 | 0.069 | 0.030 | needs slice | +0.018 vs TOP5 minimal |
| CatBoost (prev simulated) | -0.011 vs XGB | — | — | — | — | needs locked |
| TabPFN (prev simulated) | +0.063 vs XGB | — | — | — | — | needs locked; small-data only |
| ECOD ensemble | 0.980 circular | — | — | — | — | weak-label leakage |
| ECOD honest | 0.473 | — | — | — | — | FAIL |
| JA4 single | 0.926 | — | — | — | — | proxy |
| **Required comparison after honest rerun:** XGB TOP5 vs XGB behavioral-7 vs JA4 single vs ECOD vs CatBoost vs TabPFN vs rule — all on same locked D3, same 2000-boot CI, paired DeLong, per-slice.

**Small-data regime guidance (ml-review references):** n_eff 132 at p=5 → p/n 0.038 still OK for XGB stump; TabPFN designed for p/n small n<10k may help but requires honest n_eff check; ET-BERT/traffic transformers need pretraining not supported (no pretrain corpus, CPU fallback required, air-gap); CopOD/HBOS not yet tested but ECOD 0.473 suggests unsupervised fails.

---

## 10. Best Next Architecture (falsifiable, data-supported)

**Do NOT jump to:** TabPFN as default, CatBoost everywhere, ET-BERT, deep transfer, learned embeddings without corpus (ml-review: simple before complex, data support fails). Each proposal must answer: what info, data support, failure mode, still-fail case, exact experiment (per brief).

**Recommended next (evidence-backed, minimal complexity):**

1. **Keep rule engine as primary (80% honest 14/20 REAL) — ML as weak-supervision wrapper for ranking, not classifier.** Primary metric: NDCG/human usefulness, not ROC. XGB TOP5 stump is sufficient; 28-col adds no value → prune to TOP5 + 2 behavioral (`fs_flag`, `starttls_mode`) + 1 miss indicator = 8 cols max (p/n 0.06 @132, 0.016 @500).

2. **Behavioral/session-only learner (hypothesis: true security signal is STARTTLS Bennett V2, not JA4).** Features: `starttls_mode, fs_flag, handshake_success, is_deprecated, is_aead, alert_after_starttls, pre_tls_buffer_len` (if available). Falsifiable: if this drops AUC <0.65, then no behavioral signal exists and ML is wrapper.

3. **Canonical-group honest evaluation as gate.** Replace family_id grouping with canonical_cluster_id (132) in `assessment/splits.json` + `risk_metrics.py`. Lock D3 external 30 *real* (not simulated) via `lab/manifest.json` canonical holdout. This is prerequisite before any model change.

4. **Calibration fix:** Require n_cal >=60 (30 per bin honest) per statistical-power; use quantile 5-bin primary, report EW as caveat, kernel SmoothECE Silverman as corroboration only if within CI. Platt only, no isotonic at n<1000. Report per-class Brier + reliability diagram with bin CIs.

5. **ECOD removal or conditional use:** ECOD only if conditional on ja4_rarity adds >0.02 AP (experiment M). Otherwise drop — dashboard shows `ja4_rarity` directly.

6. **Human-label upgrade:** Power analysis says n=20 → mde large; need n≥60 human-graded flows, stratified by risk_level, to power NDCG Δ 0.05 at 80% (per statistical-power). Until then, do not headline human NDCG.

7. **Conformal prediction for risk_level thresholding** (small-data credible): RAPS conformal on top of XGB TOP5 to give 90% coverage sets for low/med/high — useful offline with n=132, no deep need.

**What this still could fail:** If behavioral-7 AUC ≈0.6, then ML provides no security beyond rules → ship rules only + JA4 rarity display, no model promotion.

---

## 11. What NOT to Build (ranked by waste-risk)

- **ET-BERT / pretrained traffic transformer** without pretrain corpus + air-gap CPU infeasible + n=132 insufficient — fashionable, fails data support.
- **Full 28-col XGB with early stopping 20 + subsample** — overfits synthetic epoch, no gain vs TOP5.
- **TabPFN ensemble default** — needs locked evidence; previously +0.063 on simulated may vanish honest.
- **PU learning / FlyingSquid weak supervision upgrade** without human labels — labels are deterministic, not noisy; no PU.
- **Isolation Forest / LOF / HBOS sweep** — ECOD 0.473 already proves unsupervised circular fails on this distribution.
- **MicroAE torch 50M** — referenced in LARGE_FILES.md but wheelhouse lean no torch; breaks offline <350M.
- **Isotonic calibration at n<1000** — forbidden by own guard, would overfit.

---

## 12. Exact Implementation Plan (hyperplan waves — parallel grouping, dependencies, category+skills, verification)

**Notepad:** `NOTE=$(mktemp -t ulw-$(date +%Y%m%d-%H%M%S).XXXXXX.md)` → `docs/audit-notepad.md` (durable).  
**Scenario contract (binding):** Before ANY code, define 3 scenarios covering happy/edge/regression with binary observable + real surface + test file+id (ultrawork). Scenarios below map to waves.

**Wave 0 — Evidence & Lock (no tuning, establishes ground truth) — parallel**
- T01 `assessment/splits.json: Audit canonical clusters for splits — compute 500→132 collapse, write canonical_map.json — verify by `python eval/canonical_audit.py` + `cat eval/canonical_map.json | jq .n_canonical` =132` | cat: deep | skills: [ciphercrest-ml-auditor, experimental-design, statistical-power]
- T02 `eval/metrics.json: Reproduce baseline with PYTHONHASHSEED=0 — capture fit 12.7s, LOFAM 0.939, bins [94,6,0,0,0] — verify by `python -m assessment.risk_model 2>&1 | tee eval/baseline_repro.log` + `cat eval/metrics.json | jq .risk.lofam_auc`` | cat: deep | skills: [ciphercrest-ml-auditor, ml-review, model-evaluation-report, scikit-learn]
- T03 `lab/manifest.json + eval/LEAKAGE_REPORT.md: Evidence map table generation — verify by `python scripts/evidence_map.py --out docs/evidence_map.md` lists exact paths` | cat: quick | skills: [ciphercrest-ml-auditor, ml-system-design-review]

**Wave 1 — Leakage & Power (falsification) — parallel after Wave0**
- T04 `assessment/risk_train.py: A — shuffled-target sanity (expect 0.5) — verify by RED test `tests/test_shuffled_target.py` expects 0.5±0.05, run `pytest tests/test_shuffled_target.py -q` RED→GREEN` | cat: ultrabrain | skills: [feature-engineering, ciphercrest-ml-auditor, scikit-learn, scientific-critical-thinking] — acceptance: shuffled AUC 0.5±0.07 or else leakage proven
- T05 `assessment/features.py: B-E ablations — run TOP5 removal, JA4 removal, port removal, behavioral-7 only — verify by `python -m assessment.risk_train --ablate TOP5,JA4,port,behavioral --out eval/results_ablation.json` + `cat eval/results_ablation.json` deltas` | cat: ultrabrain | skills: [feature-engineering, experimental-design, ml-review, statistical-analysis] — acceptance: behavioral-7 AUC >0.70 to claim behavioral learning else wrapper
- T06 `assessment/risk_metrics.py: F canonical LOGO132 honest — replace family_id with canonical_cluster_id — verify by `python -m assessment.risk_metrics --cv logocanonical --out eval/results_canonical.json` + `jq .lofam_canonical` gap vs prior` | cat: ultrabrain | skills: [experimental-design, statistical-analysis, ciphercrest-ml-auditor]
- T07 `eval/canonical_audit.py: O — n_eff & ICC DEFF calculation — verify by `python scripts/n_eff_audit.py --icc --out eval/n_eff_report.json` reports DEFF and n_eff honest 132 vs claimed 500` | cat: quick | skills: [statistical-power, experimental-design, scientific-critical-thinking]

**Wave 2 — Calibration & Human (statistical rigor) — parallel after Wave1**
- T08 `eval/metrics.json: N — calibration honesty — compute EW [3,3,5,7,82] vs quantile [20×5] vs kernel 0.085 vs per-class Brier decomposition — verify by `python eval/calibration_audit.py --plot eval/calibration_curve_honest.png --out eval/calibration_honest.json` checks min>=12 else 3-bin` | cat: ultrabrain | skills: [statistical-analysis, model-evaluation-report, ciphercrest-ml-auditor] — acceptance: quantile ECE with CI, not EW theater; bin CIs not [0,1]
- T09 `eval/human_grades.csv: J — power-aware NDCG with bootstrap 5000 + mde for n=20 vs 60 — verify by `python eval/ndcg_eval.py --bootstrap 5000 --power --out eval/ndcg_honest.json` shows CI [-0.045,0.183] underpowered` | cat: quick | skills: [model-evaluation-report, statistical-power, scientific-critical-thinking]

**Wave 3 — Locked Model Comparison — after Wave1 grouping locked**
- T10 `assessment/tabpfn_baseline.py + catboost_baseline.py: K/L — TabPFN/CatBoost vs XGB on same locked D1/D2/D3 canonical groups, 2000-boot CI, DeLong paired — verify by `python -m assessment.compare_locked --models xgb,catboost,tabpfn --splits canonical --out eval/compare_locked.json` + `jq .delta_tabpfn .delta_catboost`` | cat: deep | skills: [scikit-learn, ml-review, model-evaluation-report, statistical-analysis] — acceptance: promote only if delta >0.02 and CI non-overlapping and per-slice not worse
- T11 `assessment/anomaly_model.py: M — ECOD conditional value vs JA4 — verify by `python -m assessment.anomaly_model --ablate ja4 --out eval/ecod_vs_ja4.json` + `jq .delta`` — acceptance: drop ECOD if Δ <0.02` | cat: deep | skills: [ml-review, feature-engineering, ciphercrest-ml-auditor]

**Wave 4 — Remediation Implementation (only if Wave1-3 proves signal) — after Wave3**
- T12 `assessment/splits.json + risk_dataset.py: Fix grouping to canonical_cluster_id, regenerate D1 150 D2 100 D3 30 locked with family+canonical grouping — verify by `pytest assessment/tests/test_splits.py -q` passes `groups_by_family distinct` and canonical audit 132` | cat: deep | skills: [experimental-design, scikit-learn, feature-engineering, ciphercrest-ml-auditor]
- T13 `assessment/features.py: Prune to TOP5+behavioral 8-col and add equivalence test train vs serve — verify by `pytest assessment/tests/test_features.py -q` + `python -m assessment.test_serve_equiv --flows 20`` | cat: deep | skills: [feature-engineering, scikit-learn]
- T14 `eval/metrics.json + models/: Retrain honest 8-col XGB TOP5-behavioral on D1, Platt on D2, report on locked D3 with quantile EW+kernel + per-class + Brier + slice — verify by `python -m assessment.risk_model --features 8col --splits canonical --out eval/metrics_honest.json` + `cat eval/metrics_honest.json | jq .risk.ap` CI` | cat: deep | skills: [scikit-learn, statistical-analysis, model-evaluation-report, ml-review]

**Wave 5 — Documentation & Gates — after Wave4**
- T15 `eval/EVIDENCE_HONEST.md + README.md: Update evidence map + claims table PROVEN/SUPPORTED/PARTIAL/UNPROVEN/FALSE + Dataset Charter honest n_eff — verify by `python shared/schemas_eval.py` hard-fail + `pytest eval/tests/test_metrics_json.py -q`` | cat: writing | skills: [ml-system-design-review, scientific-critical-thinking, Model Evaluation Report]
- T16 `eval/LEAKAGE_REPORT.md: Append Wave1-3 results, gap honest vs prior, and Go/Conditional/Stop with explicit criteria — verify by `cat eval/LEAKAGE_REPORT.md | grep -q "honest 132"`` | cat: writing | skills: [ciphercrest-ml-auditor]
- T17 `dashboard/app.jsx + api/app.py: Ensure dropped ECOD not breaking /flows enrich — verify by `curl -s http://localhost:8000/flows | jq .[0].assessment` still serves calibrated_prob without anomaly_score if ECOD dropped` | cat: visual-engineering | skills: [webapp-ui-skill] — teardown: `bash scripts/turndown.sh --check`

**Teardown todos (cleanup = QA):** `rm eval/results_ablation.json.tmp` etc., kill `agent-browser`/`playwright` if used, `docker compose down` if lab, `rm /tmp/ulw-*` — verify by `ps aux | grep -v grep` no orphans.

**Ordering rule:** Never parallelize RED and GREEN of same scenario (ultrawork). Waves 0-1-2-3 sequential; tasks within wave parallel.

---

## 13. Acceptance Criteria (per fix — binary, observable)

- **T04 shuffled:** AUC 0.5 ±0.07, else fail → proves leakage, block promotion.
- **T05 behavioral-7:** AUC ≥0.70 on canonical LOGO132 to claim behavioral learning; else admit wrapper, ship rules only.
- **T06 canonical LOGO132:** LOFAM gap vs prior LOGO10 <0.15 and reported as honest; if gap >0.15, downgrade headline.
- **T07 n_eff:** Report DEFF, ICC, n_eff honest (expected 120-140) with formula; claim 500 only as quality target, not independent.
- **T08 calibration:** Quantile 5-bin ECE with per-bin n≥12; EW [94,6,0,0,0] flagged theater; per-bin CI width <0.3; else downgrade to 3-bin.
- **T09 NDCG:** CI must exclude zero to claim human gain; else report tie and require n≥60.
- **T10 TabPFN/CatBoost:** Δ >0.02 with non-overlapping 95% CI and no slice >10pp worse; else stay XGB stump.
- **T11 ECOD:** Conditional Δ >0.02 vs JA4 alone; else remove ECOD, dashboard shows ja4_rarity directly.
- **T14 honest retrain:** Brier joint < base 0.22 with CI, AP >0.90 on locked D3, leakage gap <0.05 on honest, fit <12s, pkl <5M, lint clean.
- **T15 docs:** `load_and_validate()` passes, all claims labeled PROVEN etc., p-values with CIs, WEAK SUPERVISION verbatim preserved.

---

## 14. Updated Claims We Can Honestly Make (verdict per ciphercrest Phase10)

| Claim | Verdict | Honest wording |
|-------|---------|----------------|
| 23-check rule engine 14/20 REAL +3 info | **PROVEN** | Deterministic, IANA exact 9/9, prec1.000 — ship as primary |
| XGB TOP5 p/n 0.01 @500 quality 28-col 0.974 AP 0.987 | **PARTIAL** | On synthetic-majority splits; honest canonical unknown until T06 |
| LOFAM 0.939 EnvCV 0.970 gap 0.031 | **UNPROVEN** | LOGO10 theater; honest LOGO132 pending |
| ECE 0.033 macro 0.030 Brier 0.069 | **PARTIAL** | EW theater 60% empty; quantile 0.062 kernel 0.085 more honest; n_cal up to 100 underpowered |
| ECOD ensemble 0.980 anomaly | **FALSE** (as security novelty) | Circular weak-label; honest 0.473 random; do not headline |
| JA4 rarity 0.926 | **SUPPORTED** | Single proxy beats ECOD — but is dataset artifact, not security novelty alone |
| NDCG tie Δ -0.005 κ 0.81 | **UNPROVEN** | No human gain, n=20 underpowered |
| n_eff 500 p_n 0.01 | **FALSE** as independent | Quality target only; honest n_eff ~132; legal n_eff=10 verbatim |
| External locked 30 | **PARTIAL** | Simulated external via rng — not real external until T07/G |
| TabPFN +0.063 CatBoost -0.011 | **UNPROVEN** | On simulated grouping — needs locked rerun |
| Air-gap offline 345M wheelhouse XGB | **PROVEN** | CI asserts, Docker single port 8000, no torch |

**Remove from write-up until T04-T11 rerun:** headline 0.939/0.987 as generalizable, ECOD 0.980, n_eff 500 independent, external validation claims, human ranking gain.

---

## 15. Final Go / Conditional / Stop

**CONDITIONAL GO — 6.5/8 interim, gated:**

- **GO for:** Offline replay primary, honest 14/20 REAL, rule engine + TOP5 stump as weak-supervision ranking wrapper, Docker air-gap, dashboard 23×3, /analyze zip50→200, GET <50ms. Ship with honest docs and WEAK SUPERVISION disclosure verbatim.
- **CONDITION:** Execute Waves 0-3 honestly and update claims before any external publication or competition judging. Block promotion to “generalizable cryptographic ML” until T04-T11 pass criteria. If T05 behavioral-7 <0.70 and T06 gap >0.15, downgrade to **Stop ML promotion — ship rules + JA4 display only**.
- **STOP for:** Claims of 500 independent envs, 0.980 anomaly novelty, external validation, human NDCG gain, and any ROC headline without canonical grouping + locked test. Do not lower gates to make model pass.

**Next step for worker:** Start Wave0 T01-T03 in parallel. Use `team_create` waves per §12 with `category` + `load_skills` as listed. Save every result to `eval/results_*.json` machine-readable, seeds preserved, D3 never tuned on.

---

## Appendix — Skill-to-Task Justification (ultrawork “USE as many as fit”)

- **ciphercrest-ml-auditor** → T01, T02, T04, T06, T08, T11, T12, T16 (Phases 1-10 audit order, leakage, split, model, calibration, n_eff)
- **ml-review** → T02, T05, T10, T11, T14 (wiki: leakage/splits, evaluation, model selection, architecture choice)
- **ml-system-design-review** → T03, T15 (rubrics, repo-and-doc audit, Scorecard)
- **scientific-critical-thinking** → T04, T07, T09, T15 (bias/GRADE, hierarchy, claim evaluation)
- **experimental-design** → T01, T05, T06, T07, T12 (randomization, blocking, DOE, pseudoreplication, ICC DEFF)
- **statistical-analysis** → T05, T06, T08, T10 (assumption checks, test selection, diagnostics)
- **statistical-power** → T01, T07, T09 (sample size, mde, sensitivity, power curves)
- **feature-engineering** → T04, T05, T11, T12, T13 (point-in-time, leakage, encoding, train/serve skew)
- **model-evaluation-report** → T02, T08, T09, T10, T14, T15 (primary metric before results, baselines, CIs, slices, calibration)
- **scikit-learn** → T02, T04, T06, T10, T12, T13, T14 (Pipeline, cv, leakage prevention, ColumnTransformer)

**Research requirement (web aggressive):** Each of T10/T11 must cite primary sources (XGBoost docs, CatBoost docs, TabPFN paper/Hub, ECOD paper) via SearXNG/search; report what info method uses, data support, failure mode, still-fail case, exact experiment (per §9 table). Do not propose fashionable method without data-support analysis (ml-review § Pick mode).

**Agents / Category routing for worker:**
- T01,T07,T09 = `quick` + relevant skills
- T02,T10,T11,T12,T13,T14 = `deep` (one goal per call)
- T04,T05,T06,T08 = `ultrabrain` (logic-heavy, hostile)
- T15,T16 = `writing`
- T17 = `visual-engineering` (dashboard)

**Evidence capture per task:** RED→GREEN proof (test runner before/after) + real-surface artifact (CLI/curl/DB) + machine-readable JSON — both mandatory (ultrawork). No task complete without `lsp_diagnostics` clean, build 0, full suite green, and surface artifact.

---
*Plan synthesized from 5 hostile critiques (file:line traced) + repository reproduction `assessment/features.py`, `splits.json`, `metrics.json`, `risk_model.py` and prior evidence docs. All experiments preserve hypothesis→command→dataset→result→CI→interpretation→conclusion→next action. If an experiment reveals flaw, document it, do not hide.*
