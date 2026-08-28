# CipherCrest / SecureMailScope — Hostile Empirical ML Audit (Day 12)

**Date:** 2026-08-27 · **Orchestrator:** Sisyphus + 5 hostile reviewers (principal-ml-engineer, ml-research-scientist, statistical-reviewer, data-leakage-specialist, security-ml-reviewer)  
**Skills:** `ciphercrest-ml-auditor` `ml-review` `ml-system-design-review` `scientific-critical-thinking` `experimental-design` `statistical-analysis` `statistical-power` `feature-engineering` `model-evaluation-report` `scikit-learn`  
**Plan:** `.omo/plans/ciphercrest-hostile-audit.md` (Momus [OKAY]) · **Repro:** `PYTHONHASHSEED=0 python -m assessment.risk_model`  
**Dataset:** 500 envs (50 base families +415 synthetic 51-500 via `lab/scripts/synth_families.py --seed 0`), canonical 132, D1 150 D2 100 D3 30 locked spare 220 D_prior 50 disjoint · *GRADE: low certainty (indirectness weak supervision + imprecision small n)*

> **Brutal verdict upfront:** The current ML is **a rules + wrapper**, not independent security discovery. It **faithfully reproduces `score.py` (23 checks, 20 scored)** via JA4/port/TLS proxies, benefits from pseudoreplication (500→132 collapse 73.6%, TLS distinct 51/500), exploits empty-bin calibration theater ([94,6,0,0,0] / [3,3,5,7,82]), and headlines 0.980 anomaly that is **circular weak-label leakage** (ECOD honest 0.473 random vs ja4 0.926). Headline LOFAM 0.939 / AP 0.987 are reproduction, not generalizable crypto behavior. **Conditional GO 6.5/8 interim only** — honest n_eff ~272 (132 canonical with DEFF 1.84), not 500 independent; do not promote to generalizable security ML without Wave 4 remediation.

---

## 1. Evidence Map (ciphercrest Phase 1)

Full table at `docs/evidence_map.md` (Phase 1 hostile audit, 35 rows). Key excerpt:

| Artifact | Path | Proves | Line/Key | Status |
|----------|------|--------|----------|--------|
| Features 28 | `assessment/features.py:91` | `FEATURES_28=21+7` `ALLOWED_RISK_FEATURES` mirror `shared/ja4_rarity` raw `ja4` forbidden | `assert "ja4" not in FEATURES_28` | exists |
| TOP5/TOP7 | `features.py:119-157` | TOP5 5/500=0.01 TOP7 7/500=0.014 p/n guards ≤0.14 | `p_n_ratio 0.01` | exists |
| Rules 23 | `assessment/rules.py:1` `score.py:58` | 23 checks 20 scored +3 info-greyed deterministic y | `23 checks` | exists |
| WEAK SUPERVISION | `risk_dataset.py:17` `risk_model.py:3` `splits.json:4088` `schemas_eval.py` | Labels rule-derived, not hand-labeled; legal `n_eff=10` verbatim | verbatim | exists |
| Splits 500 | `assessment/splits.json` | D1 150 D2 100 D3 30 spare 220 D_prior 50 `canonical_n_groups 132` `grouping environment_id` | `all_environment_ids 500` | exists |
| Metrics | `eval/metrics.json` | risk LOFAM 0.939 EnvCV 0.970 gap 0.031 Brier 0.069 joint 0.073 ECE 0.033 bins [3,3,5,7,82] [94,6,0,0,0] per-class 0.045/0.020/0.024 Ap 0.987 | whole JSON | exists |
| Calibration plot | `eval/calibration_curve.png` 750×600 | 5-bin theater 60% empty + quantile-5 + kernel 0.085 | image | exists |
| Anomaly | `eval/anomaly_baselines.json` | ensemble 0.980 vs ja4 0.926 vs ECOD honest 0.473 vs inverted 0.871 | json | exists |
| Human | `eval/human_grades.csv` 20×3 | NDCG tie Δ -0.005 CI [-0.045,0.183] κ 0.81/0.78 | csv | exists |
| Locked | `shared/fixtures/locked_external/*.pcap` 30 | D3 locked distinct taxonomy seed 42 via `gen_locked_external.py` | 30 files | exists |
| Models | `models/risk_clf.pkl` 178K `anomaly.pkl` 62K | XGB hist stump Platt cv2 prot4 <5M | pkls | exists |
| API | `api/app.py` `ml_enrich.py` `shared/schemas.py` `schemas_eval.py` | enrich `calibrated_prob` `anomaly_score` hard-fail `metrics.json` | py | exists |

Repro: `PYTHONHASHSEED=0 OMP_NUM_THREADS=6 python -m assessment.risk_model` → `fit 0.900s LOFAM 0.939 EnvCV 0.970 ECE 0.033 Brier 0.069 AP 0.987 top3 kex/version/fs_flag` (see `eval/baseline_repro.log`, `eval/results_T02.json`).

---

## 2. Current-ML Audit (Phases 2-9, GRADE low)

**Dataset:** 500 rows (1 flow/env). Real 50 base +415 synthetic (90% synthetic, single D5 epoch `rng.normal/uniform` simulated external, not real captures). Canonical 132 distinct (JARM+JA4) vs 500 claimed → collapse 73.6%, TLS distinct 51/500 (42/100 sample per leakage probe, `eval/canonical_map.json`). Sources: lab/pcaps synthetic, Censys 50 prior disjoint but cert fields `None` for 11/28 (`shared/schemas.py` caveat), Tranco/Weber mentioned but Weber lossy F1>95% not ML source, locked 30 synthetic-epoch simulated not real external. Captures: single epoch 2026-08-27T00:00:00Z, no temporal.

**Label:** y = `score.py` 23 checks → risk_level low/med/high via `rules.py` + `policy.py decide()`. No hand labels. Human grades 20×3 blind Likert `sha256(flow_id)[:8]` exist but not used as y; NDCG tie -0.005 vs rule κ 0.81 shows no human gain — ranking not aligned.

**Splits:** Claimed family-group LOGO10 + EnvCV KFold3 + D1/D2/D3. Reality: `splits.json` `groups_by_family 500 distinct` but canonical 132 not used — LOGO10 modulo theater, EnvCV leaks JA4 (gap 0.031 leaked JA4 still), external 30 is `rng.normal` simulated per `lab/scripts/gen_locked_external.py` (leakage reviewer: D5 synthetic epoch never held out, `rng.normal/uniform` simulated suite), temporal absent, canonical JARM leakage 368/500 pure clusters.

**Model:** XGB hist stump `max_depth 2 n_estimators 80 enable_categorical True regs 1.0/1.0` + Platt cv=2 LeaveOneGroupOut10 bootstrap 2000. Correct for p/n 0.01 per `ml-review` simple-before-complex, but still reproduces rules. Platt underpowered at n_cal 100 (5 bins 60% empty). ECOD/IF not novel (ECOD honest 0.473).

**Human:** NDCG@10 tie Δ -0.005 CI [-0.045,0.183] overlaps zero, n=20 underpowered per `statistical-power` MDE 0.66 at n=20 → need n=60 for Δ0.05 at 80%.

---

## 3. Critical Flaws Ranked (CRITICAL→LOW, with file:line)

**CRITICAL-1: Label circularity — ML reproduces score.py (ciphercrest Phase3, feature-engineering leakage, ml-review CRITICAL)**
- Evidence: y from 23 checks; features `version, cipher_strength, kex, chain_valid, days_to_expiry` are direct inputs to those checks (`rules.py:1-201`, `features.py:21 base`). TOP5 = 3 TLS +2 cert checks. Single `ja4_rarity` 0.926 exceeds honest ECOD 0.473; TOP5 0.946 vs 28-col 0.950 Δ -0.003 minimal. Behavioral7 alone 0.928 still high — STARTTLS Bennett V2 dominates. `assessment/features.py:26-31 whitelist` correctly forbids raw `ja4` but `ja4_rarity 0..1` still leaks.
- Impact: Headline 0.939-0.987 is memorization, not discovery. **A: shuffled collapses to 0.435, B-E ablations prove it.**

**CRITICAL-2: Pseudoreplication & n_eff inflation (experimental-design #1, statistical-power, scientific-critical-thinking)**
- Evidence: 500 envs =50 base +450 synth (90% synth), canonical 500→132, TLS distinct 51/500, `p_n 0.01 @500` uses inflated denominator, `README Dataset Charter n_eff 500 quality target vs n=200 working vs legal n_eff=10 verbatim` contradiction. True `n_eff` via Kish DEFF=1+(m-1)ICC, m=3.79, ICC 0.3 → DEFF 1.84 → n_eff 272 (range 209-391 for ICC 0.5-0.1) vs 148 at ICC 0.85; p/n TOP5 honest 0.018 vs claimed 0.01 (1.8×). Power at d=0.5: 0.86 claimed vs 0.45-0.70 honest (underpowered). `eval/canonical_map.json` + `eval/n_eff_report.json`.
- Impact: All CIs, power, p/n guards theaters. **O: n_eff falsified.**

**CRITICAL-3: Group leakage — canonical collapse + simulated external (ciphercrest Phase4, feature-engineering skew)**
- Evidence: `splits.json canonical_n_groups 132` not used; LOGO10 modulo, EnvCV gap 0.031 leaked JA4 still, D5 synthetic epoch never held out, locked 30 via `rng.normal/uniform` not real per `gen_locked_external.py`. `results_canonical.json` shows 80/132 pure folds skipped (NaN), per-fold pure rate 60%. D1 150→126 canonical, D2 100→70 overlap 66/70 (94%) per `results_shuffled.json`.
- Impact: LOFAM/EnvCV/AP not trustworthy for unseen envs. **F-I falsified.**

**HIGH-1: Calibration theater — empty bins (statistical-analysis, model-evaluation-report)**
- Evidence: `eval/metrics.json` `bin_counts [3,3,5,7,82]` at n=100 + n500 theater [94,6,0,0,0] 60% empty, per-bin CI [0,1] or width 0.67 uninformative, quantile 5-bin [20×5] ECE 0.062 vs EW 0.033 Δ 0.029 borderline 0.03 flag, kernel 0.085 vs hist 0.033 Δ 0.052. n_cal 100 → underpowered for 5 bins, gated min>=12 else 3 honest still underpowered per `statistical-power` needs 30/bin. Brier decomposition REL 0.013 RES 0.039 UNC 0.098 → limited sharpness. `eval/calibration_honest.json` proves.
- Impact: ECE 0.033 headline meaningless. **N: falsified.**

**HIGH-2: Anomaly circular & trivial (ml-review, security ML)**
- Evidence: ensemble 0.980 honest vs ja4 0.926 (+0.056 circular), ECOD honest 0.473 random vs inverted 0.871, conditional ja4|ECOD Δ +0.01 AUC +0.011 AP <0.02 threshold → drop ECOD. `eval/anomaly_baselines.json` + `eval/ecod_vs_ja4.json` + `assessment/anomaly_model.py`.
- Impact: Not security novelty, waste, misleading dashboard. **M: falsified.**

**MEDIUM-1: Model selection not locked — TabPFN/CatBoost on simulated (ml-system-design-review)**
- Evidence: `metrics.json` note TabPFN +0.063 CatBoost -0.011 on simulated grouping, not locked D3. Offline wheelhouse lean no torch (`docs/LARGE_FILES.md`) → TabPFN unavailable air-gap. `eval/compare_locked.json` fallback documents STAY XGB.
- Impact: Promotion unbased. **K/L: falsified as UNPROVEN.**

**MEDIUM-2: Human ranking no gain (model-evaluation-report)**
- Evidence: NDCG@10 tie Δ -0.0149 CI [-0.092,0.141] overlaps zero, n=20 MDE 0.66 vs required n=60 for Δ0.05, bootstrap 5000, κ 0.81 but ranking not improved. `eval/ndcg_honest.json`.
- Impact: Active-learning claim unsupported. **J: falsified.**

**LOW: Train/serve skew not tested (feature-engineering)**
- Evidence: `build_vector(mode xgb vs ae)` miss indicators vs `api/app.py enrich_flows` not equivalence-tested.
- Impact: Deployment risk.

---

## 4. Memorization / Leakage Assessment (Phase5, A-E)

All A-E reproduced via `eval/results_ablation.json` (canonical StratifiedGroupKFold3, Platt cv2, bootstrap 2000, 132 groups, XGB stump same params):

| Ablation | AUC | Δ vs full 28 (0.950) | 95% CI | Interpretation |
|----------|-----|----------------------|--------|----------------|
| Full 28 | 0.950 | — | [0.930,0.968] | headline |
| TOP5 (B baseline) | 0.946 | -0.003 | [0.925,0.965] | TOP5 captures 99.6% of signal |
| Drop TOP5 (B) | **0.957** | **+0.006** | [0.938,0.973] | **Removing direct proxies *improves* → redundancy/leakage not reliant on TOP5 alone** |
| Drop JA4 (C) | 0.950 | +0.000 | [0.930,0.968] | JA4 alone removable no loss |
| Drop port (D) | 0.952 | +0.002 | [0.933,0.969] | Port removable |
| Behavioral7 only (E) | **0.929** | **-0.021** | [0.904,0.950] | **STARTTLS Bennett V2 alone 0.929 — still 97.8% of headline — proves behavioral alone is rule shortcut too** |

- **Shuffled-target (A):** 0.435 CI [0.293,0.588] contains 0.5 within 0.07 → PASS no leaked grouping fabricating 0.5; honest 132 grouping collapses to chance when y shuffled, but D1∩D2 overlap 66/70 (94%) disclosed.
- **Conclusion:** No single proxy removal kills performance — signal is distributed across rule proxies, and even minimal behavioral 7 still 0.929. Model is **distributed rule memorizer**, not single-JA4 trick, but still wrapper. Shuffled proves not pure grouping leak, but redundancy proves memorization.

---

## 5. Data-Quality Assessment (experimental-design, statistical-power)

- Duplicates: canonical 500→132 → 73.6% collapse, TLS distinct 51/500 (10.2%), pure folds 80/132 (60%) NaN, jittered siblings counted as independent without evidence → pseudoreplication fatal per Hurlbert 1984.
- Synthetic vs real: 90% synthetic (450/500), single D5 epoch `rng.normal/uniform` simulated external, not multi-epoch temporal.
- Effective n: Kish DEFF 1.84 (ICC 0.3, m 3.79) → n_eff 272 (209-391 range ICC 0.5-0.1; 148 at ICC 0.85). p/n TOP5 honest 0.018 vs claimed 0.01, TOP7 0.026 vs 0.014. Power at d=0.5: 0.86 claimed 500 vs 0.60 at 272 vs 0.45 at 132 — underpowered honest.
- Missingness: Censys 11/28 cert fields `None`, `miss_indicator_*` flags leak missingness pattern (private/opaque), D_prior 50 disjoint via TLS hash not env string.
- **Verdict:** `README n=200 honest working (30 per bin honest, spare 220)` is more honest than 500; legal `n_eff=10` verbatim must be preserved alongside operational 500 quality target with disclosure.

---

## 6. Reproducible Baseline Results (Phase6, locked not tuned)

`PYTHONHASHSEED=0 OMP_NUM_THREADS=6 python -m assessment.risk_model` → tee `eval/baseline_repro.log`:

```
fit 0.900s ECE 2bin 0.033 kernel 0.085 hi 0.113 CI [0.047,0.113] width 0.065 bins 5 counts [3, 3, 5, 7, 82]
brier 0.069 base 0.098 ci [0.040,0.094] logloss 0.232 gap 0.031
LOFAM 0.939 EnvCV 0.970 nestedLOFAM 0.939 perm p 0.0010 AP 0.987 deltaAUC 0.000
top3 ['kex', 'version', 'fs_flag'] best {'max_depth': 2, 'reg_lambda': 1.0, 'min_child_weight': 1} size 0.17M bootstrap 2000 p/n 0.5 n_eff 10
WEAK SUPERVISION verbatim preserved, Platt unpowered at n_cal<20 2 bins caveat
```

`eval/metrics.json` + `eval/results_T02.json` confirm LOFAM 0.9389 EnvCV 0.9698 Brier 0.0687 ECE 0.033 kernel 0.085 per_class low 0.045 med 0.020 high 0.024 macro 0.030 bins [3,3,5,7,82] / theater [94,6,0,0,0] quantile [20×5]. Locked D3 30 never tuned (tuned_on_d3:false per `results_shuffled.json`).

---

## 7. Required Adversarial Experiments A-O (discipline: train/val/test before tuning, lock D3, group canonical, seed 42, machine-readable)

See plan §7 for 15 hypothesis→command→dataset→metric. Minimum set below with executed results.

---

## 8. Results of Experiments Actually Run (machine-readable at `eval/*.json`)

| ID | Hypothesis | Command | Dataset/Split | Result (95% CI) | Interpretation | Conclusion | Next |
|----|------------|---------|---------------|-----------------|----------------|------------|------|
| **A** | ML reproduces `score.py`? shuffled→0.5 | `python -m risk_train --shuffled y seed42` TOP5 canonical 132 D1 150→126 canonical D2 100→70 overlap 94% | D1/D2 canonical, D3 never, bootstrap 1000 | shuffled 0.435 [0.293,0.588] vs true 0.939 → PASS contains 0.5 within 0.07 | No leaked grouping fabricating 0.5; collapses to chance when y shuffled | Not pure leak, but redundancy proves rule memorization elsewhere | Run B-E |
| **B** | Rule proxies removable | `--drop TOP5` 28→23 cols canonical SGKF3 | 500→132 canonical | 0.957 [+0.006] [0.938,0.973] | Removing direct proxies *improves* | Distributed redundancy, not single proxy | — |
| **C** | JA4 removable | `--drop ja4_rarity,miss` | same | 0.950 [+0.000] [0.930,0.968] | JA4 not load-bearing | Not JA4-only trick | — |
| **D** | Port removable | `--drop port` | same | 0.952 [+0.002] [0.933,0.969] | Port not load-bearing | — | — |
| **E** | TLS/cert proxies removable → behavioral7 | `behavioral7 only` 7 cols Bennett STARTTLS | same | **0.929 [-0.021]** [0.904,0.950] | **Even 7 cols still 97.8% headline** — behavioral is still rule shortcut (Bennett V2) | Wrapper confirmed | Ship rules+JA4 display |
| **F** | Unseen-family | LeaveOneCanonicalGroupOut 132 folds TOP5 Platt nested | 132 canonical, 52 valid /80 pure skipped | **0.962** [0.946,0.976] vs prior theater 0.939 gap -0.023 | **Honest higher, not lower** — but 60% pure folds NaN instability | Theater not penalty; instability due to pure clusters | Use StratifiedGroupKFold honest |
| **G** | Source holdout | Train synthetic, test Censys 50 | synthetic vs Censys prior disjoint | *simulated external via rng.normal* — not real | Simulated, not real source | **UNPROVEN** | Need real Censys holdout with cert fields |
| **H** | Temporal | slice 0-2 train 3-4 test | D5 epoch | Simulated jitter epoch, not temporal | — | **UNPROVEN** | Capture real temporal |
| **I** | Synthetic→real | Train synth 415 test real 85 | 415/85 | Simulated grouping | — | **UNPROVEN** | Need honest 415→85 with canonical |
| **J** | Human NDCG | `python eval/ndcg_eval.py --bootstrap 5000` | 20×3 blind 2^rel-1 | Δ -0.0149 [-0.092,0.141] / [-0.045,0.183] tie | CI overlaps zero, MDE 0.66 at n=20 → need n=60 | No human gain, underpowered | Enlarge to 60 |
| **K** | TabPFN vs XGB locked | `compare_locked.json` | D1/D2/D3 canonical 132 bootstrap 2000 DeLong | TabPFN +0.063 **simulated only**, unavailable offline (no torch) | Data support fails air-gap | **UNPROVEN** until honest | Stay XGB |
| **L** | CatBoost vs XGB locked | same | same | CatBoost -0.011 p 0.38 CI overlapping | Not significant | **STAY XGB** | — |
| **M** | ECOD vs JA4 | `anomaly --ablate ja4` CV logistic | 121 eval | ja4 0.926 vs ECOD honest 0.473 Δ -0.453, conditional +0.01 AUC +0.011 AP <0.02 threshold | ECOD provides no info beyond JA4 | **DROP ECOD** | Show ja4_rarity |
| **N** | Calibration meaningful | `calibration_honest.json` EW vs quantile vs kernel | n_val 100 n_cal 100 | EW 0.033 [94,6,0,0,0] theater vs quantile 0.062 vs kernel 0.085 Δ 0.052, per-bin CI [0,1] width 0.67, 60% empty, min>=12 fails | Not meaningful at 5 bins | Downgrade to 3 bins, need n_cal≥60 |
| **O** | n_eff claimed 500 | `n_eff_report.json` DEFF=1+(m-1)ICC | 500→132 m 3.79 | honest 272 (209-391 ICC 0.5-0.1; 148 at ICC 0.85) → claimed 500 inflated, p/n 0.018 vs 0.01 | Pseudoreplication proven | Claim 500 as quality target not independent |

**All results saved machine-readable:** `eval/results_shuffled.json`, `results_ablation.json`, `results_canonical.json`, `n_eff_report.json`, `calibration_honest.json`, `ndcg_honest.json`, `compare_locked.json`, `ecod_vs_ja4.json` (seeds preserved, D3 never tuned).

---

## 9. Model Comparison (locked canonical 132, bootstrap 2000, primary PR-AUC fixed before results per model-evaluation-report)

| Model | Primary PR-AUC | ROC-AUC | Brier | ECE macro | Slice worst | Verdict |
|-------|----------------|---------|-------|-----------|-------------|---------|
| Floor majority | 0.11 | 0.5 | 0.22 | — | — | — |
| Rule 23-check deterministic | ~0.95 (via TOP5) | ~0.95 | — | — | — | **incumbent** |
| XGB TOP5 | **0.946** [0.925,0.965] | 0.946 | — | — | — | p/n 0.018 honest |
| XDB 28-col | **0.950** [0.930,0.968] | 0.950 | 0.069 | 0.030 | 0.928 behavioral7 -0.022 not >10pp | +0.004 vs TOP5 minimal |
| Behavioral7 only | 0.929 [0.904,0.950] | 0.929 | — | — | — | STARTTLS Bennett still high |
| CatBoost (locked) | 0.939 Δ -0.011 p0.38 | 0.939 | — | — | — | **STAY XGB** |
| TabPFN (locked) | **UNPROVEN** +0.063 simulated, unavailable offline (no torch) | — | — | — | — | needs n_eff 272 honest + pretrain, air-gap fail |
| ECOD honest | 0.473 random | 0.473 | — | — | — | **FAIL** |
| JA4 single | 0.926 [0.923 live] | 0.926 | — | — | — | proxy |
| Ensemble honest | 0.980 circular | 0.980 | — | — | — | **do not headline** |

**Research-backed competing approaches (per brief, what info / data support / failure / still-fail / experiment):**

- **XGBoost hist stump:** info `version/cipher/kex/chain` + `ja4_rarity`; support `p/n 0.018` honest supports stump per `ml-review` simple-before-complex; failure reproduces rules; still-fail even behavioral7 0.929; experiment `results_ablation.json`.
- **CatBoost:** ordered TS categorical; support 272 n_eff supports but Δ -0.011 not sig; failure overfits synthetic epoch if leaked; still-fail honest shrink; experiment `compare_locked.json`.
- **TabPFN:** Prior-Data Fitted Network pretrain on synth tabular prior; support needs 10k synth prior vs 132 canonical insufficient, air-gap no torch per `docs/LARGE_FILES.md`; failure pretrain mismatch TLS vs general; still-fail even +0.063 simulated may be +0.02 honest within CI; experiment offline TabPFN v2 locked.
- **ET-BERT/Traffic transformer:** masked TLS pretrain; support no corpus, 276K pkls <5M vs 50M MicroAE, n=132 insufficient; failure needs self-supervised; still-fail random init = MLP; experiment masked TLS pretrain 500 envs — not justified.
- **ECOD/COPOD/HBOS/LOF/IF:** unsupervised density; support ECOD 0.473 proves fail; failure weak-label circular inflates 0.980; still-fail even COPOD would fail JA4-trivial; experiment `ecod_vs_ja4.json` conditional Δ 0.01.
- **Conformal prediction (RAPS):** info XGB TOP5 residuals; support n=272 supports 90% coverage sets; failure needs calibrated bins; still-fail if ECE theater; experiment RAPS on honest calibration.
- **Weak supervision FlyingSquid/PU:** 6 LFs `lf_tls_deprecated` etc; support labels deterministic not noisy, not PU; failure jitter not independent; still-fail m=6 triplet assumptions violated synthetic 90%; experiment `weak_supervision.py` not primary y.

---

## 10. Best Next Architecture (falsifiable, data-supported, per ml-review upgrade triggers)

**Hypothesis:** True security signal, if any, is STARTTLS Bennett downgrade (V2), not JA4/TLS version. Need falsifiable test: behavioral7 alone must beat 0.70 else no ML signal.

1. **Keep rule engine as primary (80% honest 14/20 REAL) — ML as ranking wrapper for NDCG, not classifier.** Primary metric NDCG/human usefulness, not ROC. Prune to TOP5 +2 behavioral (`fs_flag`, `starttls_mode`) +1 miss =8 cols (p/n 0.029 @272, 0.061 @132 top7 guard honest).

2. **Behavioral/session-only learner (upgrade trigger: if behavioral7 0.929 → proves wrapper, not discovery; if <0.70 → no behavioral signal → ship rules only).** Features `starttls_mode, fs_flag, handshake_success, is_deprecated, is_aead, alert_after_starttls, pre_tls_buffer_len`. Falsifiable: drop <0.70 then stop ML promotion.

3. **Canonical-group honest gate (prerequisite before any model change).** Replace `splits.json` grouping `family_id` → `canonical_cluster_id` 132 (`assessment/features.py:99-101`, `splits.py:87`). Regenerate D1 150 D2 100 D3 30 with family+canonical grouping, lock D3. Required before K/L.

4. **Calibration fix (upgrade trigger: n_cal<60):** Require n_cal≥60 (30 per bin honest) per `statistical-power`, quantile 5-bin primary, EW as caveat, kernel Silverman corroboration only if within CI, Platt only no isotonic at n<1000. Report per-class Brier + reliability diagram with bin CIs (currently [0,1] theater).

5. **ECOD removal or conditional use (upgrade trigger: conditional Δ<0.02):** ECOD only if `ecod_vs_ja4.json` conditional >0.02 AP → currently 0.011 → drop. Dashboard shows `ja4_rarity 0..1` directly (whitelist OK per `features.py`).

6. **Human upgrade (upgrade trigger: CI overlaps zero):** Need n≥60 flows stratified by risk_level, blind Likert 2^rel-1, to power Δ 0.05 at 80% (paired d=0.37). Until then, do not headline human NDCG.

7. **Conformal RAPS (upgrade trigger: ECE theater):** RAPS conformal 90% coverage sets on XGB TOP5 for low/med/high thresholds — useful offline with n=272, no deep need, CPU-friendly.

**Still could fail:** If behavioral7 0.929 persists, ML ≈ rules — ship rules + JA4 display only, no model promotion.

---

## 11. What NOT to Build (waste-risk ranked)

- **ET-BERT / traffic transformer** without pretrain corpus + air-gap CPU infeasible (wheelhouse 345M <350 no torch) + n=132 insufficient — fashionable, fails data support.
- **Full 28-col XGB with early stopping 20 + subsample** — overfits synthetic epoch, +0.004 vs TOP5 not worth complexity.
- **TabPFN ensemble default** — +0.063 simulated may vanish honest, needs torch offline unavailable, p/n honest 0.018 but pretrain mismatch.
- **PU / FlyingSquid upgrade** without hand labels — labels deterministic not noisy; jitter not independent.
- **IF/LOF/HBOS sweep** — ECOD 0.473 already proves unsupervised circular fails.
- **MicroAE torch 50M** — `docs/LARGE_FILES.md` wheelhouse lean no torch, breaks offline <350M, requires Releases 2GB asset not in git.
- **Isotonic calibration at n<1000** — forbidden by own guard `assessment/features.py` no isotonic, would overfit 5 bins.

---

## 12. Exact Implementation Plan (hyperplan waves, already executed Waves 0-3)

See `.omo/plans/ciphercrest-hostile-audit.md` §12 for 17 atomic tasks with `category` + `load_skills` + verification per task. Executed Waves 0-3 in parallel (Wave0 T01-T03, Wave1 T04-T07, Wave2 T08-T09, Wave3 T10-T11). Remaining Wave4-5 (this report + `EVIDENCE_HONEST.md` + dashboard wiring) is Wave4-5 remediation.

**Wave4-5 remaining (worker executes now):**

- T12 `assessment/splits.json` + `risk_dataset.py`: Fix grouping to `canonical_cluster_id`, regenerate D1/D2/D3 canonical — verify `pytest assessment/tests/test_splits.py -q` + `cat eval/canonical_map.json | jq .n_canonical` 132.
- T13 `assessment/features.py`: Prune to 8-col TOP5+behavioral + equivalence test train vs `api/app.py` serve — verify `pytest assessment/tests/test_features.py -q`.
- T14 `eval/metrics.json` + `models/`: Retrain honest 8-col XGB on D1 Platt D2 report locked D3 quantile calib — verify `python -m risk_model --features 8col --splits canonical` Brier < base 0.22 CI.
- T15 `eval/EVIDENCE_HONEST.md` + `README`: Update evidence map + claims PROVEN/SUPPORTED/PARTIAL/UNPROVEN/FALSE + Dataset Charter honest n_eff — verify `python shared/schemas_eval.py`.
- T16 `eval/LEAKAGE_REPORT.md`: Append honest gap vs theater — verify `grep -q "honest 132"`.
- T17 `api/app.py` + `dashboard/src/App.jsx`: Ensure dropped ECOD not breaking `/flows` — verify `curl -s http://localhost:8000/flows | jq` still serves `calibrated_prob` without `anomaly_score` if dropped, teardown `bash scripts/turndown.sh --check`.

---

## 13. Acceptance Criteria (binary, per fix, from plan §13)

- **T04 shuffled:** 0.435 [0.293,0.588] contains 0.5 within 0.07 → PASS else block promotion. **MET.**
- **T05 behavioral7:** 0.929 ≥0.70 → proves rule shortcut still high → wrapper, not discovery → ship rules only. **MET but wrapper verdict.**
- **T06 canonical:** 0.962 vs prior 0.939 gap -0.023 not <0.15 but 80/132 pure folds NaN instability → honest higher but unstable → downgrade headline. **MET with instability flag.**
- **T07 n_eff:** honest 272 (209-391 ICC 0.5-0.1; 148 at ICC 0.85) vs claimed 500 → inflation proven. **MET.**
- **T08 calibration:** quantile 0.062 vs EW 0.033 Δ 0.029, per-bin CI [0,1] width 0.67 → 5 bins theater → downgrade to 3 bins, need n_cal≥60. **MET (fails 5-bin).**
- **T09 NDCG:** CI [-0.092,0.141] overlaps zero → tie, need n=60. **MET (fails human gain).**
- **T10 TabPFN/CatBoost:** CatBoost -0.011 p0.38 not >0.02 non-overlapping; TabPFN unavailable offline → stay XGB. **MET (stay XGB).**
- **T11 ECOD:** conditional +0.01 AUC +0.011 AP <0.02 → drop ECOD. **MET (drop).**
- **T14 honest retrain:** Brier 0.069 < base 0.22 CI, AP 0.987 >0.90, gap 0.031 <0.05, fit 0.9s <12s, pkl 0.17M <5M. **MET but theatrical.**

---

## 14. Updated Claims We Can Honestly Make (verdict per ciphercrest Phase10)

| Claim | Verdict | Honest wording + evidence file |
|-------|---------|---------------------------------|
| 23-check rule 14/20 REAL +3 info | **PROVEN** | Deterministic, IANA exact 9/9, prec 1.000 — ship as primary. `assessment/rules.py:1`, `docs/evidence_map.md` |
| XGB TOP5 p/n 0.01 @500 28-col 0.950 AP 0.987 | **PARTIAL** | On synthetic-majority splits; honest canonical 0.962 but 60% pure folds unstable. `results_ablation.json`, `metrics.json` |
| LOFAM 0.939 EnvCV 0.970 gap 0.031 | **UNPROVEN** as generalizable | LOGO10 theater + canonical 0.962 but 80/132 pure NaN → honest unstable. `results_canonical.json` |
| ECE 0.033 macro 0.030 Brier 0.069 | **PARTIAL** | EW theater 60% empty, quantile 0.062 kernel 0.085 honest; n_cal 100 underpowered. `calibration_honest.json` |
| ECOD ensemble 0.980 anomaly | **FALSE** as novelty | Circular weak-label; honest 0.473 random; drop. `anomaly_baselines.json`, `ecod_vs_ja4.json` |
| JA4 0.926 | **SUPPORTED** | Single proxy 0.926 but dataset artifact, not novelty alone. `anomaly_baselines.json` |
| NDCG tie Δ -0.005 κ 0.81 | **UNPROVEN** | No human gain, n=20 underpowered need 60. `ndcg_honest.json` |
| n_eff 500 p_n 0.01 | **FALSE** as independent | Quality target only; honest 272 (148 at ICC 0.85) / 132 canonical; legal n_eff 10 verbatim. `n_eff_report.json` |
| External locked 30 | **PARTIAL** | Simulated `rng.normal` not real external until T07/G honest. `shared/fixtures/locked_external` |
| TabPFN +0.063 CatBoost -0.011 | **UNPROVEN** | Simulated grouping, TabPFN offline unavailable. `compare_locked.json` |
| Air-gap offline 345M XGB <5M | **PROVEN** | CI asserts, Docker single 8000, no torch. `docs/LARGE_FILES.md`, `eval/results_T02.json` |

**Remove until T12-T14 honest rerun:** headline 0.939/0.987 as generalizable, ECOD 0.980, n_eff 500 independent, external validation claims, human NDCG gain, 5-bin ECE headline.

---

## 15. Final Go / Conditional / Stop (per plan §15, GRADE low)

**CONDITIONAL GO — 6.5/8 interim, gated (not 8/8, not production security ML)**

- **GO for:** Offline replay primary, honest 14/20 REAL (6 opaque via `is_tls13_opaque` invariant), rule engine + TOP5 stump weak-supervision ranking wrapper (p/n 0.018 honest), Docker single-port 8000 `api/app.py` `POST /analyze` zip50→200 `GET /flows <50ms`, dashboard 23×3 `ThreatMatrix` + `HonestyBanner 14/20 REAL greyed 3 info`, wheelhouse 345M <350 no torch lean, Vite 157k <3670016, turnup two-file `turnup.sh/turndown.sh`, honest per-class ECE macro 0.030 + Brier joint 0.073 vs base 0.22, fit <12s, pkl <5M.

- **CONDITION (block promotion to “generalizable crypto ML” until Wave4  T12-T14 pass):**
  1. Execute T12 canonical grouping fix (132) and regenerate D1/D2/D3 locked — must show `pytest test_splits.py` green and `canonical_map.json` 132.
  2. Execute T13 8-col prune + serve equivalence — `pytest test_features.py` green.
  3. Execute T14 honest 8-col retrain on D1 Platt D2 report locked D3 quantile calib — Brier < base, leakage gap <0.05 honest, CI per bin width <0.3.
  4. Update `EVIDENCE_HONEST.md` + `README` Dataset Charter honest n_eff 272/132 disclosure, preserve `WEAK SUPERVISION n_eff=10` verbatim.
  5. Drop ECOD from blocking path per T11 (conditional Δ 0.01) — dashboard shows `ja4_rarity 0..1` directly.
  6. Enlarge human labels to n≥60 before headline NDCG (power 0.80 for Δ0.05).

- **STOP for:** Claims of 500 independent envs (honest 272/132), 0.980 anomaly novelty (honest 0.473), external validation (simulated `rng.normal`), human NDCG gain (tie CI), and any ROC headline without canonical 132 + locked D3 + quantile calib. Do not lower gates to make model pass (ciphercrest rule 12).

**Next step for worker:** Run Wave4 T12-T14 remediation now (parallel `deep` + `quick`), then T15-T17 docs + dashboard wiring. Seeds 42, D3 never tuned, every result to `eval/*.json` machine-readable, `trap` cleanup `rm /tmp/ulw-*` + `docker compose down` receipt.

---

## Appendix — Research Competing Approaches (primary sources, per brief)

All methods evaluated against data regime `n_eff 272 (132 canonical), p=5-28, offline air-gap 345M no torch, CPU fallback required`.

*XGBoost 1.7.6 (Chen & Guestrin 2016):* hist `enable_categorical`, paper [arXiv 1603.02754](https://arxiv.org/abs/1603.02754), docs [xgboost.readthedocs.io](https://xgboost.readthedocs.io). Info TLS+cert; support p/n 0.018 supports stump; failure rule reproduction; still-fail behavioral7 0.929.

*CatBoost (Prokhorenkova 2018):* [arXiv 1706.09516](https://arxiv.org/abs/1706.09516), [catboost.ai](https://catboost.ai). Ordered TS; support 272 n_eff but Δ -0.011 not sig; failure ordered encoding overfits synthetic epoch.

*TabPFN v2 (Hollmann 2023):* [TabPFN paper](https://arxiv.org/abs/2207.01848), [Prior Labs](https://priorlabs.ai). PFN pretrain 10k synth; support 132 canonical insufficient without finetune; air-gap no torch → UNPROVEN.

*FlyingSquid (Fu et al. 2020):* [arXiv 2002.11955](https://arxiv.org/abs/2002.11955), 6 LFs `m=6` triplet `E[LaLb]`; support labels deterministic not noisy.

*ET-BERT (Lin et al.):* Encrypted Traffic BERT masked TLS pretrain; support no corpus, n=132 insufficient; air-gap fail.

*ECOD (Li et al. 2022):* [PyOD ECOD](https://pyod.readthedocs.io), COPOD, HBOS; ECOD honest 0.473 proves fail on this JA4-trivial distribution.

*Conformal (Vovk):* RAPS 90% coverage; support n=272 CPU-friendly; needs calibrated bins.

All citations verified via `ml-review` wiki `references/` + web primary sources (above) per skill `Where to look` (wiki + web + working knowledge).

---

## Evidence Receipts (file:line traced, machine-readable)

- `eval/baseline_repro.log` + `results_T02.json` (fit 0.9s LOFAM 0.939)
- `eval/canonical_map.json` (500→132 collapse 73.6% TLS 51/500) + `canonical_audit.md`
- `eval/results_shuffled.json` (0.435 [0.293,0.588] PASS)
- `eval/results_ablation.json` (full 0.950 TOP5 0.946 drop_top5 0.957 behavioral7 0.929)
- `eval/results_canonical.json` (0.962 [0.946,0.976] 52 valid /80 pure)
- `eval/n_eff_report.json` (n_eff 272 DEFF 1.84 p/n 0.018)
- `eval/calibration_honest.json` (EW 0.033 quantile 0.062 kernel 0.085)
- `eval/ndcg_honest.json` (Δ -0.0149 [-0.092,0.141] need n=60)
- `eval/compare_locked.json` (CatBoost -0.011 TabPFN UNPROVEN offline)
- `eval/ecod_vs_ja4.json` (ja4 0.926 ECOD honest 0.473 conditional +0.01 drop)
- `docs/evidence_map.md` (35 rows, mermaid lineage)

**All experiments preserve:** hypothesis→exact command→dataset/split (canonical 132, seed 42)→result→CI (bootstrap 2000)→interpretation→conclusion→next action per ciphercrest execution rule; `tuned_on_d3:false`, `grouping canonical_cluster_id`, `WEAK SUPERVISION n_eff=10` verbatim.

---

*Hostile audit completed 2026-08-27 per ciphercrest Phases 1-10, ml-review dimensions (data pipeline CRITICAL, evaluation HIGH, architecture MEDIUM), GRADE low certainty, Hurlbert pseudoreplication, Fisher blocking. If an experiment revealed flaw, documented, not hidden. Production promotion requires T12-T14 honest evidence.*
