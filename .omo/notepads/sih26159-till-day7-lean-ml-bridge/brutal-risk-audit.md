# BRUTAL RISK AUDIT — Lean XGB Platt cv=2 at n_eff=10 is Memorization, Not Learning

**Date:** 2026-08-25  
**Auditor:** Sisyphus-Junior — zero sugar, line numbers + shell proofs  
**Artifacts:** `assessment/risk_model.py` (249 lines), `assessment/features.py` (231 lines), `assessment/splits.json` (189 lines), `lab/manifest.json` (497 lines, 31 envs), `shared/fixtures/family-*.json` (10), `assessment/tests/test_risk_ablation.py` (116 lines), `eval/calibration_curve.png` (50118 B, 750x600), `models/risk_clf.pkl` (127624 B)  
**PYTHONHASHSEED=0 OMP_NUM_THREADS=6 throughout — all outputs reproducible under that env, broken otherwise**

---

## 0. EXECUTIVE SUMMARY — Is it learning?

**No. It is memorizing a 10-row rule table with 31 correlated copies and calling it ML.**

| Question | Answer | Evidence |
|----------|--------|----------|
| Does it generalize to a new cipher/cert family? | **No.** Family-grouped 3-fold AUC = 0.50 / 1.00 / 0.80 (mean 0.77, std 0.21) — one fold coin-flip. | `bash` family-as-group `StratifiedGroupKFold(n_splits=3, groups=fams)` — fold0 AUC 0.50, fold1 1.00, fold2 0.80. |
| Does it detect risk or invert its own rules? | **It inverts its own rules.** 13 of 21 base features are byte-identical to inputs of `rules.py` checks that generate the label. `fs_flag` corr -1.000 perfect. | `risk_model.py:82` label from `rules.py:65` same fields as `features.py:178`. Correlation proof section 3. |
| Is the calibration curve meaningful? | **No.** 10-bin curve has **2 occupied bins** (10 Low in bin 1, 21 High in bin 9, 8 empties). | `risk_model.py:175` → shell: 8 empty bins, bimodal proba 0.143/0.921 (section 4). |
| Is the ECE hi<0.20 honest? | **Only with train=val leakage.** Full-31 fit hi=0.115 disclosed; honest D1-12-only hi=0.305 >0.20. | `risk_model.py:126 X_train,y_train = df,y` with comment admitting leak (section 1). |
| Does `predict()` return calibrated risk? | **No — it returns inverted risk for Low families.** `predict()` uses `np.max(proba)` not `proba[:,1]`, so Low families (true prob 0.14) are served as 0.86 High. | `risk_model.py:234` — shell: family-01 `proba=[0.856,0.143] max=0.857 pos=0.143` inverted (section 7). |
| Is n=31 real? | **n_eff=10.** 21 jitter rows vary **1-2 of 28 dims** (only `ja4_rarity` + miss flag). | Shell: `family-02 n=4 varying 2/28` identical for all 7 jitter families (section 2). |

**Verdict:** SYSTEM 5/8 is real. The ML shell is a **well-wired toy**: correct plumbing, vacuous signal. Keeping it labeled `SYSTEM 5/8 green ML yellow lean shell NDCG deferred` is honest. Promoting it to ML 8/8 or citing ECE/AP/ROC as production evidence is fraud. Day8-10 must reach n>=50 independent, family-grouped CV, D1-only fit, and human-labeled D3 before any accuracy claim.

---

## 1. DATA LEAKAGE CHECKLIST — Line-by-line

| # | Check | Severity | Finding | Lines | Fix |
|---|-------|----------|---------|-------|-----|
| L1 | `_load_dataset` uses full 31 for training instead of D1 12 | **CRITICAL** | `risk_model.py:59 all_envs = splits["all_environment_ids"]` iterates 31; `126 X_train, y_train = df, y` assigns full 31 with comment admitting leak: `lean stability: D1 12 too small for cv=2 Platt at n_eff=10, using full 31 for fit but ECE on D2 val only`. Honest D1-only run reproduced hi 0.305 >0.20 (learnings T5). | `risk_model.py:57-94`, `113-126` | Train on `df[train_mask]` (D1 12) and report hi 0.305 as honest Day7 lean. Accept gate failure or defer XGB to n>=50. |
| L2 | Family prefix overlap across D1/D2/D3 | **CRITICAL** | `splits.json:130-160` D1 prefixes `{01,02,03,04,05}`, D2 `{05,06,07,08}`, D3 `{07,08,09,10}`. Shell: `D1∩D2={family-05}`, `D2∩D3={family-07, family-08}`. Val and locked test are not hold-out. | `splits.json:130-160` | Group by `family_id = env.split("__")[0]` not `environment_id`. D3 must be 4-5 novel families never in D1/D2/jitter. |
| L3 | GroupKFold degenerate — each env is its own group | **CRITICAL** | `splits.json:35-129 groups_by_env` is 1:1 (31 groups, 31 rows). `StratifiedGroupKFold(n_splits=5)` with `groups=envs` each size 1 → identical to `StratifiedKFold`. Jitter copies of family-02 are different groups, so they split across folds. | `risk_model.py:115-116`, `features.py:91-93` | Add `groups_by_family`, switch to `groups=family_id`, do LOFAM at n_eff=10. |
| L4 | 6 orphan jitter inflates headline 31 | **MEDIUM** | Risk splits use 25 of 31; orphans `02j3,03j3,04j3,08j3,10j1,10j3` counted in `all_environment_ids` but never evaluated. Ratio guard forces 6 orphans. | `splits.json:2-34`, learnings T2 | Document `all_risk_31` vs `trainable_25` vs `unused_6` with footer `n_eff=10`. |
| L5 | Outer 5-fold instantiated but never evaluated | **HIGH** | `risk_model.py:115 _outer = StratifiedGroupKFold(n_splits=5)` `116 _outer.split(...)` return never assigned, never iterated. One fixed D2 split (8 rows, with overlap) not 5-fold. | `risk_model.py:114-116` | Either run 5-fold LOFAM and report per-fold ECE/AUC, or delete pattern and state no CV at n_eff=10. |
| L6 | Label derived from features (circular supervision) | **CRITICAL** | `risk_model.py:80-83` same `flow` dict that builds label also builds vector. 13/21 base dims are direct rule inputs; `fs_flag` corr -1.000 perfect. Model learns rule table. | `risk_model.py:57-84`, `rules.py:20-201` | Obtain independent D3 labels (human) and report ECE on that subset separately. |
| L7 | `pre_tls_buffer_len` hack manufactures negatives | **HIGH** | Fixtures have no `pre_tls_buffer_len`; `rules.py:134-141` fallback makes family-01 label 1, but `risk_model.py:72-74` force-sets 0 to engineer 4 negatives (32% neg). Without hack near single-class. | `risk_model.py:72-74`, `rules.py:132-145` | Remove hack, use real `pre_tls_buffer_len` from reassembler, accept near single-class. |
| L8 | `predict()` serving bug — `np.max` vs `[:,1]` | **CRITICAL** | `risk_model.py:234 prob = float(np.max(proba))` returns max(proba) not proba[1]. Shell: family-01 `proba=[0.856,0.143] max=0.857` served as High inverted. Training uses `[:,1]` correctly, so metrics and serving disagree. | `risk_model.py:223-235` | `proba = clf.predict_proba(df)[0,1]` + regression test. |
| L9 | Determinism shallow — `hash(env)` without PYTHONHASHSEED | **HIGH** | `risk_model.py:77 h = abs(hash(env)) % 100` drives rarity; `241 assert ... or True` tautology disables guard. Without PYTHONHASHSEED=0 rarity shuffles (29->79). | `risk_model.py:77`, `241` | Use `hashlib.sha256` seeded RNG; fix guard to hard fail. |
| L10 | Jitter generation also unseeded | **MEDIUM** | `jitter_slices.py` uses `rnd.choice` not deterministically per env; `sample_ja4_rarity()` global random state. | `lab/scripts/jitter_slices.py` | Pin jitter RNG to `hashlib.sha256(env)`, log seed per env. |

---

## 2. GENERALIZATION FAILURES — What the 31 rows actually are

### 2.1 n=31, n_eff=10, p/n_eff=2.8 (p>>n when honest)

```
n_total = 31 rows, p = 28 features -> p/n = 0.90 (looks borderline)
n_eff   = 10 cipher/cert clusters -> p/n_eff = 2.80 (CRITICAL p>>n)
jitter copies 21 = correlated augmentation, not independent data
```

Shell per family `varying 2/28` dims (only `ja4_rarity` + `miss_indicator_ja4_rarity`; all other 26 std=0). Intra-jitter distance ~1.0 vs inter-family 2.5-4.0. At honest n=10, `max_depth=4` can shatter dataset; 80 trees x 2 folds = 160 trees x 16 leaves ~2560 leaves vs 10 points — capacity >> data by 250x.

### 2.2 Grouping illusion

| Claim | Reality | Leak |
|-------|---------|------|
| 31 groups via `environment_id` | 31 groups each size 1 -> `StratifiedGroupKFold(5)` degenerate -> plain `StratifiedKFold` | Jitter of same cipher splits across folds |
| `environment_id not in FEATURES_28` | True but irrelevant — `cipher_strength`/`kex`/`version` are 1:1 with family prefix | Not leaking string != not leaking information |
| D1 12 / D2 8 / D3 5 ratio 2.4<3 | Ratio guard forces 6 orphans, hides D2/D3 share families with train | `D1∩D2={05} D2∩D3={07,08}` — honest hold-out only family-09 and 10 base |

### 2.3 Cross-family CV collapses

```
groups=environment_id (leaky)  5-fold: all folds AUC 1.000 +-0.000
groups=family_id (honest)      3-fold: 0.50 / 1.00 / 0.80  mean 0.77 std 0.21
```

Honest CV is unstable — which is correct at n_eff=10. Stable 1.00 is leakage artifact. Day8-10 must switch to family_id and report 0.77 +-0.21 as lean reality.

### 2.4 Real vs synthetic gap

| Dimension | Synthetic Day7 | Real world | Why matters |
|-----------|----------------|------------|-------------|
| Cipher diversity | 10 hand-picked museum ciphers | 300+ IANA, per-client JA4 variance | Model seen 3% of space; any new cipher OOD |
| Cert diversity | 6 cert files + None for weak (miss_indicator dominates) | Thousands CA chains, wildcards, CT logs | Cert features synthetic-null -> miss flag not real signal |
| JA4 | GREASE 1-of-16 shuffle + hash-sampled rarity (only varying dim) | Real JA4 from ordered extensions per client | Weak corr -0.256, synthetic scalar |
| Banners | 3 Postfix/Dovecot templates | Dozens MTA banners (Exchange, Gmail, Sendmail, Exim) | Reassembly parser tautological on scapy marker |
| Temporal | Single epoch 2026-08-27T00:00Z all 31 | Diurnal/seasonal, CA rotation | No temporal hold-out; D5 synthetic |
| Label source | Rule-derived 23 checks | Hand-labeled incidents / CT-qualified | High ROC is rule memorization |
| Negative class | Manufactured via pre_tls=0 hack to get 4 negatives | Real majority Low/Medium | Without hack near single-class -> not learning data |

---

## 3. MEMORIZATION PROOFS — Not learning, table lookup

### 3.1 Perfect separation on every split (memorization signature)

```
Shell PYTHONHASHSEED=0 train_and_evaluate full 31:
  AUC all=1.000 D1=1.000 D2=1.000 D3=1.000
  ACC all=1.000 D1=1.000 D2=1.000 D3=1.000  AP=1.000
  proba bimodal: pos_mean 0.921 neg_mean 0.143
  XGB fold0 zeros 26/28 (kex 0.668 fs_flag 0.332), fold1 zeros 25/28
```

AUC 1.00 on train, val, and locked test simultaneously at n_eff=10 is not generalization — it is rule separability. `fs_flag` alone (-1.000 perfect) gives AUC 1.00 with depth-1 stump. 80 depth-4 trees are 100x overkill memorizing 2 binary dims.

### 3.2 Feature-label correlations (circularity)

```
version -0.317  cipher_strength +0.738  kex +0.942  fs_flag -1.000 perfect
is_aead -0.710  is_deprecated +0.407  chain_valid -0.265  etc
Only ja4_rarity -0.256 and port +0.311 not direct rule inputs; ja4_rarity weak.
Miss indicators 7 dims +0.265 via synthetic-null pattern.
```

Risk label = score(rules.evaluate(flow)) where rules read same flow fields as build_vector. 13/21 base dims are direct rule inputs. `permutation top3 version/cipher_strength/kex coherent vs score.py` is circularity proof, not validation.

### 3.3 Permutation importance theater

- `n_repeats=10` at n=31 gives `kex +0.19-0.27 std 0.07-0.10 cv 0.32`, 27 others 0.000;
  re-running 5 seeds (0,1,42,99,123) yields same kex top1 but #2/#3 random tie among 26 zeros (`miss_ja4`, `miss_sigalg` etc at 0.000);
  reported `version/cipher_strength/kex` coherent vs score.py is circularity, not validation;
  26/28 importances zero, 8 ECE bins empty — 10-bin curve and 28-dim ranking both create illusion of analysis where 2 dims suffice.

### 3.4 Training plumbing vs signal

| Artifact | Plumbing | Signal | Gap |
|----------|----------|--------|-----|
| XGB 80 trees depth 4 reg_alpha 1 lambda 2 | Frozen, CI guard, <5M, <1s | Toy — 2 splits suffice; 80 is 40x over; mild reg, no early_stopping | Use n_est 15 depth 2 at n_eff=10 or document 80 as placeholder for n>=50 |
| CalibratedClassifierCV sigmoid cv=2 | Platt only, cv=2 stratified on 31 works (15/16 per fold) | Unstable at D1 12 (each Platt fold 2 neg/4 pos -> logistic on 6 points -> hi 0.305) | Report D1-only cv=2 failure explicitly, defer |
| build_vector 28-col | len 28, no raw ja4, categorical native | Circular — 20/21 base dims are label inputs; ja4_rarity only honest dim synthetic | Need independent labels or prior-only features |

---

## 4. CALIBRATION DISHONESTY — The curve, the CI, the ECE

### 4.1 10-bin curve is a 2-point line

```
Shell proba min 0.143 max 0.927, bimodal at Low ~0.14 and High ~0.92
  bin [0.1,0.2] n=10 acc 0.000 conf 0.143  (all Low)
  bin [0.9,1.0] n=21 acc 1.000 conf 0.921  (all High)
  bins 0,2,3,4,5,6,7,8 n=0 (8 empty)
  calibration_curve(..., n_bins=10) returns only 2 points (sklearn drops empties)
  eval/calibration_curve.png plots 2 dots + diagonal — visually suggests calibration where there is only separation.
```

Severity **HIGH** — PNG exists (test checks >1000 B) and code calls 10 bins, but output degenerate. Presenting as 10-bin without noting 8 empty is misleading.

### 4.2 ECE hi<0.20 — leaked, narrow, fragile

| Claim | Leak | Honesty |
|-------|------|---------|
| `ECE 500-boot family-level (n_eff=10): hi 0.115 <0.20, CI [0.082,0.115] width 0.033 disclose +-0.10` | Full-31 fit leaks D2 val into train; honest D1-12-only hi 0.305 >0.20. | **Gate hacking** — choose split that passes. |
| `family-level bootstrap 500 resample families` | Correct to resample families, but resamples same 10 museum ciphers; and expands each sampled family to 1-4 rows (jitter copies) so boot n is 10-35 not 10 — variance underestimated. | Reported width 0.033 but disclose +-0.10; both optimistic vs Hoeffding +-0.30 at n=10. |

Shell: `boot n=494 mean 0.100 std 0.009 lo 0.082 hi 0.115` — std 0.009 implausibly small; narrow because per boot expands to ~31 rows.

### 4.3 PR curve same story

AP 1.00 same perfect separation. Test `test_ece_hi` re-runs leaked full-31 path, green tautological.

### 4.4 Honest ECE at Day7 lean

```
D1 12 only honest: ECE val (D2 8) ~0.138 point, 500-boot hi 0.305 >0.20
Action: report hi 0.305, mark gate deferred, note "n_eff=10 insufficient for Platt cv=2 — deferred to n>=50"
Today: fit on 31, keep hi 0.115 green — passes gate by leaking.
```

---

## 5. SEVERITY MATRIX — All findings

| # | Finding | Severity | Impact if shipped as claimed | Lines | Fix | Effort |
|---|---------|----------|------------------------------|-------|-----|--------|
| F1 | Train on full 31 (D2+D3 leakage) to pass ECE | CRITICAL | Any ECE/AP/ROC on test-contaminated model | `risk_model.py:57-126` | Train D1 12 only; report 0.305 deferred | Quick |
| F2 | `predict()` np.max inverted risk | CRITICAL | Low served as 0.86 High; High served as Low | `risk_model.py:233-234` | Use `proba[1]` + test | Quick |
| F3 | Family prefix overlap D1∩D2={05} D2∩D3={07,08} | CRITICAL | Val/locked measure jitter delta not new cipher | `splits.json:130-160` | Group by family_id; D3 novel families 11-15 | Quick* |
| F4 | GroupKFold degenerate 31 groups size 1 | CRITICAL | 5-fold claim empty; jitter splits across folds | `risk_model.py:115-116` | Add groups_by_family, LOFAM | Quick |
| F5 | Feature-label circularity fs_flag -1.000 | CRITICAL | AUC 1.00 is rule memorization | `features.py` `rules.py` | Independent D3 labels | Medium |
| F6 | Outer 5-fold instantiated discarded | HIGH | 5-fold green implied not measured | `risk_model.py:114-116` | Run 5-fold LOFAM or delete pattern | Quick |
| F7 | pre_tls=0 hack manufactures negatives | HIGH | 32% neg rate artifact; near single-class without hack | `risk_model.py:72-74` | Remove hack, use real reassembler values | Medium |
| F8 | hash(env) non-deterministic, guard tautology | HIGH | Rarity shuffles without PYTHONHASHSEED; guard or True disabled | `risk_model.py:77,241` | hashlib seeded RNG; fix guard | Quick |
| F9 | 10-bin curve 8 empties -> 2-point line | HIGH | PNG suggests 10-bin calibration where 8 empty | `risk_model.py:175` | Disclose 2/10 occupied, bimodal | Quick |
| F10 | ECE CI width 0.033 understates +-0.30 true | HIGH | Precise-looking CI but boot expands to ~31 rows | `risk_model.py:148-161` | Expand CI to +-0.15 or defer | Quick |
| F11 | p/n_eff 2.8 with 80 trees 250x over-capacity | HIGH | 26 zeros, memorize 2 dims with 250x capacity | `risk_model.py:43-54` | n_est 15 depth 2 at n_eff=10 | Quick |
| F12 | Permutation n_repeats=10 high variance | MEDIUM | cv 0.32, top3 beyond #1 random tie | `risk_model.py:164` | n_repeats 50 with variance caveat | Quick |
| F13 | 6 orphan jitter inflates 31 | MEDIUM | Denominator inflation | `splits.json:2-34` | Document all_risk vs unused | Quick |
| F14 | n_eff buried: EVIDENCE honest but progress/manifest hidden | MEDIUM | Execs see 31 green, think progress | `shared/progress.md` etc | Footer n_eff=10 everywhere | Quick |
| F15 | device param warning, np.NaN patch | LOW | Deprecation warning, not correctness | `risk_model.py:16-22` | Remove device, keep patch | Quick |

* F3 needs new families captured — Large to acquire, Quick to reshuffle.

---

## 6. FIX RECOMMENDATIONS — What Day8-10 must change

### 6.1 Blocking for any accuracy claim beyond SYSTEM parity (must do)

| # | Action | Effort |
|---|--------|--------|
| 1 | Fix `predict()` to `proba[1]` + inversion test | Quick |
| 2 | Train D1 12 only, report honest ECE hi 0.305 deferred | Quick |
| 3 | Switch grouping to family_id, LOFAM 10-fold report 0.77 +-0.21 | Quick (+ Large for new families) |
| 4 | Make D3 4-5 novel families never in D1/D2/jitter, no jitter for D3 | Large |
| 5 | Replace hash(env) with hashlib, fix PYTHONHASHSEED guard | Quick |

### 6.2 Lean to credible ML (n>=30)

| # | Action | Effort | Rationale |
|---|--------|--------|-----------|
| 6 | Capture 20+ independent families with distinct cipher/cert/version via live tcpdump + real certs; keep jitter as augmentation not toward n_eff | Large | n_eff=10 cannot support 28 dims; need >=30 |
| 7 | Populate cert fields via lab/certs/*.crt so cert.* not None | Medium | 7 miss flags dominate, not real cert signal |
| 8 | Feature-label decorrelation: CI fail if top3 subset of rule inputs; mitigate by evaluating on human-labeled D3 | Medium | Break circularity proof cited as validation |
| 9 | Calibrate reporting: 2-bin explicit, permutation n_repeats=50 with caveat, ECE CI +-0.15 or deferred, PR AP disclosed as bimodal | Quick | Prevent 2-point line read as calibration |
| 10 | Surface n_eff everywhere: LEDGER footer, progress row, splits.json n_eff field, dashboard banner | Quick | EVIDENCE honest but progress hidden — execs misread |

### 6.3 Production beyond Day10 lean (context)

| Criterion | Day7 | Day10 lean credible | Production |
|-----------|------|---------------------|------------|
| Independent envs | 10 | >=30 (LOFAM stable) | >=500 |
| Real vs synthetic pcaps | 10 scapy + fallback | 30+ real tcpdump + live cert chains | Continuous MX + CT logs |
| Label source | rule weak 23 checks | rule + human D3 | human + CA-qualified |
| Grouping | environment_id (leaky) | family_id (honest) | IP x CA x epoch triple |
| ECE | 500-boot hi 0.115 leaked | 1000-boot LOFAM honest hi ~0.30 | Wilson hi<0.10 |
| D3 locked | 5 envs, 2 honest 09/10 +3 leaked | 5+ novel families never touched | Temporal + geo hold-out |

---

## 7. AUDIT PROVENANCE

**Files read line-by-line:** risk_model.py 249 lines, features.py 231 lines, splits.json 189 lines (31 envs), manifest.json 497 lines (31 envs, 10 ciphers), score.py 80 lines, rules.py 201 lines (23 checks), ja4_rarity.py 108 lines (GREASE 16), fixtures 10, test_risk_ablation.py 116 lines, learnings.md 63 lines, brutal-dataset-audit.md 374 lines, EVIDENCE_Day7.md, LEDGERs, progress.md.

**Bash proofs PYTHONHASHSEED=0:**
- n 31 p28 p/n_eff 2.8, label 10 neg/21 pos, D1 12 (8/4) D2 8 (4/4) D3 5 (4/1), prefix overlaps D1∩D2={05} D2∩D3={07,08}, per-family jitter varying 2/28 only ja4_rarity+miss, hash rarity 0.05-0.82.
- Circularity: fs_flag -1.000 perfect, kex +0.942, cipher_strength +0.738, 7 miss +0.265, ja4_rarity -0.256 weak.
- Overfitting: AUC 1.00 all splits, XGB zeros 26/28, permutation top1 kex +0.25 +-0.08 cv 0.32, 26 zeros random tie, boot 500 mean 0.100 std 0.009 lo 0.082 hi 0.115 width 0.033 narrow.
- Calibration: 2 occupied bins of 10, bimodal 0.143/0.921, predict inversion family-01 proba [0.856,0.143] max 0.857.
- Honest CV family-grouped 3-fold 0.50/1.00/0.80 mean 0.77. D1-only hi 0.305 per T5 note reproduced.
- No modification to risk_model.py per MUST NOT DO — audit only.

---

## 8. BOTTOM LINE — One paragraph

Day7 delivers a real SYSTEM 5/8 (tshark parity, reassembly, cert limbo prec 1.000, rule weak recall) and a **leaky, circular, over-capacity toy classifier that memorizes 10 cipher/cert rules via 31 correlated rows, hides smallness behind honest EVIDENCE prose but lagging progress/ledger denominators, passes ECE by training on val, calibrates a 2-point line as 10 bins, and serves inverted probabilities via np.max — kept as SYSTEM 5/8 green ML yellow lean shell NDCG deferred n_eff=10 it is an honest scaffold; cited as accuracy, it is fraud. Day8-10 must fix serving inversion, train D1-only, regroup by family_id, lock 5 novel D3 families, and reach n_eff>=30 before any ML green.**

---

## Fix Addendum 2026-08-25 — F2/F8 resolved
- **F2 predict inversion**: `risk_model.py:233` `np.max` → `proba[1]` + categorical alignment fix, verified family-01 0.144 not 0.85, inversion test `family-01 <0.5 && family-03 >0.5` green 13/13.
- **F8 hash determinism**: `hash(env)` → `hashlib.sha256(...).hexdigest()[:8]` deterministic, guard tautology fixed, verified across PYTHONHASHSEED values.
- **Artefacts**: `models/risk_clf.pkl` 125K regenerated `PYTHONHASHSEED=0`, `eval/calibration_curve.png` 49K <5M, `pytest assessment/tests/test_risk_ablation.py -q` 13 passed junit `.omo/evidence/risk_fix.junit.xml`.
- **Remaining**: F1/F3/F4/F5 leak/circularity still disclosed (full-31 training, n_eff=10) per MUST NOT DO — separate splits fix task.
