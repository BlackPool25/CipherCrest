# Brutal Anomaly Audit — ECOD Lean Training (Day7)

> **Verdict: NOT anomaly detection. Trivial dataset separation via missingness + prior inversion. ROC>0.60 is a tautology artifact, not learned signal.**
> Date: 2026-08-25 | Auditor: Sisyphus-Junior | Target: `assessment/anomaly_model.py` @ 218 LOC | Evidence: empirical Python (PYTHONHASHSEED=0)

---

## Executive Summary

**Is it detecting anomalies or just separating missingness?**

It is **separating missingness/background**. The ECOD model does not learn anomalous TLS/certificate structure. It learns:
1. *Censys prior rows have 6 cert fields identically null* vs *lab family-01 has them populated* (single clean sample) → 11/28 columns are deterministic null proxies.
2. *Mixed ROC evaluation (lab 31 + censys 20 = 51)* pits 30 High/Critical lab positives against 20 censys Low negatives → 100% label-dataset confound. A single feature `ja4_rarity` alone achieves **AUC 0.926** (negated), beating ECOD's 0.871 without any ECOD training.
3. *Within-lab ROC* (the only honest anomaly task: separate High/Critical vs Low inside lab) → **AUC 0.23** — worse than random. ECOD cannot distinguish anomalies inside its own lab domain. It only distinguishes lab-vs-censys, which is a data-source artifact.

**Training <0.3s, scores invariant across contamination, threshold differs — all true per pyod #482 but prove nothing about quality.**

---

## Methodology

- Read: `assessment/anomaly_model.py`, `assessment/features.py`, `assessment/tests/test_anomaly_hybrid.py`, `shared/fixtures/censys_sampled_200.json`, `shared/fixtures/family-01.json`, `lab/manifest.json`
- Bash: PYTHONHASHSEED=0 empirical runs for X_train shape, censys vs lab overlap, ECOD decision_scores variance, ROC lab-only vs mixed, contamination invariance, skew warning capture, jitter diversity
- codegraph_explore: blast radius assessment/anomaly_model dependencies
- All numbers below are reproduced outputs, not estimates. Copy-paste from python runs.

---

## Finding F01 — Inverted Prior-Dominated Training (Spec Dishonesty)

**Severity: 🔴 CRITICAL — Dishonest documentation, invalidates ROC claim**

| Claim | Code | Reality |
|-------|------|---------|
| Docstring line 102: `7 censys +20 lab=27 (35% prior slice)` | Lines 118-120: `censys_slice = censys_flows[:20]` `lab_slice = lab_flows[:7]` | **20 censys +7 lab =27 → 74% prior-dominated background (inverted)** |
| Module header line 3: `lab 31 + prior 20 35% slice (7 censys +20 lab=27 train)` | Same | Header also lies |
| Comment lines 114-117: admits inversion as "prior-dominated ... to ensure weak High/Critical are outliers vs prior Low background" | — | Comment openly confesses inversion while header/docstring retain honest spec |

**Impact on ROC>0.60:**
- With 74% censys background (all y=0 Low), ECOD ECDF learns censys as normal mass. Lab High/Critical become outliers by definition of being the minority tail, not by learned anomaly structure.
- Prior-dominated background inflates trivial separation: censys (all y=0) vs lab (30/31 y=1) is a dataset boundary, not an anomaly boundary. Mixed ROC 0.871 is guaranteed when training mass = censys mass.
- Honest spec (7 censys +20 lab) would have 74% lab background → lab High/Critical would *be* the mass, censys Low would be outliers, ROC would collapse or invert. The inversion was chosen to force ROC>0.60.

**Evidence:**
```
X_train.shape=(27, 28) expected (27,28)
lab_in_train (7): ['family-01', 'family-02', 'family-02-jitter-01', ... 'family-03-jitter-01']
censys_in_train (20): ['censys_prior_0c4550a7', ...]
INVERTED? True -> YES, prior-dominated 74% censys vs spec 26%
```

**n_eff note:** lab training slice uses only 7 lab rows; with 30/31 lab positives (only family-06 Low), the 7 lab rows are 6 positives +1 Low → near-identical outlier set, no normal vs anomaly contrast.

---

## Finding F02 — ECOD on n≈p with Nearly Identical Data (Catastrophic Cancellation)

**Severity: 🔴 CRITICAL — Results unreliable per pyod's own warning, silently ignored**

- **Assumption violated:** ECOD assumes i.i.d. continuous features, feature independence, and sufficient n>>p for ECDF estimation. Training is `n=27, p=28 → n≈p ratio 0.96`. ECOD computes per-feature ECDF then sums `-log(ECDF)` across 28 dims; with n≈p and near-identical rows, skew calculation catastrophically cancels.
- **Warning fired, not handled:**
```
RuntimeWarning: Precision loss occurred in moment calculation due to
catastrophic cancellation. This occurs when the data are nearly identical.
Results may be unreliable.
  return np.nan_to_num(skew_sp(X, axis=axis))
  file: pyod/models/ecod.py:23 (twice per fit)
```
  Captured via `warnings.catch_warnings(record=True)` — **2 warnings per fit**, also reproducible as error with `warnings.filterwarnings('error')`. Code does `clf.fit(X_train)` with no handler, no filter, no log, no caveat in LEDGER.
- **Why data nearly identical:**
  - 3 columns zero-variance in training: `is_deprecated`, `handshake_success`, `alert_after_starttls` (all 0/1/0 constant across 27 rows).
  - 20 censys rows are near-identical: all share `cipher_strength=0, kex=0, cert_missing_reason=2, is_aead=1, fs_flag=1` + 6 cert cols `-1` + 6 miss `1.0`.
  - 7 lab rows: 6 of 7 are `missing` family (chain_valid -1, miss 1), only `family-01` is the sole clean sample (chain_valid 1, miss 0, days 120, chain 2, pubkey 2048). One outlier sample among 6 nulls + 20 censys nulls cannot support 28-dim ECDF.
  - ECOD skew_correction branch fires on constant skew → `np.nan_to_num` masks NaN, proceeds silently with degraded scores.

**Decision scores evidence:**
```
decision_scores_: [60.30, 8.17, 5.62, ... 2.92] mean 7.44 std 11.07 var 122.6
sorted min 2.92 max 60.30 — first row (family-01) 60.30 is 4.8σ outlier, dominates threshold
threshold 0.10 = 12.02 (solely determined by that one clean sample)
```
One clean lab sample among 26 null-heavy rows drives the entire threshold — not a distribution, a single-point artifact.

**Impact:** Per pyod docs, "Results may be unreliable" means no statistical guarantee. Test `test_fit_time_under_03s` and `test_roc_point_above_060` pass while warning is suppressed, creating false confidence.

---

## Finding F03 — Censys Prior Rows Have 11/28 Cols Missing (ECOD Learns Missingness)

**Severity: 🔴 CRITICAL — Signal is missingness indicator, not TLS anomaly**

Censys fixture admits `dataset_caveat: "prior-only, 7 cert cols synthetic null"` but audit shows **11 cols**, not 7:

For every censys row:
```
chain_valid=-1  miss_indicator_chain_valid=1
san_match=-1    miss_indicator_san_match=1
days_to_expiry=-1  miss_indicator_days_to_expiry=1
chain_length=-1    miss_indicator_chain_length=1
pubkey_bits=-1     miss_indicator_pubkey_bits=1
sigalg_weak=-1     miss_indicator_sigalg=1
is_expired=-1        (no miss indicator, still -1)
is_self_signed=-1    (no miss indicator, still -1)
keysize_weak=-1      (no miss indicator, still -1)
cert_missing_reason=2 (missing vs 0 none /1 opaque)
```
Plus 3 near-constant boolean cols → **11 deterministic missing cols** (6 with explicit miss indicator 1, 3 with implicit -1, 2 with cert_missing_reason divergence).

**Lab contrast:** Only `family-01` has `miss 0` for those 6 indicators (clean cert). All other 30/31 lab rows also have `miss 1` (synthetic jitter preserves missingness for families 02-10). So training contains **26 rows with miss=1 vs 1 row with miss=0** → ECOD's ECDF trivially scores `miss=0` as low-ECDF anomaly (high score 60.30 for family-01), while `miss=1` mass scores low.

**Proof ECOD learns missingness, not anomaly:**
- `miss_indicator_*` correlation in train: **r=1.0** among 6 indicators, `r=-0.55` with `miss_indicator_ja4_rarity` (only ja4_rarity miss is 0 for censys, 1 for 30/31 lab). This violates ECOD feature-independence assumption. ECDF sum across 6 perfectly correlated binary cols multiplies the same signal 6×.
- Censys `cipher_strength` all `0 (strong)` vs lab mix `0,1,2,3` — censys appears healthier than lab's weak ciphers, yet labeled Low vs lab High → label correlates with data source, not cipher signal. ECOD cannot learn weak cipher as anomaly because censys background has no weak ciphers to contrast.

**Target correction:** LE DGER.md should state "7 cert cols synthetic null" → actually **11 cols (9 cert-derived + 2 cert_missing_reason divergence)**, and that ECOD's dominant signal is this missingness.

---

## Finding F04 — Pseudo-Label ROC via Rule High/Critical as Outlier 1 (Trivial Separation, Not Anomaly)

**Severity: 🔴 CRITICAL — ROC>0.60 is tautology, not evidence of learning**

**Setup:**
- `y = 1 if risk_level in (High, Critical) else 0` via `evaluate` + `score` (23 rule checks, weak supervision).
- `all_flows = lab_flows (31) + censys_all (20) =51` for ROC. Training was 27, evaluation is 51 (includes 24 unseen rows — but censys unseen are identical to training censys).

**Label distribution:**
```
y_all len 51 positives 30 negatives 21  (30 High/Critical lab, 1 Low family-06 +20 Low censys)
y_lab positives 30/31  y_censys positives 0/20
censys all Low? True
```
- Censys all Low because synthetic null cert → few rule hits (no expiry, no self-signed, no weak sigalg populated) → rule scores Low by default. Lab High/Critical because families 02-10 carry weak ciphers, expired, self-signed etc.
- Therefore `y` is **perfectly collinear with data source**: `flow_id startswith censys_*` ↔ y=0, `flow_id startswith family-*` ↔ y=1 (except one). ECOD trained on 74% censys background learns "censys = normal", so any lab sample scores higher → mixed ROC high by construction.

**Empirical proof triviality:**

| Evaluation | AUC | Interpretation |
|------------|-----|----------------|
| **Mixed (51: lab+censys)** | **0.871** | What code reports; censys vs lab separation |
| **Lab-only (31: High/Critical vs Low inside lab)** | **0.233** | Honest anomaly task; **worse than random**. ECOD cannot separate families inside lab. |
| **Dummy single-feature `ja4_rarity` (negated)** | **0.926** | Simple threshold on one TLS field beats ECOD with no training |

- Lab-only per-row scores (ECOD trained on inverted 20 censys +7 lab):
```
family-06  Low      score 11.633  (the sole lab Low scores MID, not low — ranked higher than 12 High/Critical jitters)
family-01  High     score 60.144  (outlier due to being only clean cert)
family-02  High     score  6.847  (scores LOWEST despite being High)
```
Lab Low (family-06) is ranked in the middle, not as normal. Lab High jitters score 5.4-6.9 (lowest), while censys (true Low) would score ~2.9-5.7 (even lower) → within lab, ECOD ranks Low higher than many High/Critical → inverted signal.

**ROC computation correctness:** `roc_auc_score(y, scores)` with `y` mixed and `scores = decision_function` is mathematically correct (no bug in sklearn call), but **semantically incorrect** as an anomaly metric because train and eval distributions are confounded with source. No leakage in the sklearn sense (eval includes censys not in train for 0 of 20? actually 20 censys in train = all 20 censys, so eval censys are fully memorized), but aliasing: training censys are the same 20 evaluated. So 20/51 eval points are training points → optimistic bias.

**n_eff:** Lab jitter synthetic: 21 jitter from 10 base via uniform `rnd.random()` on ja4_rarity only; effective independent families ≈10, not 31. Rule-based weak supervision with n_eff=10 and 30 positives vs 1 negative gives extremely wide CI — reported point 0.871 has CI spanning below 0.60. No CI reported.

---

## Finding F05 — Contamination Invariance Test Correctness

**Severity: 🟡 LOW — Tautologically true, proves pyod plumbing, not model quality**

Test `test_contamination_invariance_scores_equal_threshold_differs`:
```python
clf05 = ECOD(contamination=0.05, n_jobs=1).fit(X)
clf20 = ECOD(contamination=0.20, n_jobs=1).fit(X)
assert np.allclose(clf05.decision_scores_, clf20.decision_scores_)  # passes
assert clf05.threshold_ != clf20.threshold_                          # 18.61 vs 5.78
assert np.allclose(clf05.decision_function(X), clf20.decision_function(X))
```

**Result on this tiny near-identical data:** `scores_05 == scores_20 True, threshold differs True, decision_function invariant True` — holds perfectly. But this is **tautological per pyod source**:

```python
# pyod/models/ecod.py fit():
self.decision_scores_ = self.decision_function(X)
self._process_decision_scores()  # only sets threshold_ from contamination quantile
# decision_function() is pure ECDF, never reads self.contamination
```

Contamination invariance is a *library invariant*, not a *model quality* property. It holds for any X, even random noise, even n=2. Passing this test on 27 near-identical rows proves `from pyod.models.ecod import ECOD` was called, nothing about lean training validity. The test is correctly implemented per pyod #482/#552, but its presence in the suite creates illusion of model validation.

**Proof via Python:** threshold 0.05 =18.62 threshold 0.20=5.78 (quantile of same score vector) → differs as expected, irrelevant to anomaly quality.

---

## Finding F06 — Feature Null Handling (build_vector)

**Severity: 🟡 MEDIUM — Null encoding is NaN-free but semantically leaks, no skew handling**

`build_vector` is NaN-free (all missing → -1 + miss_flag 1) and `len==28` with `ja4` excluded — correct per contract. Issues:

1. **Missingness double-counting:** Each nullable cert field encodes both as `-1` value *and* `miss_indicator 1`. For 6 fields this creates 12 columns encoding the same binary event. With `r=1.0` correlation among miss indicators, ECOD sums 6× the same `-log(ECDF)` term → missingness signal amplified 6× versus single TLS feature (ja4_rarity alone explains 0.926 AUC, ECOD amplifies noise).
2. **`is_expired`, `is_self_signed`, `keysize_weak`** have no `miss_indicator_*` yet are `-1` for censys/30 lab vs `0` for family-01 → leak via sentinel `-1` without indicator to downweight. ECOD ECDF sees `-1` as a valid numeric value, not missingness, so family-01's `0` appears as outlier high value.
3. **Days/pubs normalization absent in xgb mode:** `days_to_expiry` 120 vs -1 raw (not normalized) gives 121-unit gap → ECDF step at -1 dominates. 2048 pubkey_bits vs -1 raw gives 2049 gap. These raw gaps dwarf normalized ja4_rarity 0..1 signal, but because censys and 30 lab share -1, the only contrast is family-01's 120/2048 → again single-sample artifact.
4. **No imputation, no skew warning downstream:** `is_deprecated`, `handshake_success`, `alert_after_starttls` constant 0/1/0 across train → skew `NaN` in pyod, masked by `np.nan_to_num`. No feature selection to drop constant cols before ECOD.

**Severity medium because:** NaN-free guarantee is met, but null handling design directly causes F03 missingness learning.

---

## Finding F07 — Skew Warning Handling (Ignored RuntimeWarning)

**Severity: 🟠 HIGH — Silent reliability failure, documented in test logs**

- **What pyod warns:** `skew_sp(X, axis)` on nearly identical data → catastrophic cancellation → `skew` meaningless → ECDF with skew correction uses wrong sign → scores biased. Pyod docs: "Results may be unreliable."
- **What code does:** Nothing. No `warnings.catch_warnings`, no `warnings.filterwarnings('error')` or explicit handling, no log, no LEDGER caveat, no feature preprocessing to avoid cancellation. Test `test_fit_time_under_03s` uses `warnings` not checked; `pytest -W error` would fail the suite.
- **Reproduced:** `warnings.filterwarnings('error')` + `clf.fit(X_train)` raises `Warning: Precision loss occurred ...`. Normal run emits 2 RuntimeWarnings silently (visible only with `-W always`).
- **Impact:** At n=27 p=28 with 3 constant cols and 20 identical censys rows, skew is computed on degenerate distribution; ECOD's skew-corrected ECDF (`if skew >0 use ECDF else 1-ECDF`) may flip incorrectly for those cols, but since `skew` is NaN→0 via `nan_to_num`, correction defaults arbitrary. Test passes but model is statistically unsound.

**Fix (recommendation, not applied per MUST NOT):** Drop zero-variance cols before ECOD, or log warning and document unreliability, or switch to non-skew detector (e.g., Isolation Forest with proper contamination) for lean n≈p.

---

## Finding F08 — _load_lab_flows Deterministic Jitter via `random.Random(seed)` with `ja4_rarity` Uniform

**Severity: 🟡 MEDIUM — Synthetic diversity fake, preserves cipher strength but adds no real signal**

- **Claim in code line 52-78:** "sample ja4_rarity 0..1 and expiry jitter to give ECDF variance for ROC>0.60 while keeping lean. Never raw ja4."
- **Reality:**
  - Jitter calls `random.Random(seed).random()` uniform 0..1 for `tls.ja4_rarity` only. Other 27 cols **identical** within family across 3 jitters (except `miss_indicator_ja4_rarity` flips 1→0). Checked for family-02:
```
family-02-jitter-01 differing vs base: [('ja4_rarity', 0.379), ('miss_indicator_ja4_rarity', -1.0)]
family-02-jitter-02 differing vs base: [('ja4_rarity', 0.096), ('miss_indicator_ja4_rarity', -1.0)]
family-02-jitter-03 differing vs base: [('ja4_rarity', 0.254), ('miss_indicator_ja4_rarity', -1.0)]
```
  Only ja4_rarity varies; `days_to_expiry` jitter mentioned in comment is **not implemented** (code has `flow["cert"] = dict(...)` but no `days_to_expiry` randomization; comment says "keep honest: if leaf_present false, days stays None" so expiry jitter skipped for 30/31 rows anyway).
  - `rnd.random()` uniform destroys any cipher-strength correlation: family-02 (strong cipher) gets 0.09, 0.59, 0.75 equally spaced — no correlation with real ja4 rarity distribution (censys spans 0.02..0.996 with structure). ECDF variance added is white noise, not cipher-signal diversity.
  - Determinism via `hashlib.sha256(env_id).hexdigest()[:8]` is correctly deterministic (PYTHONHASHSEED=0 also set), but synthetic variance is still fake: 21 jitter rows from 7 families ×3 identical-until-ja4_rarity.

- **Impact on ROC:** Fake ja4_rarity variance gives ECOD's ECDF something to spread across, preventing 0-variance ECDF degenerate case for that column, and creates artificial spread that correlates with y via uniform noise rather than real TLS diversity. This is why mixed ROC reaches 0.871 despite lab-only 0.233 — the ja4_rarity uniform noise separates censys (high 0.93 mean) from lab jitters (uniform 0..1 mean 0.5) more than it separates lab High vs Low.

**Honest description** should be: "Jitter adds uniform 0..1 ja4_rarity noise to 21 synthetic rows; no cipher/certificate diversity; ECDF variance is synthetic, not empirical."

---

## Finding F09 — Training <0.3s Not Evidence of Quality

**Severity: 🟢 LOW — True but vacuous**

Measured elapsed `0.206s` on 27×28 fit. At n=27, any detector fits <0.3s; bound is not discriminating (kNN, IF, LOF all <0.1s). Test `test_fit_time_under_03s` passes trivially. No quality implication; should not be presented as lean success evidence without accompanying statistical validity.

---

## Additional Notes

- **codegraph blast radius:** `build_vector` has 16 callers, `score` 15 callers, `evaluate` 21 callers — changing feature null handling affects risk_model, policy, and all tests.
- **Censys fixture integrity:** `censys_sampled_200.json` is actually **20 rows** (not 200) per T4 learnings; filename misleading but correctly noted in tests (`test_lean_20_rows_not_200`). All 20 prior_flag true, dataset_caveat present, correctly used.
- **Lab manifest:** 31 envs (10 base +21 jitter) verified, jitter envs `family-0X__jitterY_loss5` with capture_epoch 2026-08-27T00:00:00Z, sha + GREASE distinct per slice (T1 evidence). Manifest honest; anomaly_model jitter generation is synthetic in-memory, not from pcaps, so manifest diversity not reflected in anomaly features.
- **No modification of `anomaly_model.py` per MUST NOT** — recommendations below are for future fix, not applied.

---

## Fix Recommendations (Priority Order)

1. **🔴 Honest training composition or separate evaluation** — Either restore spec `7 censys +20 lab` and report honest ROC (expected ~0.5-0.6, disclose), or keep prior-dominated but evaluate ROC **lab-only with group-aware CI** and report mixed ROC as "dataset separation, not anomaly". Update docstrings/LEDGER to match code. Add explicit `train_test_disjoint` assertion (censys IDs not in eval beyond train).

2. **🔴 Drop zero-variance + constant miss indicators before ECOD** — Filter `is_deprecated`, `handshake_success`, `alert_after_starttls` and deduplicate correlated miss indicators (keep 1 of 6, or PCA). Or replace ECOD with contamination-invariant Isolation Forest for n≈p lean. Re-run with warnings as errors and assert no RuntimeWarning.

3. **🔴 Evaluate honest anomaly, report lab-only AUC + CI** — Change `train_and_save` ROC to `lab` only (or stratified group k-fold), compute DeLong or bootstrap CI at n_eff=10, report `AUC 0.23 (lab-only) vs 0.87 (mixed artifact)`. Stop claiming >0.60 as quality gate.

4. **🟠 Handle skew warning** — Wrap `clf.fit` with `warnings.catch_warnings` and log or fail; document "Results may be unreliable" in `.omo/evidence` and LEDGER honesty annex. Alternatively preprocess: standardize or cap degenerate cols.

5. **🟡 Fix jitter diversity** — Preserve cipher strength signal: sample ja4_rarity from per-family empirical distribution (e.g., from censys_top_ja4.json per cipher) not uniform 0..1; or add real jitter to cipher/KEX/expiry via lab pcaps. Document synthetic nature and limit to 1 jitter dim.

6. **🟡 Consolidate null handling** — Use single missingness embedding (e.g., -1 + indicator for 6 cols is 12 cols; replace with 6 cols via imputed -1 only or indicator only, not both). Normalize days/pubkey in xgb mode to bound gaps.

7. **🟢 Remove <0.3s as quality evidence** — Keep as performance guard, not as anomaly success claim.

---

## Evidence Reproduction (Copy-Paste Commands)

```bash
PYTHONHASHSEED=0 python3 << 'PY'
from assessment.anomaly_model import _build_training_matrix, _load_lab_flows, _load_censys_flows, _pseudo_labels
from assessment.features import build_vector, FEATURES_28
from sklearn.metrics import roc_auc_score
import numpy as np, warnings

lab=_load_lab_flows(); censys=_load_censys_flows()
X_train,_,_ = _build_training_matrix()
print("X_train", X_train.shape)  # (27,28)
print("censys miss all 1?", all(build_vector(f,mode="xgb")[FEATURES_28.index("miss_indicator_chain_valid")]==1 for f in censys))

# Warning capture
with warnings.catch_warnings(record=True) as w:
    warnings.simplefilter("always")
    from pyod.models.ecod import ECOD; ECOD(contamination=0.10,n_jobs=1).fit(X_train)
    print("warnings", len(w), [str(x.message)[:60] for x in w])

# ROC lab-only vs mixed
from pyod.models.ecod import ECOD; import warnings; warnings.filterwarnings("ignore")
clf=ECOD(contamination=0.10,n_jobs=1).fit(X_train)
y_lab=_pseudo_labels(lab); y_all=_pseudo_labels(lab+censys)
X_lab=np.array([build_vector(f,mode="xgb") for f in lab]); X_all=np.array([build_vector(f,mode="xgb") for f in lab+censys])
print("lab-only AUC", roc_auc_score(y_lab, clf.decision_function(X_lab)))  # 0.23
print("mixed AUC", roc_auc_score(y_all, clf.decision_function(X_all)))      # 0.87

# Contamination invariance
X=X_train
a=ECOD(contamination=0.05,n_jobs=1).fit(X); b=ECOD(contamination=0.20,n_jobs=1).fit(X)
print("scores equal", np.allclose(a.decision_scores_, b.decision_scores_), "thr", a.threshold_, b.threshold_)
PY
```

---

## Severity Summary Table

| ID | Title | Severity |
|----|-------|----------|
| F01 | Inverted 20+7 prior-dominated training, docstring dishonesty, ROC inflated | 🔴 CRITICAL |
| F02 | ECOD n≈p (27×28) catastrophic cancellation, RuntimeWarning ignored, unreliable | 🔴 CRITICAL |
| F03 | 11/28 cols missing (6 null +6 miss r=1.0), ECOD learns missingness not anomaly | 🔴 CRITICAL |
| F04 | Pseudo-label ROC on mixed 30 lab positives vs 20 censys negatives trivial, lab-only 0.23, dummy ja4_rarity 0.926 | 🔴 CRITICAL |
| F07 | Skew warning not handled, silent reliability failure | 🟠 HIGH |
| F06 | Feature null double-counting, sentinel gaps, no variance filter | 🟡 MEDIUM |
| F08 | Jitter uniform ja4_rarity 0..1 fake diversity, no cipher/expiry jitter | 🟡 MEDIUM |
| F05 | Contamination invariance tautologically true, not quality evidence | 🟡 LOW |
| F09 | <0.3s vacuous for n=27 | 🟢 LOW |

---

## Honesty Annex Update (for LEDGER.md)

> ECOD lean training is **prior-dominated background separation**, not anomaly detection. 20 censys +7 lab (74% prior) inverted vs spec 35%; censys 11/28 cols synthetic null with 6 miss indicators r=1.0; ECOD sees n≈p 27×28 with 3 constant cols → RuntimeWarning catastrophic cancellation (2 per fit) ignored; mixed ROC 0.871 is trivial dataset artifact (lab-only ROC 0.233, single-feature ja4_rarity 0.926); contamination invariance holds tautologically per pyod #482; jitter adds uniform 0..1 ja4_rarity noise only. Results unreliable per pyod; Day8-10 must fix composition, variance filtering, and lab-only evaluation with n_eff=10 CI.

---

*Generated for `.omo/notepads/sih26159-till-day7-lean-ml-bridge/brutal-anomaly-audit.md` — DO NOT modify anomaly_model.py per audit scope.*
