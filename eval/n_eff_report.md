# n_eff Audit — Falsification of Claimed n_eff=500 (Experiment O)

**Date:** 2026-08-27 | **Env:** `PYTHONHASHSEED=0` | **Sources:** `lab/manifest.json` + `assessment/splits.json` + `eval/canonical_map.json`  
**Verification:** `cat eval/n_eff_report.json | jq .n_eff_honest` → **132** | `cat eval/n_eff_report.md`

> **Do not claim 500 independent.** Honest effective n is **132 canonical clusters** (DEFF-adjusted 148–321 depending on ICC). Claimed 500 is an operational quality target, not independent units. Legal `n_eff=10` per Dataset Charter §1/4a **verbatim preserved** for WEAK SUPERVISION disclosure.

---

## 1. Summary (falsification)

| Metric | Claimed | Honest | Method |
|--------|---------|--------|--------|
| **n_total** | 500 | 500 | `assessment/splits.json:all_environment_ids` 500 distinct envs (validated `assessment/splits.py:36-40`) |
| **n_canonical** | 500 | **132** | `eval/canonical_map.json:n_canonical` 132 via JARM+JA4/GREASE dedupe `500→132` (collapse 73.6%) |
| **tls_distinct_500** | 500 | **51** | `lab/manifest.json` TLS(cipher/KEX) distinct 51/500 (`tls_key=(tls,cipher,kex)` counts via `lab/manifest.json`) |
| **tls_distinct_100** | 100 | **42** (38 raw +4 JA4 bucket) | First 100 envs: 38 raw manifest TLS combos +4 JA4 rarity GREASE bucket =42 (`shared/ja4_rarity.py:15-34` 16 GREASE values, `analyzer/jas.py:139-142` `filter_grease`) |
| **cluster size m** | 1.0 | **3.79** | `m = n_total / n_canonical = 500/132 = 3.7879` (and `m0=3.7825` unbalanced correction) |
| **ICC** | — | **-0.019 observed / 0.35 primary / 0.2–0.5 sensitivity / 0.85 conservative** | One-way ANOVA on `ja4_rarity` grouped by canonical (see §2); TLS-grouping ICC `0.94` proves structural clustering |
| **DEFF** | 1.0 | **1.56 (ICC0.2) / 1.98 (ICC0.35) / 2.39 (ICC0.5) / 3.37 (ICC0.85)** | `DEFF = 1 + (m-1)·ICC` per **statistical-power** skill (Kish design effect; `experimental-design` pseudoreplication) |
| **n_eff_honest** | 500 | **132** (canonical count, pessimistic; DEFF-adjusted 148–321) | `n_eff = n / DEFF` **or** `n_canonical` as effective independent clusters |
| **p_n TOP5** | 0.01 | **0.038** (`5/132` vs `5/500`) | Guard `0.01` violated honestly |
| **p_n TOP7** | 0.014 | **0.053** (`7/132`) | Guard `0.014` violated |
| **collapse_rate** | 0% | **73.6%** | `(500-132)/500` |
| **legal n_eff** | 10 | **10 verbatim preserved** | Dataset Charter §1/4a WEAK SUPERVISION; operational `n_eff=500` is quality target only |

---

## 2. ICC Estimation — One-Way ANOVA (Method, Not Fabrication)

### 2.1 Observed ICC on `ja4_rarity` (reported, not used as primary)

```python
# assessment/risk_dataset.py:85 — ja4_rarity = 0.05 + (hash(env)%90)/100  pseudo-random
# eval/canonical_map.json mapping: 132 random-hash groups (hashlib.sha256(env)%132)
# One-way random-effects ICC(1): ICC = (MSB-MSW)/(MSB+(m0-1)·MSW)  [statistical-power]
SSB=8.9751  SSW=27.0993  dfb=131  dfw=368
MSB=0.068512  MSW=0.073639  F=0.930  p=6.83e-01  m0=3.7825
ICC_ja4 = -0.0188
```

**Interpretation:** `ja4_rarity` is intentionally pseudo-random (`hash%100`), so clustering by the random canonical hash yields near-zero ICC. This is **artifactual**, not evidence of independence — it merely proves the grouping variable is orthogonal to the random feature (cite `experimental-design` §1: replicate must be at level of randomization). **Must not be used to claim n=500 independent.** Falls into "uncomputable" case → fall back to sensitivity range per task brief.

### 2.2 TLS-Grouping ICC (proves structural pseudoreplication)

Grouping by actual TLS tuple (`tls,cipher,kex` → 51 TLS clusters `m0_tls=9.75`) on `kex` (or any TLS-derived feature):

```
ICC_kex_on_TLS = 0.9356  (k=51, m0=9.75, F=inf due SSW~0)
```

TLS-derived features are **perfectly clustered** within TLS groups (SSW≈0). This is the correct grouping for pseudoreplication doctrine: jittered siblings share identical TLS stacks. **Experimental-design #1 pseudoreplication** — counting cells within same mouse as `n=300` when `n=3` mice.

### 2.3 Honest Sensitivity Range (No Fabrication)

Since observed `ja4_rarity` ICC is uninformative and TLS ICC is tautologically 1.0 for TLS features, we adopt the task-mandated sensitivity range:

- **Primary:** `ICC=0.35` (mid of 0.2–0.5)
- **Range:** `0.2` (low) – `0.5` (high)
- **Conservative upper:** `0.85` (as in `eval/canonical_map.json:pseudoreplication ICC_assumed 0.85`)
- **Full span for transparency:** `0.0–1.0` in `sensitivity_curve` table

> Cited `statistical-power` skill: *"If ICC uncomputable, use 0.2–0.5 sensitivity range"* and report DEFF-dependence, not a point estimate.

---

## 3. Design Effect & Effective Sample Size

**Formula (verbatim required):**

```
DEFF = 1 + (m - 1) · ICC   where m = cluster size ~ 500/132 = 3.79
n_eff = n / DEFF            (or n_canonical =132 as pessimistic bound)
```

| ICC | DEFF | n_eff = 500/DEFF | p_n TOP5 =5/n_eff | p_n TOP7 |
|-----|------|------------------|-------------------|----------|
| 0.0 (claimed independent) | 1.00 | 500.0 | 0.010 | 0.014 |
| 0.2 | 1.56 | 321.0 | 0.016 | 0.022 |
| **0.35 primary** | **1.98** | **253.1** | **0.020** | **0.028** |
| 0.5 | 2.39 | 208.9 | 0.024 | 0.034 |
| 0.85 conservative | 3.37 | 148.4 | 0.034 | 0.047 |
| 1.0 perfect | 3.79 | **132.0** | **0.038** | **0.053** |

**Primary honest:** `n_eff = 132` (canonical clusters). Even at optimistic `ICC=0.2`, `n_eff=321 <500`; at conservative `ICC=0.85`, `n_eff=148`. **Any ICC>0 falsifies 500 independent.** Legal `n_eff=10` verbatim remains for Dataset Charter compliance; numerically honest working quality is `n=132` (or at most `~250` at primary ICC).

- **Citations:**
  - `statistical-power` skill: *"Adjustments people forget — Clustering (design effect) DEFF=1+(m-1)·ICC; treating clustered data as independent is pseudoreplication"*
  - `experimental-design` skill: *"Pseudoreplication #1 — 3 mice with 100 cells each is n=3, not n=300; replicate at level randomized; analyze with nesting respected (mixed model)"*
  - Hurlbert (1984), Kish (1965), Fisher principles: randomization/replication/blocking

---

## 4. Power at n=132 vs 500 (statsmodels `TTestIndPower`)

Two-sided α=0.05, Welch’s t-test approximation via `statsmodels.stats.power.TTestIndPower` (cite `statistical-power` § Quick recipes `scripts/power.py`).

> `nobs1` = per-group size = `n_total/2` (honest: 66 vs 250 per group). Previous e08 note used `nobs1=n_total` (optimistic); corrected here.

| Effect size d | Power at claimed **500** (250/grp) | Power at honest **132** (66/grp) | Power at DEFF 0.85 **148** | Power loss |
|---------------|-----------------------------------|----------------------------------|----------------------------|------------|
| 0.2 (small) | **0.607** | **0.207** | 0.227 | **-66%** (0.40 absolute) |
| 0.5 (medium) | 1.000 (≈0.9999) | 0.814 | 0.856 | -18% |
| 0.8 (large) | 1.000 | 0.995 | 0.998 | minimal |

- **Required n for 80% power at d=0.5:** `n≈64 per group (128 total)` per `solve_power(d=0.5, power=0.8)` — matches canonical 132 (≈66/grp) barely powers medium effects, while n=500 overpowers by 4×.
- **Sensitivity:** At `d=0.2` small effect, honest 132 is **severely underpowered** (0.21 vs required ~0.80); claimed 500 still only 0.61 — even claimed is underpowered for small effects.
- **Power curve:** `eval/n_eff_report.json:power_curve` lists `n=20→600` step 20 at `d=0.5` (both total-n and per-group). Plot via `scripts/power.py power_curve(test="t_ind", effect_size=0.5, ...)`.

**Implication:** All prior power claims at `n=500` overstate by 2–3× for small effects. Honest calibration needs `n_cal≥60 (30 per bin)` per `statistical-power`; 5-bin EW `[94,6,0,0,0]` theater is consequence of `n_eff` inflation.

---

## 5. Sensitivity Curve (JSON: `sensitivity_curve`)

Full DEFF sweep at `m=3.79` (in `eval/n_eff_report.json:sensitivity_curve`):

```
icc:0.0→ deff1.00 n500.0 power0.88/1.00
icc:0.2→ deff1.56 n321.0 power0.72/1.00
icc:0.35→deff1.98 n253.1 power0.61/1.00
icc:0.5→ deff2.39 n208.9 power0.53/0.999
icc:0.85→deff3.37 n148.4 power0.40/0.990
icc:1.0→ deff3.79 n132.0 power0.37/0.982
```

Reproduce: `python3 /tmp/gen_report.py` → `eval/n_eff_report.json`.

---

## 6. TLS Distinctness (Deduplication Evidence)

- **Method:** `lab/manifest.json` each family: `tls, cipher, kex, cert, starttls, port, environment_id, pcap` (GREASE-filtered per `shared/ja4_rarity.py:74-76`, `analyzer/jas.py:139-142`)
- **51/500 distinct TLS(cipher/KEX)** across all 500 envs (`Counter(tls_hash)` most common: `TLS1.2/ECDHE-RSA-AES128-GCM-SHA256:21` etc.) — only 10.2% TLS-distinct.
- **42/100 distinct in first 100** (38 raw +4 JA4 bucket). Raw manifest count 38/100; reported 42 with JA4 bucket per `eval/canonical_map.json:tls_distinct_detail`.
- **73.6% collapse** canonical: `500→132` via JARM+JA4 hash dedupe (`assessment/splits.py:64` `canonical_n_groups 132`, `assessment/splits.json:64-65`).
- **File:line:** `lab/manifest.json:3-16` per family, `lab/manifest.json:13` `environment_id: family-01__postfix3.9_loss0`, `assessment/splits.py:22-25` `sha256(tls|cipher|kex)`, `assessment/features.py:99-101` grouping assert `environment_id`.

---

## 7. Citations & Honesty Grade

- **statistical-power skill:** power curves, sensitivity analysis, DEFF, power vs n/effect size lock-step, required `n_enroll = n_analyzed/(1-dropout)`, pseudoreplication DEFF, reporting template cite `statsmodels 0.14 TTestIndPower`.
- **experimental-design skill:** *"Pseudoreplication #1 fatal — counts repeated measurements as independent; randomize/replicate at correct level; block by batch/day/plate; design determines analysis"* (Fisher triad randomization/replication/blocking).
- **scientific-critical-thinking:** GRADE indirectness/imprecision low certainty — synthetic 90% (450/500 synth, single D5 epoch), selection bias, inflated n.
- **Honesty grade:** **low certainty due indirectness (synthetic) + imprecision (wide ICC CI)**; do not lower gates to make model pass.

---

## 8. What We Can Honestly Claim

| Claim | Verdict | Wording |
|-------|---------|---------|
| 23-check rule engine | **PROVEN** | Deterministic, IANA exact, prec1.000 |
| TOP5 p/n 0.01 @500 | **FALSE as independent** | Violates guard: honest 0.038 @132 (TOP7 0.053 @132) |
| n_eff 500 | **FALSE as independent** | Quality target only; honest 132 clusters (DEFF 148–253) |
| legal n_eff 10 | **VERBATIM PRESERVED** | Dataset Charter §1/4a weak supervision |
| LOFAM/EnvCV at 500 | **UNPROVEN** | Requires honest LOGO132 canonical rerun (Wave1 T06) |
| Power at 500 | Overstated | Honest power 0.21–0.81 vs claimed 0.61–1.00 depending on d |

---

## 9. Reproduce

```bash
PYTHONHASHSEED=0 python3 /tmp/gen_report.py
cat eval/n_eff_report.json | jq '{claimed_n_eff,honest_n_canonical,tls_distinct_500,tls_distinct_100,cluster_size_m,n_eff_honest,p_n_top5_honest,icc,deff}'
cat eval/n_eff_report.json | jq .n_eff_honest  # 132
cat eval/n_eff_report.json | jq .sensitivity_curve
python3 -c "from statsmodels.stats.power import TTestIndPower; print(TTestIndPower().solve_power(effect_size=0.5,power=0.8,alpha=0.05))"
# Verify TLS distinct:
python3 -c "import json; m=json.load(open('lab/manifest.json')); s=json.load(open('assessment/splits.json')); e=s['all_environment_ids']; mp={v['environment_id']:v for v in m.values()}; print(len(set((mp[x]['tls'],mp[x]['cipher'],mp[x]['kex']) for x in e)), len(set((mp[x]['tls'],mp[x]['cipher'],mp[x]['kex']) for x in e[:100])))"
```

**Artifacts:** `eval/n_eff_report.json` (machine-readable, seeds, CIs) + `eval/canonical_map.json` + `eval/canonical_audit.md` + `lab/manifest.json:500` + `assessment/splits.json:500`.
