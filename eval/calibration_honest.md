# Calibration Honesty — CipherCrest Experiment N (eval/metrics.json n_val=100)

**Status:** NOT CALIBRATED — withhold headline ECE 0.033. Honest ECE is quantile 0.062 (Δ 0.029) / kernel 0.085.  
**Date:** 2026-08-27 | **Plan:** `.omo/plans/ciphercrest-hostile-audit.md` T08 (Wave 2 — Calibration & Human)  
**Method:** Platt sigmoid `cv=2` only — **no isotonic at n<1000** per plan guard (would overfit step-function with 60% empty bins).  
**Skills:** `statistical-analysis` assumption checks + `model-evaluation-report` Step 6 calibration + `statistical-power` sample-size + `ciphercrest-ml-auditor` gated rule.

---

## 1. Bottom Line (2–3 sentences)

Headline `ECE EW 5-bin 0.033` is **theater**: it is dominated by one bin containing 82/100 points, while 4 of 5 bins have `n<12` and 2000-boot CIs of `[0,1]`. Honest estimates are `quantile-5 ECE 0.062` (equal-mass `[20×5]`) and `SmoothECE kernel 0.085` (Silverman Nadaraya-Watson) — both >EW by Δ 0.029 / 0.052, with `min_per_bin_ok = false`, `gated honest = 3 bins`, and `n_cal=100` underpowered for 5 bins (requires ≥150). `Brier 0.069` (`joint 0.073 < base 0.098`) shows skill, but reliability `0.013` is 19% of Brier, resolution `0.039` vs uncertainty `0.098` indicates limited sharpness beyond weak-supervision replication.

---

## 2. Numbers That Matter (eval/metrics.json n=100 + n=500 theater disclosure)

| Metric | n=100 (current honest val) | n=500 theater | Note |
|--------|---------------------------|---------------|------|
| **EW 5-bin counts** | `[3, 3, 5, 7, 82]` | `[94, 6, 0, 0, 0]` | 60% empty at 500; EW counts collapse to 2 occupied bins |
| **Quantile 5-bin counts** | `[20, 20, 20, 20, 20]` equal-mass | — | Honest equal-mass; still 20/bin <30 required |
| **EW 5-bin edges** | `[0,0.2,0.4,0.6,0.8,1.0]` | same | |
| **Quantile edges** | `[0, 0.836, 0.964, 0.969, 0.973, 1.0]` | — | Concentration 0.96–0.97 due to overconfident probs |
| **ECE EW** | **0.033** (`0.0332`) | 0.033 (theater) | Dominated by bin5 82 points, masks tail error |
| **ECE quantile** | **0.062** (`0.0619`) | — | Equal-mass removes concentration bias |
| **Δ EW–quantile** | **0.029** | 0.029 | `model-evaluation-report` flag `|EW-quantile|>0.03` skew — **borderline, flag anyway due to [0,1] CIs** |
| **ECE kernel (SmoothECE Silverman)** | **0.085** (`0.0848`) `h=0.018` | 0.085 | Nadaraya-Watson Gaussian `h=0.9·min(σ,IQR/1.34)·n^-1/5`; `Δ kernel–hist 0.052` proves histogram underestimates |
| **ECE macro per-class** | **0.030** (`low 0.045 / med 0.020 / high 0.024`, spread `0.025`) | same | Per-class worst `low 0.045` — low-risk class most miscalibrated |
| **ECE debiased O(n^-1/3)** | `0.007` (`0.0066`) | — | NeurIPS 2024 9961 `bias≈0.15·√k·n^-1/3`; debiased near 0 suggests raw ECE inflated by small-n bias |
| **Brier** | `0.069` (`0.0687`) | — | Joint `0.073` < base `0.098` (also `0.22` joint base for 3-class joint) |
| **Brier decomposition (Murphy `Brier = REL − RES + UNC`)** | `REL 0.013 / RES 0.039 / UNC 0.098` | — | `REL 19%` of Brier indicates miscalibration; `RES 0.039` modest sharpness; `UNC 0.098` irreducible (`p̄=0.11` → `0.11·0.89`) |
| **Brier 95% CI (2000 family bootstrap)** | `[0.040, 0.094]` `width 0.055` | — | Non-overlap with base `0.098`? Upper `0.094 < 0.098` borderline |
| **ECE 95% CI (2000 family bootstrap)** | `[0.047, 0.113]` `width 0.065` | — | Headline `0.033` lies **outside** its own CI — theater signature |
| **Mean per-bin CI width EW** | `0.346` | — | `[0,1]` bins drive mean wide |
| **Mean per-bin CI width quantile** | `0.34` | — | Even quantile width `0.40` at `20/bin` proves n=100 insufficient |

### Why `[94,6,0,0,0]` at n=500 is theater vs `[3,3,5,7,82]` at n=100 — 60% empty trick

*Equal-width (EW) bins* partition `[0,1]` uniformly. When predicted probabilities concentrate near 1.0 (overconfident XGB stump + Platt on weak labels), almost all points fall in bin 5 `[0.8,1.0]`. At synthetic `n=500` the model outputs `94` points in `[0.8,1.0]`, `6` in `[0.0,0.2]`, `0` in `[0.4,0.6]`, `[0.6,0.8]`, and partially `0` elsewhere — **60% of bins empty** (`3/5`). ECE is then `Σ |acc−conf|·n_bin/N` over *only occupied bins*; empty bins contribute `NaN` (not 0.5) so ECE ignores the missing region entirely — it reports error only where data exists, which is exactly where the model is tautologically calibrated (high-confidence tail). This is **empty-theater**: high occupancy in one bin is mistaken for good calibration.

At `n_val=100` the artifact persists differently: counts `[3,3,5,7,82]` have **no zero-count bins** but 4/5 bins have `n < 12` (the `ciphercrest` gate). Their 2000-boot CIs are `[0,0]`, `[0,1]`, `[1,1]`, `[0.33,1.0]` — widths `0`, `1.0`, `0`, `0.67`. Only bin5 (`82`) has honest width `0.06`. So the same theater recurs at finer granularity: headline `0.033` is still driven by bin5 concentration, while tails are statistically unidentifiable.

**Quantile 5-bin `[20×5]`** fixes occupancy by choosing edges at quantiles (`0, 0.836, 0.964, 0.969, 0.973, 1.0`) so each bin has exactly `20` points. This removes empty-theater and reveals `ECE 0.062`, Δ `0.029` higher (borderline `>0.03` skew flag per `model-evaluation-report`). **Kernel `0.085`** (Silverman `h≈0.018`, Nadaraya-Watson) gives a continuous estimate without binning — `Δ 0.052 vs hist` — and falls **outside** EW's CI `[0.047,0.113]`? Actually `0.085 ∈ [0.047,0.113]` so it is *within* family CI but the signed gap proves directional underestimation by the histogram (kernel > hist).

Per `model-evaluation-report` Step 6: *always* report quantile alongside EW and flag `|EW−quantile|>0.03` as skew; *always* report kernel vs histogram gate at `n=120 3-bin [5,5,5]` vs `n=200 5-bin 12/bin`; *never* headline ECE without per-bin CI.

---

## 3. Per-Bin CIs (honest — MUST NOT be omitted)

### EW 5-bin (uniform [0,0.2,...,1.0]) — n=100, 2000 family-bootstrap per bin

| Bin | Range | Count | CI lo | CI hi | Width | Verdict |
|-----|-------|-------|-------|-------|-------|---------|
| 1 | [0.0,0.2] | 3 | 0.00 | 0.00 | 0.00 | degenerate — 3 points, CI collapses, NaN theater |
| 2 | [0.2,0.4] | 3 | 0.00 | 1.00 | **1.00** | **uninformative** — interval covers entire probability |
| 3 | [0.4,0.6] | 5 | 1.00 | 1.00 | 0.00 | degenerate at boundary |
| 4 | [0.6,0.8] | 7 | 0.33 | 1.00 | **0.67** | uninformative |
| 5 | [0.8,1.0] | 82 | 0.918 | 0.983 | 0.064 | only honest bin; drives headline |

**Interpretation:** 4/5 bins have uninformative or degenerate CIs — headlined `0.033` is not justified. `statistical-analysis` assumption check: *per-bin* CI per group requires visual + width reporting; here widths `[0,1]` violate "CI width <0.3" bar.

### Quantile 5-bin (equal-mass 20 each) — n=100

| Bin | Range (quantile edge) | Count | CI lo | CI hi | Width | Verdict |
|-----|----------------------|-------|-------|-------|-------|---------|
| 1 | [0.00,0.836] | 20 | 0.35 | 0.75 | 0.40 | underpowered — width 0.40 >0.30 |
| 2 | [0.836,0.964] | 20 | 0.45 | 0.85 | 0.40 | underpowered |
| 3 | [0.964,0.969] | 20 | 0.55 | 0.95 | 0.40 | narrow quantile edge; still wide |
| 4 | [0.969,0.973] | 20 | 0.60 | 1.00 | 0.40 | underpowered |
| 5 | [0.973,1.00] | 20 | 0.88 | 1.00 | 0.12 | better powered tail |

Quantile removes empty-theater but **still fails** `statistical-power` gate: `20/bin < 30` required for `5-bin`; width `0.40` proves imprecision. See §5.

---

## 4. Gated Logic (`min_per_bin >=12 else 3` — ciphercrest honest)

```
Rule: n_bins = min(5, max(2, n_cal//5))  → at n=100 → 5
      if min(bin_counts) < 12 and n_bins > 3: downgrade to 3 bins (honest)
```

- EW `[3,3,5,7,82]` → `min=3 <12` → **should be 3 bins**, not 5. Current `eval/metrics.json gaged_n_bins=5 (ok)` is *lenient*; honest gated = **3**.
- At `n=120` → `3-bin [5,5,5]? Wait formula: 120//5=24→min(5,24)=5 but gate forces 3-bin `[40,40,40]`? Historical gate in plan: `n=120 3-bin [5,5,5]` was Day13 lean `n_val=15` illustration; at `n=200 → 5-bin 12/bin` honest. The plan gate string `n=120 3-bin [5,5,5] vs 200 5-bin 12/bin` is shorthand for the 3-vs-5 regime boundary (≈`n=60` for 3-bin, `n=150` for 5-bin at `30/bin`).

**Report honestly:** `min_per_bin_ok: false` (min 3), `gated_bins: 3 vs 5` (honest 3, reported 5 = theater). Any claim using 5 bins at `n=100` must be caveated as **theater**; publish the 3-bin gated ECE instead.

---

## 5. Sample-Size Gate — Why `n_cal=100` Is Underpowered (statistical-power)

| Goal | Formula | Required n | Current n=100 | Verdict |
|------|---------|------------|---------------|---------|
| 3-bin honest | `3 × 30/bin` | **60** | 100 (33.3/bin EW, 20/bin quantile) | **Pass for 3-bin EW average, fail for quantile 20/bin** — but EW tail still 3 |
| 5-bin honest | `5 × 30/bin` | **150** | 100 | **Fail — need +50** |
| Detect `|acc−conf|>0.10` at `α=0.05, power 0.80` per bin | `p(1−p)·(Z_{1−α/2}+Z_{power})² / δ² ≈ 0.25·7.85/0.01 ≈ 196` for `δ=0.10` worst-case | **~30** per bin for `δ=0.20` → `150` total | `3–7` in tails | **Power <0.4 in tails** |
| Budget for next milestone | Enroll `n_cal=200` → `5-bin 40/bin` honest vs `n=150` lean | `150–200` | — | Recommend `n_cal≥150` before claiming 5-bin calibration |

`statistical-power` references: *`n_ca ≥60` (`30 per bin`) is minimum for 3 bins; don’t claim calibration with `[0,1]` CI* — Day13 lean used `3-bin [5,5,5]` at `n_val=15` as explicit honest theater label, not as evidence.

**Power guidance cited in JSON:** `statistical-power §n_cal≥60 (30 per bin)` — consistent with plan `§6`.

---

## 6. Brier Decomposition (Murphy `Brier = REL − RES + UNC`)

```
Brier (point) 0.069  Joint 0.073  Base 0.098  (also joint base 0.22 for 3-class joint)
REL 0.013  RES 0.039  UNC 0.098
Check: 0.013 − 0.039 + 0.098 = 0.072 ≈ joint 0.073 ✓ (rounding)
```

- **REL 0.013** (reliability) — calibration error component (≈19% of Brier) — non-zero, corroborates ECE miscalibration despite low headline.
- **RES 0.039** (resolution) — discrimination gain over base rate; modest vs `UNC 0.098`; indicates model separates outcomes only weakly beyond base rate (weak-supervision circular: labels from same features).
- **UNC 0.098** — irreducible variance at `p̄≈0.11` (`0.11·0.89=0.098`); for 3-class joint `0.22` reflects balanced-class entropy.

`Brier 0.069 < base 0.098` proves *skill* vs naïve prevalence, but `REL/RES` ratio `0.013/0.039≈0.33` shows one-third of resolution is consumed by miscalibration — not well-calibrated in the decision-theoretic sense (good Brier ≠ good calibration). See `assessment/risk_metrics.py:brier_decomposition` (`tfp.stats.brier_decomposition` fallback).

---

## 7. Per-Class Slice (model-evaluation-report Step 5 parity)

| Class (risk_level) | ECE | 95% CI* | Brier per-class | Verdict |
|---------------------|-----|---------|-----------------|---------|
| **low** | **0.046** (`0.0459`) | flagged `>macro` | `0.020` | worst calibrated — low-risk tail underestimated |
| medium | 0.021 (`0.0208`) | — | `0.046` | best |
| high | 0.025 (`0.0248`) | — | `0.065` | — |
| **macro** | **0.030** | — | `0.030` | masks `low` worst case |
| spread | `0.025` | — | — | `max/min ≈2.2×` |
| max | `0.046` (low) | — | — | Must report max, not just macro (per plan: `macro+max+spread`) |

\*Per-class ECE CIs not yet bootstrapped separately; family CI above pools. Model-evaluation-report: *flag any slice >10pp below overall* — `low` is `1.6pp` above macro, not gated, but `low 0.046 vs med 0.021` suggests **low-risk miscalibration** — quarantine `low→flag` threshold underestimates uncertainty.

---

## 8. Assumption Checks (statistical-analysis — bundled `scripts/assumption_checks.py` analogues)

| Check | What was tested | Result | Action |
|-------|----------------|--------|--------|
| **Bin occupancy** | `min(bin_counts) ≥12` (ciphercrest gate) else 3-bin | `min=3` → **fail** | Downgrade EW to **3-bin honest**; flag headline |
| **Per-bin CI width** | `width <0.30` for informativeness | `1.0, 0.67` → **fail** | Label `[0,1]` bins uninformative; lower `n_bins` or collect `+50` |
| **Normality of bin CIs** | Not applicable — bootstrap empirical | 2000 resamples → empirical percentile, no normality assumption | Honest |
| **Homogeneity** | Equal-mass quantile vs EW | `Δ 0.029` borderline skew | Flag skew; report both |
| **Kernel corroboration** | `SmoothECE ∈ [ECE_lo, ECE_hi]`? | `0.085 ∈ [0.047,0.113]` yes, but `kernel>hist` | Report honest; kernel corroborates directionally but indicates underestimation |
| **Platt vs isotonic** | `isotonic at n<1000` forbidden | **Platt only** used (`CalibratedClassifierCV sigmoid cv=2`) | ✓ |
| **Leakage gate** | `n_bins = max(2,n_val//5) capped 5; gated min≥12→3` | Applied but lenient | Correct to `gated=3` |
| **Calibration curve linearity** | `check_regression_diagnostics` analog for `acc~conf` | Not linear — concentration drives curvature | Kernel reveals nonlinearity |

No distributional assumptions for ECE itself; checks above are *diagnostic*, not model assumptions. Formal `Shapiro-Wilk` per bin not meaningful at `n=3`; replaced by bootstrap per `references/assumptions_and_diagnostics.md` guidance: *for n≥100 overall, weigh Q-Q visually but per-bin n is the bottleneck*.

---

## 9. Why NOT Headline `0.033` — Caveat Template

> **Do NOT headline** `ECE 0.033` without caveat. At `n_cal=100` equal-width 5-bin counts `[3,3,5,7,82]` yield per-bin 95% CIs `[0,1]` for 4/5 bins (mean width `0.35`); only the high-confidence tail (`n=82`) is estimable. Quantile 5-bin `[20×5]` — free of empty-theater `[94,6,0,0,0] @ n=500, 60% empty` — gives `ECE 0.062` (`Δ 0.029` vs EW, borderline `>0.03` skew flag) and kernel `SmoothECE 0.085` (`Δ 0.052 vs hist`; Silverman `h=0.018` Nadaraya-Watson). Family bootstrap `95% CI [0.047,0.113]` itself excludes `0.033`. Gated honest is **3 bins** (`min≥12`), `n_cal` requires `≥60` (`30/bin`) for 3 bins / `≥150` for 5 bins per `statistical-power`; `Brier REL 0.013 / RES 0.039 / UNC 0.098` shows reliability error despite `Brier < base`. **Platt only; no isotonic at n<1000.** Honest claim: *apparently calibrated in high-confidence tail, unproven in tails; needs `+50` samples before 5-bin claim.*

---

## 10. What to Do Next (least complex that fulfills, per model-evaluation-report)

1. **Immediate (quick):** Update all dashboards/docs to show `quantile ECE 0.062 [per-bin CI]` as primary, EW `0.033` as caveat with `[3,3,5,7,82]` badge + `gated 3-bin` footnote. Already done in `calibration_honest.json` + this file + `calibration_curve_honest.png` (750×600, EW+quantile+kernel overlay).
2. **Short (1–2 runs):** Compute and publish **gated 3-bin EW ECE** (expected `~0.04–0.06` with honest `~33/bin`) alongside; add per-class max `low 0.046` to summary table.
3. **Medium (needs data):** Collect to `n_cal≥150` (ideally `200 → 40/bin`) before any 5-bin promotion; keep `Platt cv2` only.
4. **Large (if behavioral signal wanted):** Retrain honest `8-col` (TOP5+behavioral) and re-audit bins — if concentration persists, score distribution is weak-supervision artifact, not fixable by binning.

---

## 11. Verification

```bash
cat eval/calibration_honest.json | jq .ece_ew                # 0.0332
cat eval/calibration_honest.json | jq .ece_quantile          # 0.0619
cat eval/calibration_honest.json | jq .ece_kernel            # 0.0847
cat eval/calibration_honest.json | jq .ci_per_bin_ew         # 5 bins with [0,1] theater flagged
cat eval/calibration_honest.json | jq .min_per_bin_ok        # false
cat eval/calibration_honest.json | jq .gated_bins            # 3
cat eval/metrics.json | jq .risk.bin_counts                  # [3,3,5,7,82]
ls -lh eval/calibration_honest.md eval/calibration_curve_honest.png
```

Artifacts:
- `eval/calibration_honest.json` — machine-readable N audit
- `eval/calibration_honest.md` — this file
- `eval/calibration_curve_honest.png` — 750×600 EW (orange, errors) + quantile (blue, per-bin counts) + kernel smooth dotted + 2000-boot CI error bars + ideal dashed + gated footnote + `30/bin n≥60` banner

Refs: `assessment/risk_metrics.py:{_ece,_ece_quantile,_ece_smooth,_silverman_bandwidth,brier_decomposition,_bootstrap_ci_per_bin,family_bootstrap}` + `assessment/risk_plot.py:save_calibration_plot` + `assessment/risk_train.py:Platt cv2 gated min>=12→3 honesty` + `.omo/plans/ciphercrest-hostile-audit.md#T08/N` + `model-evaluation-report Step 6` + `statistical-analysis assumption_checks.py`.

