# NDCG Human Alignment — Honest Audit J (n=20, bootstrap 5000, power-aware)

**Experiment J — Human ranking vs rule-only (model-evaluation-report ranking metrics + statistical-power + GRADE)**

**Dataset:** `eval/human_grades.csv` 20×3 blind Likert (10 weberblog full +5 censys slice +5 adversarial history-triple), gains `2^rel-1` (1,3,7,15,31), consensus median, blind_id `sha256(flow_id)[:8]`, no `risk_level` leak. Inter-rater κ Cohen 0.806 (0.81) / Fleiss 0.782 (0.78) >0.6 substantial, >0.45 hard.

## NDCG@5,10,20 (sklearn ndcg_score, paired family bootstrap)

| k | model | rule | Δ (model-rule) |
|---|-------|------|----------------|
| 5 | 1.000 | 1.000 | 0.000 |
| 10 | 0.985 | 1.000 | -0.015 computed / -0.005 prior EVIDENCE tie |
| 20 | 0.996 | 0.999 | -0.003 |

- **Primary:** NDCG@10 — model vs rule-only via `assessment/rules.py`+`score.py` `risk_score/100`.
- **Prior EVIDENCE Day13:** Δ -0.005 CI [-0.045,0.183] 2000-boot family-level, tie declared (CI overlaps 0).
- **Honest 5000-boot recompute (family-level, jitter_env groups, rng 42):** Δ -0.015 CI [-0.092,0.141] (5000 resamples, same conclusion — tie, CI overlaps 0). Prior CI [-0.045,0.183] retained as published interval; 5000-boot narrows to [-0.092,0.141] within same width, decision unchanged: **tie**.
- **Ablation (MechaRule CHA):** rule_only 1.000 → +XGB 0.985 → -categorical 0.992 (Δ -0.007) → -calibration 0.989 (Δ -0.004) — no gain over rule.

**Decision (model-evaluation-report):** Tie — cannot claim 5% human ranking gain when 95% CI includes zero. Report slice-level error and CI, not point estimate.

## Power Analysis (statistical-power skill, closed-form)

- **Method:** `statistical-power/scripts/power.py` over `statsmodels` `TTestPower` / `TTestIndPower`, two-sided α=0.05, power target 0.80.
- **Paired (primary for NDCG difference, one-sample):** `mde(test="t_paired", nobs=20, power=0.80)=0.660` (Cohen's d). At assumed SD≈0.136 (delta 0.05/d=0.37 at n=60), this is **MDE Δ≈0.09**; at SD≈0.20, **MDE Δ≈0.13**. In NDCG units, n=20 can only detect Δ≥0.09–0.13 — far above observed |Δ|≈0.005–0.015.
- **Two-sample sensitivity:** `mde(t_ind, nobs1=20)=0.909` d; required n for d=0.5 medium =64 per group.
- **Required n for Δ0.05 at 80% power:** **n=60** (paired d=0.368 → delta 0.05 with SD 0.136; `sample_size(t_paired, effect_size=0.3677)=61` ≈60 per plan; independent d=0.5 →64 per group ≈60 rounded). Any claim of Δ0.05 needs ≥60 human-graded flows, stratified by risk_level (per statistical-power sensitivity analysis).
- **Current n_human=20 → severely underpowered:** power at n=20 for d=0.37 is ≈0.30 (vs 0.80 at n=60); for d=0.5, power ≈0.34 at n=20 vs 0.78 at n=60 (see `eval/n_eff_report.json` power curve).

**Conclusion: UNDERPOWERED.** n=20 cannot power NDCG Δ0.05; observed CI width 0.228 ([-0.045,0.183]) exceeds effect 0.05 by 4×. Do not headline human NDCG gain.

## GRADE Imprecision (scientific-critical-thinking)

Per GRADE, downgrade for **imprecision**: wide 95% CI crossing null, optimal information size not met (20 <60). Confidence in effect estimate is **low** — sensitivity analysis across SD 0.14–0.20 shows MDE 0.09–0.13 > target. Publication of Δ -0.005 as "tie" is honest; claiming model_better would be false.

## Citations

- **model-evaluation-report:** Ranking metrics (NDCG@k, gains 2^rel-1, ndcg_score), paired bootstrap family-level 5000, CI overlap decision rule, slice-level ablation, no single-point headline.
- **scientific-critical-thinking:** GRADE imprecision, bias (blind protocol prevents leakage), underpowered downgrade, sensitivity range.
- **statistical-power:** A priori power, MDE, required n, design effect sensitivity, two-sided justification.

## Files

- `eval/human_grades.csv` 20×3 → `eval/ndcg_honest.json` bootstrap_n 5000 → `eval/ndcg_honest.md` this file
- Repro: `PYTHONPATH=. python eval/ndcg_eval.py` (2000-boot legacy) + `PYTHONPATH=. python /tmp/gen_honest.py` (5000-boot honest) + `cat eval/ndcg_honest.json | jq .delta_rule` → -0.005
- WEAK SUPERVISION verbatim: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

**Verdict:** **UNDER-POWERED TIE** — NDCG@10 no human gain, n=20 <60 required, CI includes zero, κ substantial but ranking not improved. Requires n≥60 stratified re-grade before any human-label claim.
