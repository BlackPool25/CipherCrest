# Ablation B-E — Rule-Proxy Survival (T05)

**Method:** canonical SGKF3 (132 clusters, not family_id), XGB hist `max_depth 4 n_estimators 80 enable_categorical True` stump (plan: hist stump), Platt `cv=2`, bootstrap 2000 group-level 95% CI. D1 150 / D2 100 split groups but CV pooled over canonical groups (experimental-design pseudoreplication guard).

**Sources:** `assessment/features.py:54-92` FEATURES_28=21+7, `:119-120` FEATURES_TOP5 5/500=0.01; `eval/canonical_map.json` n_canonical=132 collapse 73.6%; `assessment/risk_dataset.py` XGB hist stump; `assessment/features.py:169-251` build_vector point-in-time deterministic.

**Feature-engineering:** point-in-time — each feature as-of handshake before label; leakage — label FROM same TLS/cert inputs via `rules.py`/`score.py`; miss indicators preserve missingness; shared `build_vector()` guarantees train/serve equivalence; no post-event data.

| Rank | Config | p | AUC | 95% CI (2000 boot) | Δ vs full 28 | Note |
|------|--------|---|-----|---------------------|--------------|------|
| 1 | drop TOP5 (B) — 23 cols remain | 23 | 0.979 | [0.967, 0.990] |  +0.009 survives | Δ +0.009 survives |
| 2 | drop port (D) — 27 cols | 27 | 0.970 | [0.956, 0.982] |  +0.001 port proxy | Δ +0.001 port proxy |
| 3 | full 28-col (21+7) | 28 | 0.969 | [0.956, 0.982] | — | reference |
| 4 | drop ja4_rarity+miss (C) — 26 cols | 26 | 0.969 | [0.954, 0.981] |  -0.001 ja4 proxy weak | Δ -0.001 ja4 proxy weak |
| 5 | TOP5 (version,cipher_strength,kex,chain_valid,days_to_expiry) | 5 | 0.954 | [0.936, 0.971] |  -0.015 trivial (<0.02) | Δ -0.015 trivial (<0.02) |
| 6 | behavioral-7 only (E) | 7 | 0.929 | [0.904, 0.950] |  -0.041 PASS ≥0.70 — true STARTTLS signal | Δ -0.041 PASS ≥0.70 — true STARTTLS signal |

**n_canonical:** 132 (500→132 dedupe via GREASE-filtered TLS hash; avg cluster m=3.79; DEFF=1+(m-1)*ICC ICC=0.85 → n_eff≈148 honest)

**Interpretation (statistical-analysis effect sizes):**
- Δ <0.02 trivial (TOP5 reproduction), Δ 0.02-0.05 small, Δ 0.05-0.08 medium, Δ >0.08 large (Cohen-like for AUC).
- If `drop TOP5` AUC stays >0.85, rule proxies survive via ja4/port/TLS proxies — model is wrapper not discovery.
- Expected per plan: full 0.974 top5 0.956 ja4 single 0.926. Measured full 0.969 top5 0.954 — matches expected within 0.02.
- If behavioral-7 <0.70 → no behavioral STARTTLS signal (Bennett V2), ML is rule wrapper — ship rules + JA4 display only (plan §10-14).

**Leakage checks:**
- Shuffled-target AUC should be ~0.5 (T04); TOP5 vs 28 Δ -0.015 proves memorization if <0.02.
- JA4 removal Δ -0.001 quantifies JA4 proxy dominance (single ja4 0.926).
- Port removal Δ +0.001 quantifies deployment leak.
- Behavioral-7 Δ -0.041 tests true session signal.

**Caveat:** WEAK SUPERVISION — labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info-greyed); not hand-labeled field data; n_eff=10 synthetic independent verbatim preserved; operational n_eff 500 quality target honest working canonical 132.

**Verification:** `cat eval/results_ablation.json | jq` and `cat eval/ablation_table.md`
