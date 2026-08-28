# SecureMailScope Hyperplan — Executable Work Plan (Honest n_eff 272 / Canonical 132 → 60 distinct families m0138 + FlyingSquid active)
*Plan derived from hyperplan adversarial review (5 members, 3 rounds) and formalized by the plan agent.*
*Team: hyperplan 7311dea2-67e2-405d-b897-915ae8f5f9a9 — 34 findings × 3 rounds, 135 cross-attacks, 34 defenses, 0 destroyed*
*Gates: G1 Adaptive CI signed, G2 XGB+CatBoost signed (searchXNG researched), G3 Never veto signed, G4 **ACTIVE FlyingSquid m=6 triplet CPI + brutal retrain + 60 distinct families (m0138)**, G5 SQLite fix + filter-repo wheelhouse/dist purge EXECUTED 2026-08-27 (Parsed 185 commits, .git 3.3M, wheelhouse 339M local not in git)*
*Filter-repo: 2026-08-27 `git filter-repo --path wheelhouse --path dashboard/dist --invert-paths --force` — Parsed 185 commits HEAD 71d68c7, repacked 3.3M, size-pack 2.97M, origin restored git@github.com:BlackPool25/CipherCrest.git*
*Update 2026-08-27 m0138: **60 distinct families required (not 40)** — currently TLS distinct 42/100 (38 raw +4 JA4), canonical 132 (51 TLS overall); must expand to ≥60 truly distinct JARM+JA4 canonical clusters, re-establishing p_n 5/60=0.083 ≤0.14, n_eff recalc, D1/D2/D3 rebalance, brutal suite must hold on 60 distinct holdout*

## Context & Gates (see docs/DECISIONS_GATES.md + .omo/specs/gate-thresholds.json for signed thresholds)
- **C1 n_eff collapse:** 500 =85 orig +415 synth → canonical 132 (73.6% collapse) via eval/canonical_map.json; n_eff 272 DEFF 1.84 ICC 0.3 m=3.79; sensitivity 253@0.35 209@0.5 148@0.85; legal n_eff=10 verbatim; p_n TOP5 0.01@500 0.029@272 0.038@132 guard ≤0.14
- **C2 Weak supervision:** score.py 23 checks 20+3 info-greyed 14/20 REAL → verbatim
- **C3 Grouping:** canonical_cluster_id **132 now → expand to ≥60 distinct families (m0138)** GroupKFold; D1 150→126 D2 100→70 D3 30 spare 220 D_prior 50 → **rebalance after 60 distinct verified, TLS distinct 42/100 → 60/100 required**
- **C4 Feature/label separation:** 8-col TOP5+fs_flag+starttls_mode+miss_days_to_expiry, ALLOWED_RISK_FEATURES, ja4_rarity only, is_tls13_opaque invariant, prior_flag never trains
- **C5 Anomaly theater:** ECOD 0.473 vs ja4 0.926 contrast disclosed, inverted 0.871 + ensemble 0.980 deleted
- **C6 Adaptive calibration:** min25/bin [94,6,0,0,0], ECE quantile 0.062 macro 0.030 CI [0.0396,0.1000] 2000-boot, Brier 0.069<0.22 gap -0.023
- **C7 NDCG underpowered:** 20×3 κ 0.81/0.78 Δ -0.005 CI [-0.045,0.183] MDE 0.18 non-veto
- **C8 Offline:** wheelhouse 339M 37 wheels local NOT in git (filter-repo purged), .git 3.3M, models <5M, gzip 157k, !torch, GET <50ms typed
- **C9 GRADE low:** weak supervision indirectness + imprecision, clamp deletions disclosed, HonestyBanner 14/20 REAL+3 info
- **Decisions locked:** D1 4 exps not13, D2 2 candidates **XGB-Platt + CatBoost-Platt** (G2 searchXNG signed), D3 reject ET-BERT, D4 **ACTIVE FlyingSquid m=6 triplet CPI (was defer) + brutal retrain**, D5 delete calibrator until CI, D6 B+Platt wrapper, D7 lock 8-col, D8 delete ensemble, D9 defer torch lean, D10 grouping.py resolver + **60 distinct families expansion**
- **Gates signed:** G1 Adaptive CI, G2 XGB+CatBoost (searchXNG: TabPFN +0.187 but open-env CatBoost>TabPFN per arXiv2505.16226, TabICL 72%+4x, torch violates !torch), G3 Never veto, G4 **ACTIVE FlyingSquid + brutal retrain + 60 distinct (m0138)**, G5 SQLite fix + filter-repo executed

## Dependency & Parallel Graph
```
Wave0 GATE: T0 (blocks all) — T0 now SIGNED, proceed to Wave1
Wave1 Foundation (3-way parallel after T0): T1 canonical grouping & n_eff, T2 8-col freeze, T3 SQLite typed + bundle guards
Wave2 Core (3-way parallel after Wave1): T4 4-exp harness, T6 anomaly honest fix, T9 weak supervision deferral
Wave3 Calibration & candidate (2-way after Wave2): T5 Platt + bootstrap CI, T7 2-candidate eval XGB+CatBoost + ET-BERT reject
Wave4 Evaluation (2-way after Wave3): T8 NDCG non-veto, T10 scientific gate-keeping
Wave5 Integration (after Wave4): T11 evidence & leakage report
Critical Path: T0 → T1 → T4 → T5 → T10 → T11 (38% speedup vs sequential)
```

## Tasks T0-T11 (WHERE/WHY/HOW/VERIFY, TDD, atomic commits)

**T0 Gate — Resolve 5 Open Questions** WHERE docs/DECISIONS_GATES.md + .omo/specs/gate-thresholds.json — VERIFY docs contains 5 gates signed, gate-thresholds.json validated via shared/schemas_eval.py — Skills scientific-critical-thinking, statistical-power, experimental-design — **DONE 2026-08-27 SIGNED**

**T1 Canonical grouping & n_eff provenance [UPDATED m0138: 60 distinct families]** WHERE eval/canonical_map.json + eval/n_eff_report.json + assessment/grouping.py + assessment/splits.json + lab/manifest.json — Implement grouping.py resolver canonical_cluster_id 132 → **expand to ≥60 distinct JARM+JA4 canonical clusters** (currently 42/100 TLS distinct, 51/500 overall; need +18 distinct families via lab/generate_manifest.py or curated real families, verify GREASE-filtered JARM+JA4 distinct); regenerate canonical_map 500→132(+new) + n_eff recalc DEFF=1+(m-1)*ICC with m=n_total/n_canonical + p_n 5/60=0.083 guard; splits D1/D2/D3 rebalance — Skills statistical-power, experimental-design, scientific-critical-thinking, data-validation — VERIFY pytest assessment/tests/test_splits.py -k canonical + test_n_eff asserts n_canonical>=60 + TLS distinct >=60 + python -m eval.n_eff_report --check — Depends T0

**T2 8-col feature/label freeze** WHERE assessment/features.py + LEDGER + shared/schemas.py — Lock TOP5+fs_flag+starttls_mode+miss_days_to_expiry=8, ALLOWED_RISK_FEATURES, p_n ≤0.14 @272/@132, reject ja4 raw, exclude prior_flag, is_tls13_opaque invariant — Skills feature-engineering, data-validation, scientific-critical-thinking — VERIFY pytest assessment/tests/test_features.py — Depends T0,T1

**T3 Offline SQLite typed columns & bundle guards** WHERE api/db.py + api/app.py + shared/schemas_eval.py + scripts/turnup.sh — Typed flows + FlowVerdict hard-fail before upsert, GET <50ms, POST zip50→200 chunk1MiB 413, wheelhouse <350, models <5M, gzip <3670016, !torch, git ls-files==0 — Skills data-validation, ai-app-architecture — VERIFY pytest api/tests/test_api_e2e + test_offline_bundle + turnup --check — Depends T0,T1 — **Filter-repo history purge DONE, local wheelhouse 339M remains but NOT in git**

**T4 4-exp harness (not13) + grouping resolver** WHERE assessment/risk_model.py + splits.json + eval/metrics_honest.json — Exactly 4 exps XGB hist max_depth4 Platt cv2 vs CatBoost (G2), GroupKFold canonical via grouping.py, gap <0.15 perm p0.001 — Skills training-workflow, experiment-tracking, experimental-design, statistical-power — VERIFY pytest assessment/tests/test_risk_ablation.py — Depends T0,T1,T2

**T5 Platt-only calibrator + adaptive bootstrap CI** WHERE assessment/risk_model.py + eval/calibration_curve.png + eval/metrics_honest.json — Delete isotonic until CI, keep B+Platt cv2, min25/bin quantile [94,6,0,0,0], 2000-boot CI [0.0396,0.1000] width0.06, ECE quantile0.062 macro0.030 Brier0.069<0.22 gap -0.023 — Skills evaluation, statistical-power, statistical-analysis, experiment-tracking — VERIFY pytest eval/tests/test_metrics_json + calibration_curve.png 750x600 — Depends T0,T1,T2,T4

**T6 Anomaly honest fix — delete theater** WHERE assessment/anomaly_model.py + eval/anomaly_baselines.json — Delete inverted 0.871 + ensemble 0.980, keep ECOD 0.473 vs ja4 0.926 + IF0.759, decision_scores_ invariance — Skills evaluation, data-validation — VERIFY pytest assessment/tests/test_anomaly_hybrid + grep inverted==0 — Depends T0,T1

**T7 2-candidate eval XGB+CatBoost + ET-BERT reject** WHERE assessment/risk_model.py + eval/metrics_honest.json + docs/DECISIONS_GATES.md — Exactly 2 candidates **XGB-Platt + CatBoost-Platt** per G2, AP0.976 PR curve, ET-BERT reject doc, defer torch !torch guard still true (CatBoost CPU wheel added, verify du -m wheelhouse still <350) — Skills training-workflow, evaluation, experiment-tracking, huggingface (reject rationale) — VERIFY pytest -k candidate exactly2 GroupKFold canonical + ls eval/risk_pr.png + catboost wheel exists but not torch — Depends T0,T4,T5

**T8 NDCG underpowered non-veto** WHERE eval/ndcg_eval.py + human_grades.csv + blind-likert.md — 20×3 blind 2^rel-1 NDCG@10 Δ-0.005 CI[-0.045,0.183] 2000-boot, κ0.81/0.78>0.6 MDE0.18 disclosed non-veto per G3 — Skills statistical-power, statistical-analysis, llm-evaluation, evaluation — VERIFY pytest eval/tests/test_ndcg — Depends T0,T7

**T9 FlyingSquid m=6 triplet CPI + brutal retrain [ACTIVE per m0134 + 60 families m0138]** WHERE assessment/weak_supervision.py + weak_labels_flyingsquid.json + assessment/LEDGER.md + score.py + README — Implement FlyingSquid m=6 triplet CPI outer fold (never train on weak labels), label_version pin, PYTHONHASHSEED 0 deterministic, byte-identical test; retrain hook for T4/T7 on denoised labels; 60 distinct families prerequisite — Skills dataset-curation, scientific-critical-thinking, data-validation, training-workflow — VERIFY pytest assessment/tests/test_rules.py -k weak_supervision + tests/test_label_reproducibility.py + weak_labels_flyingsquid.json exists canonical>=60 — Depends T0,T1,T2

**T10 Scientific gate-keeping & clamp disclosure** WHERE README + dashboard/app.jsx + shared/schemas.py + eval/metrics_honest.json — GRADE low, disclose removed clamps prob_syn 0.28/0.52/0.74 ece_hi0.24 gap0.08 brier0.75, HonestyBanner 14/20 REAL+3 info + is_tls13_opaque blue banner — Skills scientific-critical-thinking, frontend, dashboard-design, data-validation — VERIFY pytest tests/test_readme + dashboard snapshot — Depends T0,T1,T5,T6,T8,T9

**T11 Integration evidence & leakage report** WHERE eval/metrics_honest.json + calibration_curve.png + LEAKAGE_REPORT.md + EVIDENCE_Day14.md — Aggregate 34/34 survived, metrics_honest hard-fail via schemas_eval, gap0.000 perm p0.001, p_n guards, trio lineage manifest→reassembled→features vs tshark 4 prefs, 750x600 — Skills experiment-tracking, data-validation, scientific-critical-thinking, evaluation — VERIFY python -c load_and_validate() + pytest eval/tests/test_metrics_json eval/tests/test_ndcg + ls calibration_curve.png — Depends T1,T2,T3,T5,T6,T7,T8,T10

## Commit Strategy (12 atomic TDD-gated commits)
gate-signed → grouping → features → api typed → 4-exp harness → calibration → anomaly → candidates XGB+CatBoost → NDCG → disclosure → dashboard → evidence — each pytest slice + schemas_eval hard-fail before commit; never stage wheelhouse/ + dashboard/dist/; pre-commit guard git ls-files==0; origin git@github.com:BlackPool25/CipherCrest.git restored after filter-repo

## Success Criteria
Gate-signed 5/5 (G2 now XGB+CatBoost) + provenance 34/34 survived + grouping 500→132 + 8-col p_n≤0.14 + calibration honest ECE0.062 macro0.030 Brier0.069 gap-0.023 + anomaly 0.473 vs0.926 inverted/ensemble absent + 4 exps 2 candidates XGB+CatBoost ET-BERT rejected + NDCG 20×3 κ>0.6 non-veto + WEAK SUPERVISION verbatim GRADE low + offline wheelhouse 339M local NOT in git .git3.3M + hard-fail green
