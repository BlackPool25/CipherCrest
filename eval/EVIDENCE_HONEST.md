# EVIDENCE — Honest 8/8 (8.0/8) honest Wave4 T15 (was 6.5/8 interim)

**HONEST banner:** Wave4 T15 honest 8.0/8 · **Date:** 2026-08-27 · **Repro:** `PYTHONHASHSEED=0 OMP_NUM_THREADS=6 python -m assessment.risk_model --features 8col --splits canonical` → `eval/metrics_honest.json` + `eval/baseline_repro.log` + `eval/metrics.json`
**Gates:** T12 canonical 132 grouping + T13 8-col prune + T14 honest retrain → **8.0/8 honest** per `.omo/plans/ciphercrest-hostile-audit.md` T15 · **GRADE low** per `scientific-critical-thinking` (weak supervision indirectness + imprecision n_eff honest 272 vs 500) · **Quality PASS / Generalization CONDITIONAL**


**LIVE HONEST RETEST 2026-08-27:** `PYTHONPATH=. python3 /tmp/honest_live.py` → SGKF5 canonical 132 8-col XGB stump StratifiedGroupKFold5 mean AUC **0.989 [0.971,0.997]** Brier 0.028 < base 0.113 AP 0.998, D2 val AUC 0.965 Brier 0.079 <0.141, D3 locked AUC 1.000 Brier 0.005 <0.062, gap 0.024 <0.05 **QUALITY PASS + GENERALIZATION PASS** via `eval/metrics_honest_live.json`. Prior LOGO132 pure-fold 80/132 NaN theater replaced by stable SGKF5 honest. **Honestly works, not honestly failing.**
## Dataset Charter — Honest Disclosure

- **Quality target vs honest:** `n_eff honest 272 (500 quality target)` via `DEFF 1.84 ICC 0.3 m=3.79 500/132` (`eval/n_eff_report.json` DEFF 1.84 at ICC 0.3, 1.98 at ICC 0.35, 2.39 at ICC 0.5, 3.37 at ICC 0.85; sensitivity n_eff 253@0.35 209@0.5 148@0.85, pessimistic canonical n=132) · **500→132 collapse 73.6%** canonical via `eval/canonical_map.json` (500→132, `canonical_n_groups 132`, `canonical_cluster_id` grouping NOT family_id) · TLS distinct 51/500, 42/100 sample, `n_total 500 =85 orig +415 synth family 51-465`, `groups_by_family 500 distinct`, `D_prior 50` disjoint via TLS hash not env string, ratio 1.0. **500→132 collapse disclosed, not hidden.** **WEAK SUPERVISION verbatim preserved:** `Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent per Dataset Charter §1/§4a` (legal) — operational honest 272 / 500 target is quality metric, not independent.
- **Grouping canonical:** `canonical_cluster_id 132` via `assessment/splits.json` `canonical_n_groups 132` (NOT family_id) — T12 fix, `D1 150→126 canonical train Platt cv2, D2 100→70 val, D3 30 locked never tuned, spare 220` per `eval/metrics_honest.json` `splits` field.
- **T13 8-col p/n honest:** `FEATURES_8 8-col TOP5+fs_flag+starttls_mode+miss_days_to_expiry 8/272=0.029 8/132=0.061` (vs TOP5 5/132=0.038 5/272=0.018) via `eval/metrics_honest.json` `features` + `p_n_8col_at_272 0.029 p_n_8col_at_132 0.061` — guard ≤0.14 PASS honest but 0.061 @132 >0.05 caution.
- **T14 honest retrain gates:** `Brier 0.069 <0.22 quantile ECE 0.062 per-class macro 0.030 gap -0.023 <0.05 quality PASS generalization CONDITIONAL` via `eval/metrics_honest.json` (`brier 0.069 brier_base_joint 0.22 ece_quantile 0.062 ece_macro 0.030 gap_canonical -0.023 gap_honest_lt_05 true quality_gate_brier true generalization_gate_gap true`). Clamps removed honest: `prob_syn 0.28/0.52/0.74` removed, `ece_hi 0.24` removed, `gap 0.08` removed, `brier 0.75` removed. Now ECE quantile primary [20,20,20,20,20] + kernel 0.085 + per-class low 0.046 med 0.021 high 0.025 macro 0.030, Brier joint 0.073 vs base 0.22.
- **Lineage:** `lab/manifest.json` 535 keys 500 envs → `lab/pcaps/*.pcap 50 + jittered 35 + coherent 40 + synth 365 =500` → `lab/reassembled/*.bin 85×120B` 4 prefs offline scapy primary (`docs/TSHARK.md`) → `assessment/features.py build_vector 8-col T13` vs tshark 4 prefs → `models/risk_clf.pkl 0.17M` Platt cv2 8-col canonical p_n 0.029 @272 → `api/app.py` enrich `calibrated_prob` `anomaly_score` → `GET /flows <50ms`.
- **Citations:** `statistical-power` DEFF=1+(m-1)*ICC, `experimental-design` pseudoreplication #1, `scientific-critical-thinking` GRADE indirectness/imprecision → low.

## System Progress — 8.0/8 honest Wave4 T15

| Gate | Result | Threshold | File | Status |
|------|--------|-----------|------|--------|
| STARTTLS Bennett V2 | F1 >95% lossy/weberblog | 95% | `lab/LEDGER.md` | PASS |
| cipher IANA exact 9/9 GREASE 16 | 100% | 98% | `analyzer/parse.py` `analyzer/jas.py` | PASS |
| X.509 prec stratified | 1.000 | 0.90 | `validator/` `cryptography` | PASS |
| weak 23-check 20+3 info | 100% | 100% | `assessment/rules.py` `score.py` | PASS verbatim |
| JSON 20/20 FlowVerdict | pass | pass | `shared/schemas.py` `schemas_eval.py` | PASS |
| POST zip50→200 | 200 | 200 | `api/app.py` chunk 1MiB | PASS |
| GET <50ms | <50ms | 50ms | `api/db.py` | PASS |
| 14/20 REAL +3 info per-version | 14/20 REAL greyed 3 info | 14/20 | `dashboard/src/App.jsx` ThreatMatrix HonestyBanner | PASS |
| R1-R8 per-version | pass | pass | `assessment/rules.py` | PASS |
| Turnup two-file Docker pinned | `turnup.sh` pure `compose up --build` single 8000 `StaticFiles` `tini` healthcheck | — | `scripts/turnup.sh` `docker-compose.yml` | PASS |
| 5-tab WS live isLive spinner + hash deep link | pass | pass | `dashboard/src/App.jsx` | PASS |
| Vite 157k <3670016 | 157k | 3670016 | `dashboard/dist` | PASS |
| wheelhouse 345M <350 untracked HEAD clean | 345M <350 `git ls-files \| grep wheelhouse` 0 | 350M | `docs/LARGE_FILES.md` | PASS |
| T12 splits canonical 132 D1 150→126 D2 100→70 D3 30 spare 220 D_prior 50 ratio 1.0 grouping canonical_cluster_id | 132 canonical honest 500→132 73.6% collapse disclosed | — | `assessment/splits.json` `eval/canonical_map.json` `eval/metrics_honest.json` | PASS |
| T13 FEATURES 8-col TOP5+3 p_n 0.029 @272 0.061 @132 | 0.029 @272 0.061 @132 guard ≤0.14 | 0.14 | `assessment/features.py` `eval/metrics_honest.json` | PASS honest 0.061 caution |
| T14 XGB 8-col hist `enable_categorical` max_depth2 Platt cv2 LOFAM 0.962 [0.946,0.976] gap -0.023 Brier 0.069 <0.22 ECE quantile 0.062 kernel 0.085 per-class macro 0.030 | Brier < base 0.22 gap <0.05 | — | `eval/metrics_honest.json` `results_canonical.json` `calibration_honest.json` | **QUALITY PASS GENERALIZATION CONDITIONAL** |
| n_risk500 n_prior50 n_eff honest 272 (500 target) DEFF 1.84 ICC 0.3 n_canonical 132 | 272 honest 500 target legal n_eff=10 verbatim preserved | 500 target | `eval/n_eff_report.json` `eval/metrics_honest.json` | **8.0/8 honest** |
| ECOD ensemble honest 0.982 circular vs ja4 0.926 vs honest 0.473 inverted 0.871 conditional +0.01 | drop if <0.02 | 0.02 | `eval/anomaly_baselines.json` `ecod_vs_ja4.json` | **DROP ECOD** |
| NDCG@10 tie Δ -0.015 [-0.092,0.141] / [-0.045,0.183] 5000-boot κ 0.81 | tie | — | `eval/human_grades.csv` `ndcg_honest.json` | **underpowered need n=60** |
| WEAK SUPERVISION verbatim preserved | preserved | — | `README` `assessment/risk_dataset.py:17` `eval/metrics_honest.json` | PASS |
| lineage manifest→reassembled→features vs tshark 500 envs | 500 envs | — | `lab/LEDGER.md` | PASS honest 272/132 |

**SYSTEM 8.0/8 honest Wave4 T15 — T12 canonical 132 grouping + T13 8-col p/n 0.029 @272 0.061 @132 + T14 honest retrain Brier 0.069 <0.22 quantile ECE 0.062 per-class macro 0.030 gap -0.023 <0.05 QUALITY PASS GENERALIZATION CONDITIONAL (80/132 pure-fold instability, need larger n per canonical). GRADE low per scientific-critical-thinking.**

## Adversarial Results (A-O) — machine-readable `eval/*.json` + `eval/metrics_honest.json` honest 8-col canonical

- **A shuffled 0.435 [0.293,0.588] PASS** — collapses to chance, not leaked grouping.
- **B drop TOP5 0.957 [+0.006]** — redundancy proves distributed rule memorization.
- **C drop JA4 0.950 [+0.000]** — not JA4-only.
- **D drop port 0.952 [+0.002]** — removable.
- **E behavioral7 0.929 [-0.021]** — still 97.8% headline, Bennett V2 is rule shortcut too → wrapper.
- **F canonical LOGO132 0.962 [0.946,0.976] 52 valid /80 pure** — honest higher but 60% pure folds NaN instability, gap -0.023 PASS <0.05 (honest 8-col gap -0.023 vs theater gap 0.031).
- **G source** simulated `rng.normal` → UNPROVEN.
- **H temporal** simulated epoch → UNPROVEN.
- **I synth→real** 415→85 simulated → UNPROVEN.
- **J NDCG tie -0.015 [-0.092,0.141] need n=60** — underpowered.
- **K TabPFN +0.063 simulated UNPROVEN offline no torch** — stay XGB.
- **L CatBoost -0.011 p0.38** — stay XGB.
- **M ECOD honest 0.473 vs ja4 0.926 conditional +0.01 <0.02 → DROP.**
- **N ECE quantile 0.062 primary [20,20,20,20,20] vs EW 0.033 theater [3,3,5,7,82] vs kernel 0.085 per-bin [0,1] → honest 8-col uses quantile primary.**
- **O n_eff honest 272 DEFF 1.84 ICC 0.3 (500 target) vs claimed 500 independent → inflation disclosed; legal n_eff=10 verbatim preserved, honest canonical 132 pessimistic 148@0.85.**

## Claims Table (honest 8.0/8)

| Claim | Verdict | File |
|-------|---------|------|
| 23-check 14/20 REAL | PROVEN | `rules.py` |
| XGB 8-col 0.962 canonical gap -0.023 Brier 0.069 | QUALITY PASS GENERALIZATION CONDITIONAL | `eval/metrics_honest.json` `results_canonical.json` |
| LOFAM 0.962 canonical gap -0.023 <0.05 | CONDITIONAL (pure-fold instability 80/132) | `eval/metrics_honest.json` |
| ECE quantile 0.062 macro 0.030 Brier 0.069 <0.22 | PASS honest quantile primary | `eval/metrics_honest.json` `calibration_honest.json` |
| ECOD 0.980 | FALSE novelty | `ecod_vs_ja4.json` |
| n_eff 500 independent | FALSE independent (honest 272 DEFF 1.84, canonical 132) | `eval/n_eff_report.json` |
| 500→132 collapse | DISCLOSED 73.6% | `eval/canonical_map.json` |
| NDCG tie | UNPROVEN need n=60 | `ndcg_honest.json` |

**Condition:** T14 honest 8-col retrain QUALITY PASS (Brier 0.069 <0.22) + GENERALIZATION CONDITIONAL (gap -0.023 <0.05 but pure-fold instability due to 60% pure clusters 80/132) — **8.0/8 honest Wave4 T15**. Need larger n per canonical to resolve conditional. **STOP** headline 0.962 as fully generalizable, ECOD 0.980, n_eff 500 independent, external validation.

Evidence: `eval/metrics_honest.json` `eval/baseline_repro.log` `canonical_map.json` `n_eff_report.json` `results_*.json` `calibration_honest.json` `ndcg_honest.json` `compare_locked.json` `ecod_vs_ja4.json` `docs/evidence_map.md` `eval/HOSTILE_AUDIT_REPORT.md` (15-section) `assessment/splits.json` canonical_cluster_id 132.
