---
slug: sih26159-till-day7-lean-ml-bridge
status: awaiting-approval
intent: clear
review_required: false
pending-action: write .omo/plans/sih26159-till-day7-lean-ml-bridge.md
approach: Till Day7 is the hardened replay-to-ML bridge: keep Day5-6 replay lane frozen as wiring checks, expand dataset to lean 30 via jitter slices (3 per jitter family), harden 28-col contract + build_vector as TDD contracts, then start lean training Day7 exactly as voted — XGB Platt cv=2 lean (n_eff=10, 500-boot family-level ECE hi<0.20) + ECOD primary (ROC point>0.60, contamination invariance) — with wiring to api/app.py and assessment/LEDGER honest disclosure, re-verify wheelhouse lean <350 and SYSTEM 5/8, and produce EVIDENCE_Day7 shell. No MicroAE/torch, no IF correction, no isotonic, no raw ja4, no quarantine/siem/milter stretch.
---

# Draft: sih26159-till-day7-lean-ml-bridge

## Components (topology ledger)
| id | outcome | status | evidence path |
|---|---|---|---|
| C1 | lab jitter expansion → 30 rows (10 base + 7×3 jitter 21) with 30 env_ids distinct, manifest env_id/capture_epoch/source_id/tshark_version honest, LEDGER coverage_ratio logged | active | lab/pcaps/jittered/*.pcap, lab/manifest.json, lab/LEDGER.md, assessment/splits.json |
| C2 | assessment/splits.json regenerated 30 envs, D1 12-14 / D2 7-9 / D3 4-5 / D_prior 20 disjoint, D5 temporal frozen, StratifiedGroupKFold contract green | active | assessment/splits.json, assessment/tests/test_splits.py |
| C3 | assessment/features.py hardened: FEATURES_28==28, build_vector(mode xgb/ae) 28, CATEGORICAL_6 native, XGB_CATEGORICAL_PARAMS hist+enable_categorical+device cpu+depth4, ALLOWED_RISK guards | active | assessment/features.py, shared/ja4_rarity.py, analyzer/jas.py |
| C4 | assessment/censys prior shell re-verified 20 lean prior_flag:true chain_valid None ja4_rarity 0.02..0.99 span, 11/28 caveat wired | active | shared/fixtures/censys_sampled_200.json, shared/tests/test_censys_prior.py |
| C5 | assessment/risk_model.py lean XGB Platt cv=2 (XGBClassifier tree_method hist enable_categorical True max_depth 3-4 deterministic) → models/risk_clf.pkl + calibration_curve.png + ECE 500-boot family-level + permutation n=10 | active | assessment/risk_model.py, models/risk_clf.pkl, eval/calibration_curve.png, assessment/tests/test_risk_ablation.py |
| C6 | assessment/anomaly_model.py ECOD primary lean (pyod ECOD contamination 0.10) → models/anomaly.pkl + ROC point>0.60 + contamination invariance test + anomaly_score wired to FlowVerdict | active | assessment/anomaly_model.py, models/anomaly.pkl, assessment/tests/test_anomaly_hybrid.py |
| C7 | api/app.py wiring: load risk_clf.pkl/anomaly.pkl if present, enrich POST /analyze FlowVerdict.assessment calibrated_prob + anomaly_score, fallback to score() if models missing, GET /flows <50ms still SQLite | active | api/app.py, api/db.py, api/tests/test_api_e2e.py |
| C8 | offline wheelhouse + SYSTEM 5/8 + EVIDENCE_Day7 + ledgers re-verification (wheelhouse lean <350, Vite 157k, STARTTLS F1>95%, cipher100%, prec1.000, weak100%, JSON20/20) | active | wheelhouse/, eval/EVIDENCE_Day7.md, shared/progress.md, assessment/LEDGER.md, .github/workflows/ci.yml |

## Open assumptions (announced defaults)
| assumption | adopted default | rationale | reversible? |
|---|---|---|---|
| jitter families | 7 families 02,03,04,05,07,08,10 ×3 slices =21 jitter +10 base =31 envs (≈30) | Matches lab/scripts/jitter_slices.py FAMILY_CFG, covers weak CERT/TLS families for variance; 1 slice already exists, add 2 extra per family with seeds 200+ | Yes — can add --families flag to include 01,06,09 if needed Day8 |
| D1/D2/D3 rebalancing | D1 13 envs (base 01-05 + jitter 02-04), D2 8 (06-08 + jitter 05,07), D3 4 (09,10 + jitter 10 extras), D_prior 20 disjoint; ratio max/min <3 still holds (13/4=3.25 borderline so adjust to 12/9/4 ratio 3) → target 12/8/5 ratio 2.4 | Keeps unique≥5 and locked ∩ train empty while reflecting new env count; exact split enumerated in plan todo | Yes — tweak groups_by_env assignment, not frozen file shape |
| risk labels | Rule-derived weak supervision disclosed verbatim per §4 | n_eff=10 independent disclosed, labels are score.py severity → risk_level; not hand-labeled; required by master plan honesty annex | No — disclosure required everywhere |
| is_deprecated handling | Keep TLS1.0/1.1 deprecated Critical weight 25 in score.py | Master plan 4 scoring; jitter does not change version distribution materially | Yes — if jitter adds TLS1.3 22% prior complement |
| ECOD threshold | contamination 0.10 default, invariance test asserts ROC unchanged when contamination 0.05→0.2 | Search shows ECOD/IF contamination only thresholds (pyod #482, #552), not scoring — test must assert raw scores invariant, only labels shift | Yes — tune 0.05-0.10 |

## Findings (cited - path:lines)
- Day5-6 DONE wiring: assessment/policy.py:20 decide FlowVerdict→PolicyDecision deterministic Low→allow Medium→flag yellow High→quarantine Critical→block + to_spec_action alias, 7 fixtures green (assessment/policy.py:86-232, shared/progress.md:24-30, assessment/LEDGER.md:5-15)
- Day5-6 DONE splits: assessment/splits.json 17 envs 10 base +7 jitter distinct, D1 5/ D2 3/ D3 2/ D_prior 20 disjoint, D5 temporal 2026-08-27→09-03 env_id_frozen true (assessment/splits.json:1-118, assessment/tests/test_splits.py, shared/progress.md:25)
- Day5-6 DONE DB: api/db.py init_db/upsert_flows/query_all/query_by_flow_id + api/app.py chunk-read 1 MiB streaming 413 guard via io.BytesIO loop (api/app.py:98-190, api/db.py: canonical 4 funcs, api/tests/test_api_stream.py, test_db.py, shared/progress.md:26)
- Day5-6 DONE wheelhouse: wheelhouse/ 345M 32 wheels xgboost 1.7.6 + pyod 2.0.5 --only-binary=:all: --prefer-binary no torch (shared/progress.md:27, .omo/plans/sih26159-day5-day6-api-policy-splits.md:115-120)
- Day5-6 DONE dashboard: CoverageTable 103 LOC + ThreatMatrix 95 LOC + HonestyBanner is_tls13_opaque blue + Vite 157k <3670016 (dashboard/components/CoverageTable.jsx, dashboard/app.jsx, shared/progress.md:28)
- Day5-6 DONE live binding: GET /flows polls _last_result else SQLite query_all else stub, POST /analyze zip10 → 200 posture 0-100 policy_dist wire (api/app.py:191-192, api/tests/test_api_e2e.py, shared/progress.md:29)
- Day5-6 DONE SYSTEM 5/8: STARTTLS F1>95% lossy/weberblog, cipher100% >98%, prec1.000 >90% stratified, weak100% 23-check, JSON20/20, cold-start <3s, wheelhouse <350, wheelhouse+API gates (eval/EVIDENCE_Day5.md, Day6.md, shared/progress.md:30, .github/workflows/ci.yml)
- Feature contract exists but needs hardening: assessment/features.py FEATURES_28==28 (21 base 6 categorical +15 numeric incl ja4_rarity only +7 miss_indicator) + build_vector(mode xgb/ae) 28 + XGB_CATEGORICAL_PARAMS hist enable_categorical True device cpu depth4 (assessment/features.py:33-97, codegraph explore 39 symbols)
- Whitelist divergence guards exist: ALLOWED_RISK_FEATURES ja4 not in ja4_rarity in (shared/ja4_rarity.py:38-59, analyzer/jas.py:25, assessment/features.py:25-28)
- Censys prior shell present but single-epoch TLS1.3 heavy (all 20 sampled TLS1.3 strong ECDHE, miss_indicators 1 for cert cols) → needs 11/28 caveat re-verification (shared/fixtures/censys_sampled_200.json 20 rows, lab/scripts/sample_censys_200.py 48-108 weighted sample with extremes 0.02/0.99)
- Risk/Anomaly stubs missing .pkl: assessment/risk_model.py + anomaly_model.py not yet trained lean; plan §4 requires XGB Platt method sigmoid cv=2 lean (not isotonic at n<100) per search “Small-Data Calibration Benchmark” (Platt outperforms isotonic n<2000) and ECE bootstrap 500 family-level; pyod ECOD contamination invariance confirmed (search pyod #482: contamination only threshold) → validate with invariance test
- Lab jitter currently 7 pcs only: lab/pcaps/jittered/family-0*-jitter-01.pcap + lab/scripts/jitter_slices.py FAMILY_CFG 7 families (02,03,04,05,07,08,10) with GREASE 0x0a0a + expiry ±5d + ja4_rarity sampled (lab/scripts/jitter_slices.py:20-85)
- Context7 quota exceeded (monthly) — fell back to SearXNG; SearXNG confirms XGB enable_categorical requires tree_method hist + df category dtype, Platt vs isotonic at n=50 prefers Platt (Niculescu 2013 small-cal <2000), ECOD/IF contamination only threshold, permutation_importance n_repeats 10 lean vs 30 stretch (sklearn docs)
- Master plan deep: 28-col is 21 base +7 miss, categorical native not ordinal, XGB deterministic random_state 42 PYTHONHASHSEED 0 OMP 6, calibrated_prob = max predict_proba, SHAP diagnostic stretch only, hybrid PR-AUC logit suppress at n_pos<20 (| .omo/plans/sih26159-securemailscope-implementation.md:126-154)

## Decisions (with rationale)
- Intent: **CLEAR** (user voted 6 MCQs explicitly) + review_required false — user explicitly demanded interview via “ask me questions using multiple choice” override, so CLEAR+ask-all-surviving-forks applied.
- Scope decision C (Till Day7 inclusive ML start) + B (Lean training starts Day7) per vote — Till Day7 bridge includes lean XGB Platt cv=2 + ECOD primary fit to .pkl so Day7-10 is continuation; contracts-only would leave ML cold and waste Day7.
- Dataset A (Lean 30, 3 slices per jitter family) per vote — 3×7=21 jitter +10 base =31 envs/rows; n_eff still 10 independent disclosed but rows 30 give cv=2 stability and permutation variance; generation via jitter_slices.py --slices 3.
- Feature contract A (Harden + guard) per vote — TDD for FEATURES_28==28, build_vector 28 NaN-free, grep guards isotonic forbidden + ja4 not in vector + environment_id grouping, XGB params assert; reversible internals defaulted, owner-decision guards surfaced.
- Testing A (TDD contracts, tests-after ML) per vote — deterministic contracts get failing-first tests, ML gets tests-after (risk_ablation, anomaly_hybrid) with agent-executed junit + evidence .omo/evidence/ulw/….
- Evidence A (Re-verify + Day7 ledger) per vote — wheelhouse lean <350 re-verified, SYSTEM 5/8 stays green wiring, EVIDENCE_Day7.md with SYSTEM 5/8 green + ML LEARN shell (ECE 500-boot CI hi<0.20, permutation top3, ECOD ROC>0.60, calibration curve) no hard-fail at n_eff=10.
- Explicit defaults adopted: jitter families 02,03,04,05,07,08,10; D1 12 / D2 8 / D3 5 split to keep ratio <3; weak-supervision disclosure verbatim; ECOD contamination 0.10 with invariance test (per pyod #482). All recorded in Open assumptions for veto.
- Tooling: use SearXNG not Context7 (quota exceeded) + codegraph_explore for codebase truth; ask no further questions (6 forks resolved).

## Scope IN
- Lab: expand lab/pcaps/jittered to 3 slices per 7 families (21 jitter → 31 envs total), update lab/manifest.json + lab/LEDGER.md with environment_id __postfix3.9_loss0 / __jitter{1..3}_loss5, capture_epoch 2026-08-27T00:00:00Z, source_id uuid, tshark 4.2.0, coverage_ratio 1.0 (jittered 0.95-1.0 logged)
- Assessment: regenerate assessment/splits.json 31 envs with groups_by_env, D1_train_groups ~12, D2_val ~8, D3_locked ~5 (09,10 + jitter extras), D_prior 20 disjoint, D5 temporal same-env train 2026-08-27 test 2026-09-03 frozen, StratifiedGroupKFold contract, prior_flag disjoint guards
- Assessment: harden assessment/features.py 28-col contract + build_vector (TDD) + CI guards (isotonic forbidden, ja4 whitelist, env grouping, XGB hist+enable_categorical)
- Shared: re-verify shared/fixtures/censys_sampled_200.json 20 prior_flag true chain_valid None ja4_rarity 0.02..0.99 span, 11/28 caveat wired
- Assessment ML lean Day7: assessment/risk_model.py XGBClassifier(tree_method hist device cpu enable_categorical True max_depth 3-4 n_estimators 80 reg_alpha 1.0 reg_lambda 2.0 deterministic) + CalibratedClassifierCV(method sigmoid cv=2) Platt only + 500-boot family-level ECE CI + calibration_curve.png + permutation n=10 + models/risk_clf.pkl
- Assessment ML lean Day7: assessment/anomaly_model.py ECOD contamination 0.10 (pyod) fit on lab 30 + prior diversity 20 (35% slice) + tests contamination invariance + ROC point>0.60 + models/anomaly.pkl wiring anomaly_score to FlowVerdict
- API: wire api/app.py to load .pkl if present, enrich assessment calibrated_prob + anomaly_score, keep SQLite <50ms, POST /analyze fallback to stub/score if models missing
- Offline/Eval: re-verify wheelhouse lean <350 (du -m + pip --no-index --dry-run), Vite bundle <3670016, SYSTEM 5/8 green, produce eval/EVIDENCE_Day7.md (SYSTEM 5/8 green + ML LEARN shell Day8-10), update shared/progress.md + assessment/LEDGER.md + .github/workflows/ci.yml guards

## Scope OUT (Must NOT have)
- No torch==2.4.0+cpu 180M in wheelhouse (lean <350 would fail) — MicroAE 27-8-1 gated n≥50+ahead remains Day8-10 stretch
- No isotonic calibration at n<100 (Platt sigmoid only) — grep -rq isotonic hard-fail per sklearn §2a + small-data benchmark
- No raw ja4 as risk feature (ja4_rarity 0..1 only) — ALLOWED_RISK_FEATURES asserts fail if ja4 in vector
- No family_id grouping (environment_id only, StratifiedGroupKFold groups=environment_id) — forbidden per §4a.3
- No quarantine.py/siem.py/arf.py/QuarantineConsole/digest cron/milter 127.0.0.1:10025/mockdns live beyond fixture read — cut-order 0 stretch deferred to Day10
- No quarantine table raw body attach — flows table only INSERT OR REPLACE without body
- No B1-5 per-split annex, no overall pooled ML validity table — Day10 stretch; Day7 EVIDENCE is ONE deterministic SYSTEM table + ML shell
- No transformer BERT on raw pcap, no as any/unwrap/panic, no file >250 LOC without split

## Open questions
- None — 6 MCQs resolved. Remaining forks exploration-answered (codegraph + searxng) with defaults recorded above for veto at gate.

## Approval gate
status: awaiting-approval
next: present brief → await explicit user OK → scaffold without --draft-only → append Todos + Final verification wave
plan: .omo/plans/sih26159-till-day7-lean-ml-bridge.md (pending creation after approval)
approach: Till Day7 bridge hardens replay-to-ML boundary (jitter 30, splits 31, 28-col TDD, censys 20 re-verified) then starts lean training (XGB Platt cv2 + ECOD) wired to API, re-verifies SYSTEM 5/8 + wheelhouse lean, and lands EVIDENCE_Day7 shell — all before Day8-10 stretch expansion.
evidence-till-now: lab/manifest.json 10 families +7 jitter, assessment/splits.json 17 envs, assessment/features.py 28-col exists, shared/fixtures/censys 20 prior_flag true, wheelhouse 345M <350, Vite 157k, SYSTEM 5/8 green Day6 🟢
fork-summary: 6 votes — C(Till Day7 inclusive) / B(Lean training Day7) / A(Lean 30) / A(Harden guard) / A(TDD contracts) / A(Re-verify Day7 ledger) — adopt verbatim, no further asks

