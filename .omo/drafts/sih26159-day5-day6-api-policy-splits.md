---
slug: sih26159-day5-day6-api-policy-splits
status: approved — Momus R1 REJECT → Oracle REJECT → patched C1-C4 + R2 CONDITIONAL APPROVE → fixed 4 Medium (T4 overwrite, T2 D1/D2/D3 balance, T3 20-vs-15, T5 streaming harness) → Momus R3 APPROVE 2026-08-27 — only 2 Low remain (requirements.txt pins, censys 14-row replacement) patched — READY for /start-work
intent: clear
review_required: false
pending-action: plan written at .omo/plans/sih26159-day5-day6-api-policy-splits.md — awaiting user explicit okay to hand off to /start-work (execution is separate, never auto-started by planner)
approach: Lean API+DB hardening + lean policy only + splits.json 12 lean groups with prior_flag disjoint + censys prior shell 20 lean + lean wheelhouse <350M + SYSTEM 5/8 EVIDENCE — gateway quarantine/siem/arf/milter deferred per cut-order 0
---

# Draft: sih26159-day5-day6-api-policy-splits

## Components (topology ledger)
| id | outcome | status | evidence path |
|---|---|---|---|
| C1 | assessment/policy.py lean decide 7 fixtures | active | assessment/tests/test_policy.py |
| C2 | assessment/splits.json 12 groups env_id prior disjoint | active | assessment/tests/test_splits.py |
| C3 | shared/fixtures/censys prior shell 20 lean ja4_rarity 0..1 | active | shared/tests/test_censys_prior.py |
| C4 | api/db.py SQLite JSONB <1ms + <50ms GET /flows | active | api/tests/test_db.py |
| C5 | api/app.py POST /analyze chunk-read 1MiB zip fan-out cold-start <3s | active | api/tests/test_api.py |
| C6 | wheelhouse lean <350M --only-binary | active | du -m wheelhouse |
| C7 | dashboard CoverageTable 23x3 + honesty 14/20 banner | active | dashboard/components/CoverageTable.jsx |
| C8 | dashboard live binding zip->db->dashboard E2E | active | api/tests/test_api_e2e.py |
| C9 | ledgers daily poll Day5-6 | active | shared/progress.md |
| C10 | eval/EVIDENCE_Day5-6 SYSTEM 5/8 | active | eval/EVIDENCE_Day5.md |
| C11 | CI hard-fail guards isotonic/ja4/grouping/prior | active | shared/tests/test_censys_prior.py |
| C12 | wire check collect-only | active | pytest --collect-only |

## Open assumptions (announced defaults)
| assumption | adopted default | rationale | reversible? |
|---|---|---|---|
| PolicyDecision literals | keep shared/schemas.py literals allow/quarantine/block/flag with alias to spec deliver/banner/quarantine/hold_incident in policy layer only | CODEOWNER freeze additive-only, no breaking rename | yes — alias map |
| Wheelhouse lean | <350M without torch (ECOD+XGB only) | MicroAE torch 180M is stretch gated n≥50+ahead per §7; lean <350M gate already in test_offline_bundle.py | yes — add torch Day7 if ahead |
| Splits lean size | 12 groups lean (not 30 stretch) | 12 still passes ≥5 gate, reveals Day7 without waiting for 5 jitter slices | yes — stretch 30 Day7-10 |
| Censys 20 vs 200 | lean 20 rows if 200 not ready | 20≥15 span check, blocks Day7 without 200-file generation delay | yes — sample_censys_200.py 200 stretch |
| EVIDENCE gate | SYSTEM 5/8 only Day5-6 | ML gates require XGB/ECOD training Day7-10 n_eff disclosure | yes — 8/8 Day10 |

## Findings (cited - path:lines)
- Day4 closed: reassembler lossy F1>95% + pre_tls_buffer + stripping 3flow same 5-tuple 127.0.0.11:54330 (lab/reassembler/reassemble.py:30-70, lab/LEDGER.md, shared/progress.md:Day4)
- TLS parse dual tshark 4-prefs + scapy fallback, legacy_version 0x0303 + supported_versions 0x0304 → TLS1.3 else 1.2, cipher/KEX/fs_flag (analyzer/parse.py, shared/ja4_rarity.py:1-81 GREASE 16, shared/data/censys_top_ja4.json)
- Validator Store/PolicyBuilder dual-store + limbo prec 1.000 stratified (validator/chain.py, validator/LEDGER.md:prec 1.000)
- Rule 23 weak 100% (assessment/rules.py:1-201, assessment/score.py:18-33 weights Critical25 High15 Medium7 Low3 Info1, shared/schemas.py:120-129 PolicyDecision)
- API current: api/app.py:1-294 already has _real_pipeline_for_bytes + USE_STUB flip fixed + _db_* inline, api/db.py exists but inline, api/flows.db exists
- Dashboard current: dashboard/app.jsx 345 LOC grandfathered, dashboard/components/CoverageTable.jsx exists, honesty wiring done Day2
- SearXNG research: FastAPI chunk-read read(size) + 413 guard + python-multipart (exa), cryptography Store/PolicyBuilder Rust 2024 (cryptography.io), XGB CalibratedClassifierCV sigmoid Platt small-n (sklearn docs) — verified via seraxng_tech_search 2026-08-27
- CODEOWNER: shared/CONTRIBUTING.md P1 owns shared/schemas.py + fixtures/* additive-only Day2 00:00

## Decisions (with rationale)
1. Day5 owns API+DB hardening — user MCQ answer "API + DB hardening" — aligns with master plan Days 4-7 Rule+Dash live-binds to real features, not ML
2. Lean policy only — user MCQ "Lean policy only" — cut-order 0 gateway is stretch, keep replay lane gradeable
3. Day5 creates splits.json 12 groups — user MCQ — unblocks Day7 GroupKFold without leaking Censys into D1
4. Lean wheelhouse <350M — user MCQ — ECOD+XGB only, MicroAE stretch Day7 if ahead, matches test_offline_bundle lean <350M
5. SYSTEM 5/8 EVIDENCE Day5-6 — user MCQ — ML B gates deferred to Day7-10, SYSTEM 5/8 is deployment blocker per §6
6. Censys prior 20 lean — default adopted (M3 Q) — 20 passes 0..1 span guards, 200 stretch via sample_censys_200.py
7. CoverageTable <250 LOC — keep Vite 3.5MB gz gate, Streamlit fallback documented but not built Day5

## Scope IN
- Lean policy decide + splits D1/D2/D3/D_prior/D5 + censys 20 + SQLite JSONB + POST /analyze hardening + wheelhouse lean + CoverageTable 23x3 + live binding + ledgers + EVIDENCE SYSTEM 5/8 + CI guards + wire check

## Scope OUT (Must NOT have)
- quarantine.py/siem.py/arf.py/QuarantineConsole/digest cron/milter/mockdns live, torch in wheelhouse, XGB/ECOD training, quarantine table raw body, breaking rename, B1-B5 per-split annex, BERT/isotonic

## Open questions
- none — all 5 MCQ forks answered (Day5 focus, policy scope, splits timing, wheelhouse, EVIDENCE gate)

## Approval gate
status: approved — Momus R1 REJECT → Oracle REJECT → patched C1-C4 + R2 CONDITIONAL APPROVE → fixed 4 Medium (T4 overwrite, T2 D1/D2/D3 balance, T3 20-vs-15, T5 streaming harness) → Momus R3 APPROVE 2026-08-27 — only 2 Low remain (requirements.txt pins, censys 14-row replacement) patched — READY for /start-work
approach: Lean API+DB+policy+splits 12 groups + censys 20 + wheelhouse lean <350M + SYSTEM 5/8 — plan written at .omo/plans/sih26159-day5-day6-api-policy-splits.md — handoff awaits explicit user okay; execution via /start-work in separate worker session (planner never implements)
next: user says "approve" or "revise Q{...}" — on approve, worker runs /start-work sih26159-day5-day6-api-policy-splits
