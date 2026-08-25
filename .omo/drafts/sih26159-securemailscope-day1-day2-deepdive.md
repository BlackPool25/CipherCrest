---
slug: sih26159-securemailscope-day1-day2-deepdive
status: approved
intent: clear
review_required: false
pending-action: done — .omo/plans/sih26159-securemailscope-day1-day2-deepdive.md written and high-accuracy reviewed
approach: Deep-dive execution plan for Day1-2 of SIH26159 — full 6-model shared/schemas.py (Pydantic v2) frozen Day1, tshark-golden fixtures (tcp desegment + tls desegment), fixture-passthrough stubs, triple-smoke lab (587/993/stripped), Vite gauge shell, schemas.json-only offline proof Day1. All research-grounded (SearXNG+tshark+JA4+Context7).
---

# Draft: sih26159-securemailscope-day1-day2-deepdive

## Components (topology ledger)
| id | outcome | status | evidence path |
|---|---|---|---|
| shared | schemas.py 6 models + schemas.json + fixtures (tshark golden 2h) + censys_top_ja4.json + tests green | active | shared/schemas.py, shared/schemas.json, shared/fixtures/*, shared/data/censys_top_ja4.json |
| lab | triple smoke pcaps (01/06/09) + docker-compose + certs + manifest.json + reassembler_stub parity | active | lab/docker-compose.yml, lab/certs/**, lab/pcaps/family-*.pcap, lab/manifest.json |
| api | FastAPI POST /analyze + GET /flows + GET /report stub returning fixture list[FlowVerdict] validated | active | api/app.py, api/tests/test_api.py |
| dashboard | Vite React gauge shell (Gauge+Matrix 23cols) reading fixtures via /api/flows stub | active | dashboard/app.jsx, dashboard/vite.config.js |
| offline-gate | Day1 only schemas.json gate; wheelhouse/docker deferred to Day2/5 per Q5:A | deferred | shared/tests/test_offline_bundle.py |

## Open assumptions (announced defaults)
| assumption | adopted default | rationale | reversible? |
|---|---|---|---|
| Python version | 3.11 (plan Q1:C) | SIH lab standard, Pydantic v2 + cryptography Store/PolicyBuilder stable | yes but pinned in requirements.txt |
| Monorepo shape | monorepo + shared/ CODEOWNER (P1) per §0.1 | Single repo prevents 6-agent drift, shared is merge gate | no |
| Pydantic mode | v2 BaseModel with model_json_schema() per Context7 | Generates draft2020-12 JSON Schema, strict validation, FastAPI native | yes |
| Tshark prefs | tcp.desegment_tcp_streams:true + tcp.reassemble_out_of_order:true + tls.desegment_ssl_records:true | Both OFF by default since 3.0; without them parity false-fails on lossy/weberblog (Wireshark docs) | no |
| JA4 GREASE | Filter 0x0a0a..0xfafa before hash per FoxIO ja4#305 | Harmonizes Python vs Rust/Wireshark divergence | no |
| Bundle Day1 | schemas.json only, not wheelhouse | Q5:A — fastest Day1, defers 30-40min wheelhouse to Day2/5 | yes |

## Findings (cited - path:lines)
- Plan locks 15 forks: Ideal6, Python3.11 FastAPI+React, 10-12d parallel, schemas freeze Day2 00:00 additive-only — `.omo/plans/sih26159-securemailscope-implementation.md:5-7`
- Repo shape monorepo shared/schemas.py + fixtures + mocks + progress.md ledger — `...implementation.md:14-43`
- Shared schemas TLS (version Literal 5, cipher_strength, is_aead, kex, ja4/ja4_rarity, early_data, ech_outer) + Cert (leaf_present, is_tls13_opaque invariant, ocsp_stapled_status) + Finding + Assessment + PolicyDecision + FlowVerdict — `...:47-122`
- CI gate server-side hard fail .github/workflows/ci.yml, pre-push advisory only — `...:124,482-483`
- Day1-2 Gantt: Shared schemas+fixtures+ja4_rarity, Lab smoke Family01, API stub, Dash vite shell, Gate test_schema + STARTTLS F1>95% — `...:131,488-490`
- SearXNG: Pydantic v2 GenerateJsonSchema customization via handler, model_json_schema() per docs — exa pydantic.dev 2026-02-16
- SearXNG: pip download -d wheelhouse + --only-binary=:all: mandatory (xgboost sdist 2x to >1GB), offline install --no-index --find-links — exa pydeps + stackoverflow
- SearXNG: Wireshark 3.0 TCP Reassemble out-of-order disabled default, tls.desegment_ssl_records OFF default — must set tcp.desegment_tcp_streams:true + tls.desegment_ssl_records:true (docs/wsug_html_chunked/ChAdvReassembly) — exa wireshark.org 2019-02-28
- SearXNG: JA4 GREASE filter 0x0a0a..0xfafa anywhere (draft-davidben-tls-grease-01), Python filters sigalgs GREASE but Rust/Wireshark not — divergence logged #305 — exa github FoxIO ja4
- Context7: Pydantic v2 model_json_schema() with $defs, TypeAdapter.json_schema() for unions — /pydantic/pydantic docs
- Context7: FastAPI POST multipart via Annotated[list[UploadFile], File()] + Pydantic validation — /websites/fastapi_tiangolo
- Context7: Vite chunkSizeWarningLimit default 500kB, adjust via build.chunkSizeWarningLimit — /vitejs/vite

## Decisions (with rationale)
| decision | choice | rationale |
|---|---|---|
| D1 schemas scope | A Full 6 models Day1 | User Q1:A — max contract upfront, freezes Day2 00:00 additive-only, dependents start without re-wire |
| D2 fixture gold | A tshark golden 2h | User Q2:A — real-grounded, proves tcp/tls desegment prefs, prevents tautological gate |
| D3 stub contract | A Fixture passthrough | User Q3:A — shared/mocks/reassembler_stub returns fixtures list[FlowVerdict], validator_stub returns opaque-aware Cert; flip via USE_STUB=False at Day3 when reassembled/*.bin 🟢 |
| D4 lab smoke | B Triple 01+06+09 | User Q4:B — covers STARTTLS upgrade (587), implicit TLS1.3 opaque (993), stripped cleartext (587 no STARTTLS) — exercises all banner/branch paths Day1 |
| D5 offline bundle | A schemas.json only Day1 | User Q5:A — validates single source truth without 1-2h wheelhouse/docker overhead; full bundle Day3/5 per Gantt |
| D6 dashboard | A Vite React gauge shell | User Q6:A — heatmap superiority, but Day1 proves <3.5MB gz, tree-shaken recharts, chunkSizeWarningLimit:600 |

## Scope IN
- Day1: repo scaffold, shared/schemas.py 6 models, schemas.json generation, tshark golden derivation for triple smoke, censys_top_ja4.json stub, fixtures, mocks, manifest.json, docker-compose.yml triple smoke, certs triple, API stub POST /analyze, Dashboard Vite shell, all Day1 tests green
- Day2: full 10-family cert matrix (add 02,03,04,05,07,08,10), sender+mockdns wiring (offline DNS), gen_traffic.sh triple-history, reassembly_coverage_ratio, coverage table per-port, ledger updates, CI hard fail gate re-validation

## Scope OUT (Must NOT have)
- No wheelhouse/docker save on Day1 (deferred — Q5:A)
- No real X.509 chain validation logic Day1 (fixture Cer ts only; real chain Day2-5 per Validator window)
- No ML/Risk/Anomaly training Day1-2 (Rule 23 checks Day4+, ML Day7+)
- No quarantine/siem/policy engine wiring Day1-2 (assessment/policy.py Day7+)
- No weberblog/limbo real corpus ingest Day1 (dual-corpus Day10+)
- No live capture requiring NET_RAW/privileged (zero-privilege replay is primary)

## Open questions
None — 6 forks resolved via Q&A 2026-08-25 (A/A/A/B/A/A). Proceed to approval brief → plan write.

## Approval gate
status: approved
approach: Day1-2 deep dive with hour-by-hour commands, file-by-file specs, exact Pydantic fields, tshark -o flags, openssl cert commands, FastAPI route signatures, Vite config limits, test assertions, ledger gates, and evidence paths. Approval authorizes writing .omo/plans/sih26159-securemailscope-day1-day2-deepdive.md only; execution starts separately via /start-work.

## High-accuracy review receipts (2026-08-25)
- Oracle Momus Pass 1: FAIL 9/16 shallow, tautology, deadlock — 7 repairs checklist (ses_fc8ef848effeE3DhegGSAi4ohT)
- Repairs applied: W2→W3 re-wave deadlock fix, 3/3 not 20/20 + pubkey_bits None, split test_fixtures_schema vs test_reassembly, real pcap not JSON disguised, ulw evidence standardization, weberblog guard, tshark install + GREASE + chunkSizeWarningLimit
- Oracle Momus Pass 2: CONDITIONAL PASS 2 nits (ses_fc8ed62efffe5BB8je8U9aM1aD) — Todo8 stale wording + Todo16 ulw path — both patched 2026-08-25
- Final: PASS — plan is decision-complete with real agent-executed tests (pytest/TestClient) happy+failure, no scope creep, dependency acyclic, evidence ulw tree
## Approval gate
status: approved — user approved writing 2026-08-25 m0021; high-quality review requested and completed. Next: worker executes via /start-work (boulder) with evidence .omo/evidence/ulw/<session>/a<attempt>/
