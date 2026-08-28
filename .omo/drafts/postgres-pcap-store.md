---
slug: postgres-pcap-store
status: awaiting-approval
intent: clear
review_required: true
pending-action: write .omo/plans/postgres-pcap-store.md
approach: Postgres single source-of-truth across ALL sites (dashboard/families/lab/live/reports → Postgres only, no SQLite/JSON fallback); postgres:16-alpine + pgdata in docker-compose.yml; JSONB + BYTEA; separate tables; families derived not_run (show run iff pcap/flow exists in DB, else not_run badge) + Inspect matrix list; Dashboard PowerBI cross-filter ?flow= + triage sorted risk_score DESC + protocol matview + model_runs; startup-idempotent seed (not init-only), history FOR UPDATE transaction, always-SELECT (remove _last_result), BYTEA streamed, generated columns + GIN, CONCURRENTLY unique indexes
---

# Draft: postgres-pcap-store

## Working contract
Prometheus, planning consultant, no implementation until explicit user okay. Approval authorizes plan write only; execution via separate worker (e.g. /start-work). Delegated subagents are read-only.

## Intent verdict
Intent: **CLEAR**, review not required — user demanded Postgres docker storage with clone→turnup auto-populate, Postgres consistently across ALL sites (no JSON/SQLite fallback), families initially not_run with dashboard subset auto-run on turnup, lab/live/dashboard/reports isolation, fix families score regression, and asked to be interviewed. Routed CLEAR per override; adopt-default OFF; 8 multiple-choice Qs answered + 2 follow-ups (consistent postgres + not_run).

## Topology ledger (to be planned — one row per component)
| id | outcome | status | evidence path |
|---|---|---|---|
| docker-postgres-service | postgres:16-alpine service in docker-compose.yml with named volume pgdata, env POSTGRES_DB/USER/PASSWORD, healthcheck pg_isready | active | docker-compose.yml, Dockerfile (runtime tini+uvicorn), lab/docker-compose.yml |
| db-schema-migration | SQL DDL creating families, pcap_files (BYTEA), flows (JSONB + history), lab_runs, live_captures, report_runs + indexes + matviews | active | api/db.py (SQLite flows+history), shared/schemas.py (FlowVerdict), lab/manifest.json |
| seed-orchestration | Init-only /docker-entrypoint-initdb.d/01_schema.sql + api startup Python idempotent seed that upserts families/pcaps/fixtures even when volume non-empty | active | scripts/turnup.sh, lab/scripts/synth_families.py, shared/fixtures |
| api-db-layer | Replace api/db.py SQLite 4-func API with async psycopg/SQLAlchemy Postgres adapter, keep same function signatures + add pool, transactions, history versioning | active | api/db.py:1-280, api/app.py:1-330 |
| dashboard-query-migration | Families/Lab/Live/Reports/Dashboard pages stop fetching JSON/manifest only; query Postgres via new /api/flows, /api/families, /api/metrics endpoints backed by matviews | active | dashboard/src/pages/Families.jsx, Lab.jsx, Live.jsx, dashboard/src/services/api.js |
| families-score-fix | Eliminate _last_result truncation bug; ensure posture_score/risk_level persists per flow_id via flows_history latest-wins; frontend merges correctly | active | api/app.py: _last_result global, dashboard/src/pages/Families.jsx mergedFamilies |
| live-lifecycle | live_captures TRUNCATE on turnup --with-lab / docker compose down sequence; distinct retention policy vs persisted flows | active | scripts/turnup.sh wait_for + lab/docker-compose.yml |
| report-packet-detail | Reports tab queries actual packet/pcap rows via join pcap_files→flows with pagination + download, not just marks | active | api/app.py /report endpoint, shared/schemas.py |

## Findings (cited - path:lines)
- **Current store is SQLite only**: `api/db.py:16` defines `_DB = Path(__file__).parent / "flows.db"`, schema `flows (flow_id TEXT PK, data TEXT)` + `flows_history (flow_id, version, data, created_at)` with json_extract probe, INSERT OR REPLACE + history versioning via `COALESCE(MAX(version),0)+1`. No Postgres dependency anywhere.
- **API app couples memory + DB incorrectly**: `api/app.py:176` `_last_result` global holds last analyze result; `get_flows()` returns `_last_result` if not None else `query_all()` else stub reassemble. This hides DB rows after one analyze → families score reset bug reported: "when I run one others are reset". Also `_last_summary` similarly in-memory. WebSocket broadcaster also uses `_last_result`.
- **Flows verdict is validated JSON blob**: `shared/schemas.py: FlowVerdict` strict pydantic with nested TLS/Cert/Assessment/PolicyDecision, with honesty invariant for is_tls13_opaque. `api/db.py:upsert_flows` validates via `FlowVerdict.model_validate` before write, then `json.dumps(f.model_dump())`.
- **Pcaps live on filesystem**: `lab/pcaps/family-*.pcap` ~1-60KB each × 10+40 synth families, `lab/reassembled/*.bin` 120B, `lab/manifest.json` docs/FAMILY_TAXONOMY 40-core table mapping port/tls/cipher/kex/cert/starttls/flag/buf. `lab/scripts/synth_families.py:make_pcap` uses scapy Ether/IP/TCP/Raw + TLSRecord/TLSClientHello with GREASE filtering, deterministic via `hashlib.sha256` + `random.Random(seed)`.
- **Turnup is pure Docker single-port**: `docker-compose.yml` defines single service `demo` build `.` port 8000:8000, healthcheck curl /health or /flows, env PYTHONHASHSEED=0 OMP_NUM_THREADS=6. `scripts/turnup.sh` does `docker compose up -d --build demo` plus optional `--profile lab` (postfix/dovecot/mockdns). `lab/docker-compose.yml` defines 5 lab services on 172.31.0.0/24 bridge.
- **Dockerfile baked SQLite touch**: `Dockerfile:56` does `touch /app/api/flows.db && chmod 666 /app/api/flows.db` — will be replaced by Postgres client libs + waiting for pg_isready in new plan.
- **Dashboard fetches flows client-side fallback**: `dashboard/src/services/api.js: fetchFlows` fetches `/api/flows` with no-store, falls back to `getFallbackFlows()` 10 hardcoded families if list length <5. `Families.jsx` merges `flowsById` map over manifest `synthesizeFamilies()` but relies on flows array completeness; filtered/sorted/paginated client-side.
- **Families page synthesizes up to 60 families**: `Families.jsx: synthesizeFamilies()` base 10 + loop 11..60 deterministic ciphers/certs/tls/ports/posture; `Live.jsx` synthesizes pcap via `synthesizePcapBlob` client-side; both POST `/api/analyze` then `fetchFlows()` refresh.
- **No existing migrations**: No alembic, psycopg, asyncpg, sqlalchemy in requirements.txt; search confirms no postgres references.
- **Clarification 2026-08-28 (round3)**: Families tab must "show if pcap has actually run for that family in the DB then show else say not run" → status is DERIVED via LEFT JOIN families→flows/pcap_files existence, not static enum alone; seed dashboard 10 flows remain visible as runs, others stay not_run until Play→flows upsert.
- **Follow-up 2026-08-28 (round2)**: Families not_run UI badge + Inspect matrix list, Dashboard monitored flows click cross-filters graphs (PowerBI), triage reminders sorted by highest risk_score, protocol analysis DB-bound, model_training metadata seeded and used in graphs + recent packets via DB.
- **New follow-up 2026-08-28**: User requires "Use postgres consistently across all the sites" and "initially make all the families in the families tab as not run and the ones we show in the dashboard they should run on turnup" → plan must add families.status enum + dashboard auto-run seed job.
- **Online research verdict**: Postgres `/docker-entrypoint-initdb.d` scripts run ONLY when data directory empty → init-only seed skips on existing volume (seedfa.st 2026-07-10, docs.docker.com). Bytea TOAST stores binary out-of-line, 1GB limit, entire bytea loads into memory on read/write (cybertec). Hybrid BYTEA <5MB vs large spill recommended for 100MB uploads but user chose pure BYTEA. Named volumes vs bind mounts: named portable, bind visible for host backup.

## Decisions (with rationale — user answered 8 multiple-choice)
1. **Topology A + named volume (Recommend)**: Add `postgres:16-alpine` service to existing `docker-compose.yml` (not separate compose), named volume `pgdata:/var/lib/postgresql/data`, healthcheck `pg_isready -U $POSTGRES_USER`. Rationale: keeps `git clone → docker compose up` UX; lab profile stays orthogonal; named volume survives `down` without `down -v`, survives across demo restarts, supports turnup wait_for health.
2. **PCAP storage A: BYTEA**: Column `pcap_files.data BYTEA` holds full pcap binary TOASTed; metadata columns `sha256, byte_length, family_id, created_at`. Rationale: user choice; transaction-safe, no filesystem drift, backup includes pcaps; acceptable at ~3MB seed + 100MB max upload (memory load transiently okay).
3. **Schema shape A: JSONB blob**: `flows.data JSONB` stores entire FlowVerdict dump; plus extracted `flow_id TEXT PK`, `created_at`, `updated_at`, `version INT`. Alternative indexed columns deferred. Rationale: user choice; minimal code change from SQLite TEXT json; preserves strict validation; allows later migration to generated columns.
4. **Table separation: Separate tables (user choice)**: Create 6 tables: `families` (static taxonomy copy of manifest, 60 rows), `pcap_files` (BYTEA), `flows` (canonical verdicts), `flows_history` (versioned), `lab_runs` (lab matrix synthetic runs), `live_captures` (ephemeral), `report_runs` (join materialization). Rationale: enables distinct retention, TTL, truncate live without affecting families/flows.
5. **Seed: Init-only (user choice) with mitigation**: Schema via `init-db/01_schema.sql` mounted to `/docker-entrypoint-initdb.d` runs only on empty `pgdata`. Seed data via `02_seed.sql` OR via Python `api/seed.py` called from `turnup.sh` after `pg_isready` (idempotent INSERT ON CONFLICT DO UPDATE). Risk: init-only alone won't re-seed when adding families 61+ without `down -v`; plan will add idempotent app-startup seed path even though user chose init-only, to prevent drift — reconcile in plan as "init-only primary + startup upsert guard".
6. **Families score fix: Fix + keep history**: Remove `_last_result` short-circuit in `GET /flows` and `GET /report`; always `SELECT` from Postgres ordered by `updated_at DESC`; on POST `/api/analyze` upsert + append to `flows_history` with version increment; latest version wins; add index `flows(data->>'assessment'->>'risk_level')` via GIN for filters. Rationale: preserves scores across runs, never resets others.
7. **Live lifecycle A: TRUNCATE on turnup**: `scripts/turnup.sh` adds `psql -c "TRUNCATE live_captures RESTART IDENTITY"` when `--with-lab` or on `--fresh` flag; or on `scripts/turndown.sh --with-lab` hook. Separate table ensures families/flows persist.
8. **Dashboard/reports source C: Materialized views**: Create `mv_dashboard_metrics` (risk counts, avg posture, cipher histogram, tls histogram, ja4 rarity buckets) refreshed via `REFRESH MATERIALIZED VIEW CONCURRENTLY` trigger on flow upsert; new endpoints `GET /api/metrics` and `GET /api/reports?family_id=` join `pcap_files`→`flows` with pagination/bounded BYTEA download. Rationale: user choice; fast dashboard vs client derive.
10. **Consistent Postgres across all sites (follow-up 2026-08-28)**: Every site (dashboard, families, lab, live, reports) reads from Postgres via /api/*; remove client-side fallback synthesis and manifest JSON fallback once DB seeded; Lab/Live uploads write directly to Postgres; single connection string shared via POSTGRES_DSN env across demo + api services.
11. **Families initial not_run + dashboard auto-run (follow-up 2026-08-28)**: On turnup seed, insert 60 rows into `families` with `status='not_run'`, `last_run_at=NULL`; dashboard subset (families 01-10 baseline + any with pre-seeded flows) auto-run via `api/seed.py --run-dashboard` that iterates those 10 pcaps through `_real_pipeline_for_bytes` → upsert into flows + history + publish metrics; subsequent user Stream actions transition status `not_run→running→done/failed` and update posture/risk; dashboard reads only flows that have run.

12. **Families derived not_run + Inspect matrix list (round3 clarified)**: Derived status via `SELECT f.*, (EXISTS(SELECT 1 FROM flows WHERE flows.flow_id=f.family_id)) AS has_run` → badge not_run iff not has_run; `families.status` maintained by AFTER INSERT ON flows trigger for indexability but UI derives; click Play inserts flow → badge flips; Inspect Matrix tab lists 23 checks from assessment.findings + flows_history Families.jsx badge `not run yet`; click **Play** (POST /api/analyze) → status `running` → on success `done` + upsert flows + show posture/risk; **Inspect** drawer new tab "Matrix" renders 23-check list from `assessment.findings` + derived `severityFor` logic now DB-driven, grouped TLS/Cert/STARTTLS/MTA/Info with severity colors/icons, not hardcoded fallback.
13. **Dashboard PowerBI cross-filter + triage + protocol analysis (follow-up round2)**: `MasterList` flow click sets `selectedFlowId` in React context/nuqs `?flow=` that filters all `Graphs.jsx`, `AnalyticsCapsuleChart`, `ThreatMatrix`, `Protocol Analytics` via `GET /api/metrics?flow_id=` and `GET /api/flows?flow_id=` backed by Postgres `WHERE data @> ...` + matview `mv_protocol_stats`; triage reminders = `SELECT * FROM flows ORDER BY (data->'assessment'->>'risk_score')::int DESC LIMIT 5` (recent packets sorted highest risk) with `updated_at` recency; protocol analysis = `mv_protocol_stats` (app_protocol, tls.version, cipher counts) DB-derived, not static `getDiverseBaselineFlows`.
14. **Model metadata seeded + graphed (follow-up round2)**: New table `model_runs (model_name TEXT PK, trained_at TIMESTAMPTZ, params JSONB, metrics JSONB, artifact_sha TEXT, n_eff INT, dataset_caveat TEXT)` seeded on turnup from `models/*.pkl` sidecars + `assessment/risk_model.py` / `anomaly_model.py` run metadata (stored via `api/ml_enrich.py` lazy load); graphs consume `GET /api/models` + `GET /api/metrics` joining model_runs for calibrated_prob / anomaly thresholds; ensures `git clone → turnup` reproducibly seeds model info alongside pcaps.
9. **Migration: Fresh Postgres (user choice)**: Do not auto-migrate `api/flows.db`; drop SQLite handling on compose up; re-seed from `lab/pcaps/*.pcap`, `shared/fixtures/*.json`, `lab/manifest.json` only. Rationale: clean state, reproduce `git clone` seed; document optional one-shot migration script `scripts/migrate_sqlite_to_postgres.py` for existing devs.

## Open assumptions (announced defaults — not asked, reversible)
| assumption | adopted default | rationale | reversible? |
|---|---|---|---|
| Postgres image pin | `postgres:16-alpine` with sha256 pin, not 15 | Alpine minimal, 16 stable 2026, EOL 2028 | yes |
| Driver | `psycopg[binary]==3.2` async + `sqlalchemy[asyncio]==2.0` via requirements.txt | Binary wheel no build, async FastAPI compatible | yes |
| ORM vs raw | Raw psycopg + SQL files in `init-db/*.sql` + thin `api/db_pg.py` mirroring 4-func API, no heavy Alembic for v1 | Minimal churn, keeps SQLite removed cleanly | yes |
| Volume name | `pgdata` named volume | Portable across laptops/CI, matches docs.docker.com guidance | yes |
| Env vars | POSTGRES_DB=ciphcrest, POSTGRES_USER=app, POSTGRES_PASSWORD from `POSTGRES_PASSWORD` env or generated .env | Matches demo env pattern | yes |
| Port expose | 5432 not exposed to host by default (internal compose network only) | Secure by default; app connects via service name `postgres:5432` | yes |
| Bytea load strategy | Read BYTEA via `psycopg.Binary` streaming; no large-object fallback unless >1GB (guard 413 already) | API already 413 >100MB | yes |
| JSONB validation | Keep `FlowVerdict.model_validate` in Python before INSERT; DB adds CHECK (jsonb_typeof) | Double gate | yes |
| Families table source | Populate from `lab/manifest.json` + taxonomy md + derived posture baseline; not from DB flows | Ensures 60 families visible even pre-analysis | yes |
| History retention | Keep all versions (no pruning) for families/reports; live_captures TRUNCATE clears | Audit trail | yes |
| Refresh strategy | Debounced LISTEN/NOTIFY 5s REFRESH CONCURRENTLY (unique index required), not trigger tx | Avoids deadlock, fallback not needed | yes |
| Medium UX | Loading skeleton while pg_isready, split ?q vs ?flow, lpad sort, Live WS same-origin, synth pcap contracted sha256 | Prevents flash/collision/OOM | yes |
| History all runs | Every upsert (families/lab/live) appends to *_history partitioned, never UPDATE without history | Audit trail per rerun | yes |

## Scope IN
- Add postgres service + pgdata volume + init-db SQL + wait-for-healthy in turnup.sh and docker-compose.yml
- Replace api/db.py SQLite impl with Postgres impl (or new api/db_pg.py + shim) preserving query_all/query_by_flow_id/query_history/query_all_history/upsert_flows signatures + async pool
- Update Dockerfile to install libpq/psycopg, remove SQLite file touch, add seed step
- Create seed orchestration: deterministic load of 60 pcaps + 10-50 fixtures + manifest entries into families/pcap_files/flows
- Fix api/app.py to not use _last_result as primary; make GET /flows, /report, /flows/history DB-backed; keep _last_result as optional in-memory LRU only for websocket broadcast or remove
- Add new endpoints: GET /api/families, GET /api/pcap_files/:family_id/download, GET /api/metrics, GET /api/reports/:family_id/packets
- Update dashboard/src/services/api.js (extend only, no restyle) — swap fetchFlows to GET /api/flows vs fallback, add GET /api/families/metrics/models wrappers keeping existing TOK/Recharts + Families.jsx + Lab.jsx + Live.jsx to call /api/metrics and not synthesize fallback when DB has data
- Add TRUNCATE live_captures lifecycle hook in scripts/turnup.sh and scripts/turndown.sh
- Add materialized views + indexes + GIN for JSONB queries
- Add families.status lifecycle (not_run initially) + dashboard auto-run hook in turnup.sh (seed → run 10 baseline families) so Families tab shows not_run while Dashboard shows executed flows
- Families not_run badge + Play/Inspect matrix list: POST /api/analyze status lifecycle + Inspect drawer 23-check list from DB findings
- Dashboard cross-filter: selected flow filters graphs/protocol analytics via /api/metrics?flow_id= (PowerBI behavior)
- Triage reminders: ordered by risk_score DESC via DB query (recent highest risk packets)
- Protocol analysis: DB-driven via mv_protocol_stats (counts by app_protocol/tls.version)
- Model metadata: model_runs table seeded on turnup + GET /api/models consumed by graphs
- Enforce consistent Postgres across all sites: gate dashboard/Lab/Live/Families/Reports behind DB readiness, remove fallback JSON/manifest paths when DB reachable
- Update README/docs/LARGE_FILES.md for `git clone → docker compose up` with Postgres

## Scope OUT (Must NOT have)
- No S3/minio external storage for pcaps (BYTEA only per user choice)
- No host-managed Postgres or separate repo
- No migration of SQLite rows on default path (fresh only; optional migrator script out-of-band)
- No Alembic heavy migration framework in v1 (raw SQL files)
- No removal of scapy fallback reassembler; keep stub for offline fallback even if DB empty
- No frontend rewrite to server-side pagination beyond families limit/offset already
- No auth/RBAC on DB access beyond compose internal network
- No sharding or read-replica
- No UI theme redesign (TOK colors/tokens/layout stay frozen unless wiring explicitly requires new badge/tab; extend, don't restyle)
- No client-side static fallback for triage/protocol/model graphs — all via Postgres once seeded

## Open questions (all resolved via interview — remaining confirmations for approver)
- Confirm init-only seed risk: Are you okay that adding families 61+ later requires `docker compose down -v` or manual `python -m api.seed` to re-seed, since init scripts won't re-run on non-empty volume? Plan adds startup upsert guard; need explicit ack.
- Confirm TRUNCATE boundary: Should `TRUNCATE live_captures` run on every `turnup.sh` (even without --with-lab) or only when `--with-lab` / `turndown.sh --with-lab`?
- Confirm report packet granularity: Should `report_runs` materialize per-packet rows (requires tshark parse → packets table) or per-flow + pcap blob download is sufficient for "actual data queried from DB"?
- No new questions to block — decisions above are sufficient to draft plan.

## Coverage completeness + Medium problems + History for all runs (user 2026-08-28 round4)
User insists: solve MEDIUM problems too, cover every project point, analysis data and reruns must have history for runs and stuff.

**Adopted coverage:**
- Every site (families/lab/live/dashboard/reports/triage/protocol/model) Postgres only — no fallback.
- Analysis data + reruns versioned: `flows_history` for synthetic families + `live_captures` history via `live_captures_history` table or reuse `flows_history` partitioned by source; `lab_runs` history via `lab_runs_history`; `model_runs` versioned via `model_runs_history`.
- Medium frontends: Postgres readiness gate (loading skeleton vs 503 banner), Families ?q collision split to ?q search vs ?flow deep-link, client synth pcap dialect contracted via sha256/byte_length headers, optimistic flash handled, lexical family sort lpad, Live WS streaming fallback, Reports BYTEA pagination + Range.
- Medium backend operational: Dockerfile remove flows.db touch + add pgcrypto, turnup.sh wait_for postgres before HTTP health, report packet granularity deferred (join pcap_files→flows sufficient), Create Index CONCURRENTLY outside TX, TRUNCATE boundary decided (--with-lab only), lab_runs/report_runs clarified as matviews not tables.

## High-accuracy review — Brutal frontend (Oracle 1) + Backend/DB/ML (Oracle 2) — momus dual required
**Review required: true (user explicitly demanded high quality brutally)**

### Frontend brutal verdict (Oracle persona: React/PowerBI dashboard)
**CRITICAL will ship broken if plan executed as drafted:**
- getFallbackFlows masks empty DB first-clone flash lie → need isLoading/isSeeded empty skeleton, not fallback 10
- synthesizeFamilies 60-row client fabrication hides not_run badge (status never surfaced)
- PowerBI cross-filter is local useState, Graphs/AnalyticsCapsuleChart ignore flow filter (static days 78/88/74)
- Inspect drawer History tab static Version 1, never calls fetchHistory
- Live.jsx WebSocket hardcodes :8000, simulated packets never hit live_captures
- Reports PDF export from firstFlow only, no BYTEA download pagination

**Required fixes before plan freeze:** Define contracts GET /api/families?status, GET /api/flows vs GET /api/metrics?flow_id, GET /api/flows/history, GET /api/pcap_files/:id/download; replace fallback with empty state; rewrite Families data layer to fetch /api/families render status badge; implement ?flow= via nuqs FlowContext filtering Graphs/ThreatMatrix; wire History via fetchHistory paginated; fix Live.jsx WS same-origin + fallback poll live_captures; replace static analytics days + Graphs y=16.5 thresholds with /api/metrics + /api/models.

### Backend/DB/ML brutal verdict (Oracle persona: DB architect + ML platform)
**CRITICAL data loss/incorrect:**
- init-only seed loses families 61+ without down -v → startup-idempotent api/seed.py after pg_isready (not turnup.sh) required; init-db stays bootstrap only
- MAX(version)+1 race under Stream All 60×80ms → duplicate PK swallowed → fix with SELECT FOR UPDATE transaction or sequence
- _last_result hides DB (GET /flows returns 1 forever) → delete globals, always SELECT, order_by updated_at DESC, single queue consumer after COMMIT NOTIFY
- BYTEA TOAST OOM triples RAM (buf.getvalue 100MB × pipeline tmp + Binary) → stream via COPY STDIN BINARY / LargeObject + 413 on Content-Length before read + CHECK octet_length <100MB
- JSONB unindexable triage ORDER BY risk_score → generated columns risk_score INT STORED + indexes + GIN jsonb_path_ops
- Seed ordering non-deterministic UUID churn triggers matview refresh every turnup → deterministic source_id = sha256(family+seed), wrap 60 in BEGIN
- Model thresholds hardcoded 16.5/14.9 → seed model_runs from models/*.pkl sha + metadata.json + splits, wire Graphs ReferenceLine from DB

**Adopted mitigations now locked into plan:** Startup guard > turnup guard (FastAPI lifespan retry), history transaction before REPLACE, derived not_run via families LEFT JOIN flows existence + trigger maintaining families.status for indexability, lexicographic sort fix lpad, TRUNCATE without FK or separate retention 7d, matview CONCURRENTLY unique indexes + LISTEN/NOTIFY debounced 5s not trigger-tx.

**Momus pending:** Dual review requires native momus plan critic pass after draft patch; Oracle 1+2 already recorded; will run momus before plan write.

## UI theme constraint (user 2026-08-28 round5)
User: "Do not change the UI theme or stuff unless explicitly needed and just connect the points and extend" → Plan is **connect + extend only**: keep TOK palette (#1F7A4D Forest Green, #E7F5EC, #F6F8F7, #FFFFFF cards), Inter/JetBrains Mono, Donezo shell, Recharts/Tailwind tokens; no visual redesign, no token swaps. All todos are wiring: replace data source (manifest/getFallbackFlows → GET /api/*), keep markup/CSS as-is except minimal status badge + matrix list grouping that reuses existing TOK. Any styling change must be explicitly justified in acceptance (e.g., not_run badge uses TOK.warningLight).

## Approval gate

status: awaiting-approval
approach: See approach header: single-compose postgres + BYTEA + JSONB + separate tables + init-only + history fix + matviews + truncate-live + fresh seed
next: Present 60-second brief, await explicit user "okay"/"approve"/"yes" to write .omo/plans/postgres-pcap-store.md; then append todos.
recorded_at: 2026-08-28
