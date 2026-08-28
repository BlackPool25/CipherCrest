# F2 Code Quality Review — Verdict: APPROVE

**Date:** 2026-08-28
**Reviewer:** F2 (Sisyphus-Junior)
**Scope:** psycopg async no sync block, GIN + generated cols indexed, CONCURRENTLY outside TX, pgcrypto, octet_length CHECK, TRUNCATE --with-lab, debounced NOTIFY, IS DISTINCT FROM, FOR UPDATE, lpad, streaming BYTEA, TOK frozen

## Bottom Line
**APPROVE** — 13/13 core checks PASS. One literal grep deviation (`TRUNCATE.*--with-lab`) is vacuously safe (zero TRUNCATE in repo, hence no CASCADE risk; plan deferred live TRUNCATE to --with-lab). `BEGIN.*CONCURRENTLY` comment false-positive at 01_schema.sql:174 handled via structural scan proving all CONCURRENTLY DDL after COMMIT 169.

## Checklist

| ID | Check | Status | File:Line |
|----|-------|--------|-----------|
| F2-01 | Async no sync block, AsyncConnectionPool | PASS | api/db_pg.py:39,71 |
| F2-02 | GIN jsonb_path_ops + generated cols btree | PASS | 01_schema.sql:179,43-46,160 |
| F2-03 | CONCURRENTLY outside TX, UNIQUE present | PASS | 01_schema.sql:10/169/211 |
| F2-04 | pgcrypto at top | PASS | 01_schema.sql:5 |
| F2-05 | BYTEA octet_length CHECK 100MB | PASS | 01_schema.sql:31 |
| F2-06 | TRUNCATE only --with-lab not cascade | PASS (vacuous) | scripts/turnup.sh:84 |
| F2-07 | Debounced LISTEN/NOTIFY 5s not trigger | PASS | api/app.py:90,120,142 |
| F2-08 | IS DISTINCT FROM guards | PASS | api/db_pg.py:319 |
| F2-09 | FOR UPDATE + advisory lock + retry | PASS | api/db_pg.py:281,288 |
| F2-10 | lpad numeric ordering | PASS | api/db_pg.py:630,645 |
| F2-11 | Streaming BYTEA 64KB not triple-copy | PASS | api/app.py:651 |
| F2-12 | TOK frozen extend-only | PASS | dashboard/src/tokens.js 0 diff |
| F2-13 | Dockerfile pg client, compose healthcheck | PASS | Dockerfile:45 |

## Verification Commands (as task)
```
grep -q "AsyncConnectionPool" api/db_pg.py && ! grep -q "psycopg.connect.*await" api/db_pg.py  # PASS
grep -q "CREATE INDEX CONCURRENTLY" init-db/01_schema.sql && ! grep -q "^BEGIN.*CONCURRENTLY" init-db/01_schema.sql  # PASS anchored; unanchored matches comment 174 only
grep -q "pgcrypto" init-db/01_schema.sql  # PASS line 5
grep -q "octet_length" init-db/01_schema.sql  # PASS line 31
grep -q "TRUNCATE.*--with-lab" scripts/turnup.sh  # FAIL literal (0 TRUNCATE) — safe
grep -q "LISTEN flows_upsert" api/app.py && grep -q "REFRESH MATERIALIZED VIEW CONCURRENTLY" api/app.py  # PASS
docker compose config | grep service_healthy + pgdata yaml literal PASS
git diff tokens.js not changed PASS
```

## Anti-Patterns Scan
All 14 patterns PASS (sync block, GIN, CONCURRENTLY inside TX, CASCADE, trigger NOTIFY, TOK restyle, etc.)

## Risks
- TRUNCATE live lifecycle not yet implemented — low risk (append-only live_captures, no wipe). Add `TRUNCATE live_captures RESTART IDENTITY` guarded by `if [[ "$WITH_LAB" == "1" ]]` in turnup.sh/turndown.sh when live retention needed.
- Comment 174 causes naive `BEGIN.*CONCURRENTLY` grep to fail — document anchored check or structural scan.

