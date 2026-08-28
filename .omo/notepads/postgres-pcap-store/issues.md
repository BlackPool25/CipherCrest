## 2026-08-28 Task 1 issues

- No issues blocking. Note: `docker compose config` renders volumes as long-form `source: pgdata target: /var/lib/postgresql/data` not short `pgdata:/var/lib/postgresql/data`; yml literal still `pgdata:/var/lib/postgresql/data` and config structured check confirms. Stale_state checked via second config diff identical. Dirty_worktree only docker-compose.yml + init-db/.gitkeep staged.
- Adversarial classes not applicable per task: malformed_input (compose yaml validated via yaml.safe_load), prompt_injection (no user input to compose), cancel/resume (no), hung_commands (compose config <1s), flaky_tests (deterministic config), repeated_interruptions (single edit) — one-line each.


## 2026-08-28 Task 2 issues

- No blocking issues. Idempotent second run initially warned duplicate indexes but IF NOT EXISTS suppressed error and exit 0; CONCURRENTLY outside transaction verified via pg_isready ephemeral; pgcrypto extension present before gen_random_uuid. Stale_state probed by running psql -f twice — second must not error duplicate_table, confirmed IF NOT EXISTS handling. Dirty_worktree only init-db/01_schema.sql (removed .gitkeep). Misleading_success_output checked via actual pg_indexes and REFRESH CONCURRENTLY not just file exists. Hung_commands timeout 15s for docker exec psql passed.
- Adversarial classes not applicable per task: malformed_input (no user parsing, DDL fixed), prompt_injection (no user input to DDL), cancel/resume (single atomic DDL), flaky_tests (deterministic postgres:16-alpine pinned), repeated_interruptions (single commit) — one-line each.

## 2026-08-28 Task 3 issues

- No blocking issues. Builder libpq-dev added though psycopg[binary] wheel does not need compile, but kept for source fallback. Runtime postgresql-client adds 58MB (libpq5+perl) but required for pg_isready/psql health scripts; layer caching efficient via separate RUN after chown. Stale_state checked via docker build --no-cache? Used fresh build with new Dockerfile hash, verified docker run import reflects new version 3.2.5 not stale 3.3.4 (host had 3.3.4, container correctly 3.2.5). Dirty_worktree only Dockerfile+requirements.txt+api/tests/test_docker_psycopg.py+evidence+learnings (expected). Misleading_success_output checked via actual docker run import not just grep, and flows.db absent via ls inside container not just Dockerfile grep. Hung_commands docker build timeout 5m, completed 33s.
- Adversarial classes not applicable per task: malformed_input (no user parsing), prompt_injection (no), cancel/resume (single commit), flaky_tests (deterministic docker build), repeated_interruptions (single edit) — one-line each.
