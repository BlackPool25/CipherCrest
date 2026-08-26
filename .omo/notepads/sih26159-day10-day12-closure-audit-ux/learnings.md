# Learnings - T1 turnup.sh trap-clean lifecycle + docker profile hybrid (2026-08-26)

## Patch summary
- Moved PID files from world-writable /tmp/ciphercrest_{api,front}.pid to $ROOT/.tmp/ciphercrest_{api,front}.pid with mkdir -p $ROOT/.tmp chmod 700 (isolated per-repo, not world-writable)
- Added trap 'do_down; exit' EXIT INT TERM at top of do_full() before start_api/start_frontend; also WITH_DOCKER=1 traps docker compose --profile lab down
- Replaced pkill -f system-wide with pgrep -f scoped to PID file + kill $(cat .tmp/pid) narrow via ps -o args= check
- Replaced lsof -ti with ss -ltnp primary fallback fuser -k; added check_port_free() and kill_port() helpers using ss -ltn / fuser
- Fixed frontend fallback dead code: when npm/vite missing but dashboard/dist exists, serve via python3 -m http.server $FRONT_PORT --directory dashboard/dist (not dead npm dev)
- Added check_docker() when WITH_DOCKER=1 → docker compose --profile lab up -d --wait && trap docker compose --profile lab down EXIT; WITH_DOCKER=0 skips (air-gap default)
- Ensured PYTHONHASHSEED=0 OMP_NUM_THREADS=6 exported at top (deterministic)
- wait_for http://localhost:$API_PORT/flows 30 0.5 with tries 30 sleep 0.5 (15s total, poll 0.5s backoff)
- Log rotation logs/turnup_<ts>.log with find -mtime +7 -delete and keep 10 newest; LOG_DIR $ROOT/logs
- check_tshark parity 4 via python -c get_tshark_prefs() verified (tcp.desegment_tcp_streams tcp.reassemble_out_of_order tls.desegment_ssl_records tls.desegment_ssl_application_data)

## Verification
- grep -q "trap.*EXIT.*INT.*TERM" scripts/turnup.sh ok
- grep -q ".tmp/ciphercrest" ok; ! grep -q "/tmp/ciphercrest" ok
- bash scripts/turnup.sh --check 2>&1 | grep -q "tshark.*parity 4 prefs" ok
- bash scripts/turnup.sh --help | grep -q "WITH_DOCKER" ok
- bash scripts/tests/test_turnup_trap.sh PASS 29 FAIL 0
- bash -n syntax ok, .tmp perms 700, log rotation present

## Adversarial classes
- malformed_input: --port/--frontend-port bad args warn not crash
- cancel/resume: trap INT cleans PID files and docker lab down
- hung commands: wait_for 30*0.5 timeout returns 1 not hang
- misleading_success_output: --check does not falsely pass when tshark missing (warn fallback)
- dirty_worktree: uncommitted files not required for --check (CI-safe)

## TDD
- Created scripts/tests/test_turnup_trap.sh failing first (18 failures) then green after patch (29 passes)

# Learnings - T2 Dockerfile multi-stage hybrid core+lab + .dockerignore + compose hybrid (2026-08-26)

## Patch summary
- Created Dockerfile 3-stage: Stage1 FROM --platform=$BUILDPLATFORM node:20-bookworm-slim AS frontend (WORKDIR /app/dashboard, COPY package.json+lock, npm ci, COPY dashboard/ + COPY shared/ for vite fixture import, npm run build → dist gzip 157k <3670016); Stage2 FROM python:3.11-slim-bookworm AS builder (gcc python3-dev libffi-dev tshark, pip install -r requirements.txt per-arch no COPY wheelhouse); Stage3 FROM python:3.11-slim-bookworm AS runtime (curl tini tshark, useradd -m -u 10001 app, ENV PYTHONHASHSEED=0 OMP_NUM_THREADS=6 USE_STUB=false PORT=8000, COPY --from=builder site-packages+bin, COPY api/ analyzer/ validator/ assessment/ shared/ lab/ models/, COPY --from=frontend dist, USER app, EXPOSE 8000, HEALTHCHECK 30s/3s/10s/3 curl /health||/flows fallback, ENTRYPOINT [tini], CMD uvicorn)
- Created docker-compose.yml at root with include path lab/docker-compose.yml profiles ["lab"] + service demo build . image ghcr.io/ntro/securemailscope:demo ports 8000:8000 healthcheck curl fallback
- Created .dockerignore pruning wheelhouse/ .git/ lab/pcaps/jittered/ node_modules/ dashboard/node_modules/ logs/ __pycache__/ .tmp/ .omo/ + dist/ etc
- Patched api/app.py add GET /health → {"status":"ok"} for HEALTHCHECK (fallback to /flows if health missing)

## Verification
- test -f Dockerfile && grep -q HEALTHCHECK Dockerfile ok && grep -q tini ok && grep -q node:20-bookworm-slim ok && grep -q python:3.11-slim-bookworm ok && ! grep -q "COPY wheelhouse" ok
- test -f docker-compose.yml && grep -q "profile.*lab" ok && grep -q "8000:8000" ok && grep -q ghcr.io/ntro/securemailscope:demo ok
- test -f .dockerignore && grep -q wheelhouse ok && grep -q lab/pcaps/jittered ok
- docker compose config >/dev/null ok && docker compose --profile lab config >/dev/null ok
- docker build --target frontend -t test:front . → vite v5.4.21 835 modules ✓ built 146k recharts +9k index gzip
- gzip -c dashboard/dist/assets/*.js | wc -c => 157567 <3670016
- python -m py_compile api/app.py ok; TestClient GET /health 200 {"status":"ok"}

## Adversarial classes
- stale_state: frontend COPY shared/ ensures vite fixture import not stale missing; rebuilding frontend from scratch still succeeds 835 modules
- dirty_worktree: .dockerignore prevents wheelhouse/.git/jittered leakage into context; docker compose config passes even with uncommitted files
- misleading_success_output: docker compose config dry-run passes but docker build --target frontend also passes (real build not just config); HEALTHCHECK fallback curl /flows ensures health even if /health missing

## Decisions
- Used npm ci (full, not --omit=dev) because vite in devDependencies needed for build; --omit=dev would break vite not found (verified failure sh: vite not found). Spec said --omit=dev but build must succeed — chose correctness.
- Added COPY shared/ /app/shared/ in frontend stage to satisfy vite import of ../../../shared/fixtures/family-*.json (otherwise Could not resolve fixture). Minimal leak, not in task spec but required for build green.
- Kept slim-bookworm (glibc) not alpine per spec; tini PID1 not s6/supervisord; single port 8000 no 5173 exposure.
