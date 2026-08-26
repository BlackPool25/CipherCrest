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
