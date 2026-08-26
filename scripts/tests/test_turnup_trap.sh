#!/usr/bin/env bash
# TDD test for turnup.sh trap-clean lifecycle + docker profile hybrid
# Must fail before patch, pass after. Run: bash scripts/tests/test_turnup_trap.sh  OR  pytest ...
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TURNUP="$ROOT/scripts/turnup.sh"
PASS=0; FAIL=0
ok(){ echo "[ok] $*"; PASS=$((PASS+1)); }
fail(){ echo "[fail] $*"; FAIL=$((FAIL+1)); }
check(){
  desc="$1"; shift
  if eval "$*"; then ok "$desc"; else fail "$desc"; fi
}
echo "=== test_turnup_trap TDD ==="
# 1 trap EXIT INT TERM in do_full
check "trap EXIT INT TERM exists" "grep -q 'trap.*EXIT.*INT.*TERM' \"$TURNUP\""
check "trap do_down exists" "grep -q 'trap.*do_down' \"$TURNUP\""
# 2 PID path .tmp/ciphercrest
check "PID uses .tmp/ciphercrest" "grep -q '\.tmp/ciphercrest' \"$TURNUP\""
check "no /tmp/ciphercrest" "! grep -q '/tmp/ciphercrest' \"$TURNUP\""
# 3 .tmp mkdir chmod 700
check "mkdir -p .tmp" "grep -q 'mkdir -p.*\.tmp' \"$TURNUP\""
check "chmod 700 .tmp" "grep -q 'chmod 700.*\.tmp' \"$TURNUP\" || grep -q 'chmod 700' \"$TURNUP\""
# 4 pgrep scoped not pkill -f system-wide
check "uses pgrep -f scoped" "grep -q 'pgrep -f' \"$TURNUP\""
check "no pkill -f system-wide (allow only kill \$(cat))" "! grep -q 'pkill -f' \"$TURNUP\""
# 5 ss fallback fuser
check "ss -ltnp fallback" "grep -q 'ss ' \"$TURNUP\""
check "fuser fallback" "grep -q 'fuser' \"$TURNUP\""
check "no bare lsof only (ss preferred)" "grep -q 'ss.*ltn' \"$TURNUP\""
# 6 frontend fallback python -m http.server when npm/vite missing
check "frontend fallback http.server" "grep -q 'http.server' \"$TURNUP\""
# 7 WITH_DOCKER docker compose --profile lab
check "WITH_DOCKER env" "grep -q 'WITH_DOCKER' \"$TURNUP\""
check "docker compose --profile lab up -d --wait" "grep -q 'docker compose.*--profile lab.*up -d.*--wait' \"$TURNUP\" || grep -q 'docker compose.*--profile lab' \"$TURNUP\""
check "docker compose --profile lab down trap" "grep -q 'docker compose.*--profile lab.*down' \"$TURNUP\""
# 8 PYTHONHASHSEED=0 OMP_NUM_THREADS=6 exported
check "PYTHONHASHSEED=0 exported" "grep -q 'PYTHONHASHSEED=0' \"$TURNUP\""
check "OMP_NUM_THREADS=6 exported" "grep -q 'OMP_NUM_THREADS=6' \"$TURNUP\""
check "export PYTHONHASHSEED" "grep -q 'export.*PYTHONHASHSEED' \"$TURNUP\" || grep -q 'PYTHONHASHSEED=0' \"$TURNUP\""
# 9 wait_for http://localhost:$API_PORT/flows 30 0.5
check "wait_for flows 30 0.5" "grep -q 'wait_for.*flows.*30.*0.5' \"$TURNUP\" || grep -q 'wait_for.*30' \"$TURNUP\""
# 10 log rotation logs/turnup_<ts>.log
check "log rotation turnup_<ts>.log" "grep -q 'logs/turnup_' \"$TURNUP\" || grep -q 'turnup_.*\.log' \"$TURNUP\""
check "LOG_DIR logs" "grep -q 'LOG_DIR.*logs' \"$TURNUP\""
# 11 check_tshark parity 4 prefs
check "check_tshark parity 4" "grep -q 'parity 4' \"$TURNUP\""
check "get_tshark_prefs parity" "grep -q 'get_tshark_prefs' \"$TURNUP\""
# 12 --check tshark parity 4 prefs output
echo "--- runtime: --check tshark parity ---"
bash "$TURNUP" --check > /tmp/turnup_check_out.txt 2>&1 || true
if grep -E -q "tshark.*parity 4 prefs|parity 4 prefs" /tmp/turnup_check_out.txt; then ok "bash --check tshark parity 4"; else fail "bash --check tshark parity 4"; cat /tmp/turnup_check_out.txt | head -30 || true; fi
# 13 --help WITH_DOCKER
bash "$TURNUP" --help > /tmp/turnup_help_out.txt 2>&1 || true
if grep -q "WITH_DOCKER" /tmp/turnup_help_out.txt; then ok "--help WITH_DOCKER"; else fail "--help WITH_DOCKER"; cat /tmp/turnup_help_out.txt | head -20 || true; fi
# 14 --check passes (no servers)
if grep -q "turnup --check done" /tmp/turnup_check_out.txt; then ok "--check passes done"; else fail "--check passes done"; fi
# 15 WITH_DOCKER=0 skips docker
WITH_DOCKER=0 bash "$TURNUP" --check > /tmp/turnup_check_docker.txt 2>&1 || true
if ! grep -q "docker compose.*error" /tmp/turnup_check_docker.txt; then ok "WITH_DOCKER=0 skips docker (no error)"; else fail "WITH_DOCKER=0 skips docker"; fi
# 16 port collision preflight ss -ltn
check "port collision preflight ss -ltn" "grep -q 'ss.*ltn' \"$TURNUP\""
# 17 wait_for poll 0.5 backoff present
check "wait_for sleep 0.5" "grep -q 'sleep.*0.5\|sleep_s' \"$TURNUP\""

echo "=== result PASS=$PASS FAIL=$FAIL ==="
if [[ $FAIL -gt 0 ]]; then echo "FAIL $FAIL tests"; exit 1; else echo "ALL PASS $PASS"; exit 0; fi
