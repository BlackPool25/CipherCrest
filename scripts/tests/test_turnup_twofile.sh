#!/usr/bin/env bash
# TDD test for two-file lifecycle: turnup pure Docker + turndown
# Must fail before patch, pass after. Run: bash scripts/tests/test_turnup_twofile.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TURNUP="$ROOT/scripts/turnup.sh"
TURNDOWN="$ROOT/scripts/turndown.sh"
PASS=0; FAIL=0
ok(){ echo "[ok] $*"; PASS=$((PASS+1)); }
fail(){ echo "[fail] $*"; FAIL=$((FAIL+1)); }
check(){
  desc="$1"; shift
  if eval "$*"; then ok "$desc"; else fail "$desc"; fi
}
echo "=== test_turnup_twofile TDD ==="
# 1 pure docker: docker compose up -d present
check "grep docker compose up -d in turnup" "grep -q 'docker compose up -d' \"$TURNUP\""
check "grep docker compose up -d --build" "grep -q 'docker compose up -d --build' \"$TURNUP\" || grep -q 'docker compose up -d.*--build' \"$TURNUP\""
# 2 turndown exists
check "test -f turndown.sh" "test -f \"$TURNDOWN\""
# 3 --help mentions with-lab
check "--help has with-lab" "bash \"$TURNUP\" --help 2>&1 | grep -q 'with-lab'"
# 4 --check keeps python 3.11 check
check "keep python 3.11 check" "grep -q 'python.*3.11\|python3' \"$TURNUP\""
check "keep node >=18 check" "grep -q 'node.*>=18\|node.*18' \"$TURNUP\""
check "keep tshark 4 prefs" "grep -q 'parity 4\|get_tshark_prefs\|tshark.*prefs' \"$TURNUP\""
check "keep wheelhouse <370" "grep -q '370' \"$TURNUP\""
check "keep models prot4 <5M" "grep -q 'prot.*4\|protocol 4' \"$TURNUP\" && grep -q '5M\|5\*1024' \"$TURNUP\""
check "keep gzip <3670016" "grep -q '3670016' \"$TURNUP\""
check "keep check_port_free 8000 via ss/fuser" "grep -q 'check_port_free' \"$TURNUP\" && grep -q 'ss ' \"$TURNUP\" && grep -q 'fuser' \"$TURNUP\""
# 5 wait_for health 30 0.5
check "wait_for health 30 0.5" "grep -q 'wait_for.*health\|wait_for' \"$TURNUP\" && grep -q '30.*0.5\|wait_for.*30' \"$TURNUP\""
# 6 curl /analyze present
check "curl /analyze in turnup" "grep -q 'curl.*/analyze' \"$TURNUP\" || grep -q '/analyze' \"$TURNUP\""
# 7 trap only INT TERM not EXIT
check "trap INT TERM only" "grep -q 'trap.*INT.*TERM' \"$TURNUP\" && ! grep -q 'trap.*EXIT' \"$TURNUP\""
# 8 no native uvicorn when Docker available (no bare uvicorn start)
# Allow uvicorn only in comments about fallback removed; should not have "python.*uvicorn api.app:app" as start command
if grep -q "python3 -m uvicorn api.app:app" "$TURNUP"; then fail "no native uvicorn when Docker available (found uvicorn start)"; else ok "no native uvicorn when Docker available"; fi
# 9 keeps PYTHONHASHSEED 0 OMP_NUM_THREADS 6
check "PYTHONHASHSEED 0" "grep -q 'PYTHONHASHSEED=0' \"$TURNUP\""
check "OMP_NUM_THREADS 6" "grep -q 'OMP_NUM_THREADS=6' \"$TURNUP\""
# 10 turndown checks
if [[ -f "$TURNDOWN" ]]; then
  check "turndown has down" "grep -q 'docker compose.*down' \"$TURNDOWN\""
  check "turndown ss check" "grep -q 'ss ' \"$TURNDOWN\""
  check "turndown rm pid" "grep -q 'rm.*pid\|ciphercrest' \"$TURNDOWN\" || grep -q '\.pid' \"$TURNDOWN\""
  check "turndown log rotation" "grep -q 'turnup.*log\|LOG.*log\|rotation' \"$TURNDOWN\" || grep -q 'logs' \"$TURNDOWN\""
  check "turndown --check idempotent" "bash \"$TURNDOWN\" --check > /tmp/turndown_check.txt 2>&1; grep -q 'ok\|done\|check' /tmp/turndown_check.txt || true; bash \"$TURNDOWN\" --check > /tmp/turndown_check2.txt 2>&1; [[ $? -eq 0 ]]"
  # run --check should exit 0
  if bash "$TURNDOWN" --check >/dev/null 2>&1; then ok "turndown --check exit 0"; else fail "turndown --check exit 0"; fi
  # idempotent second run
  if bash "$TURNDOWN" --check >/dev/null 2>&1 && bash "$TURNDOWN" --check >/dev/null 2>&1; then ok "turndown --check idempotent double run"; else fail "turndown --check idempotent double run"; fi
else
  fail "turndown --check (missing file)"; fail "turndown idempotent (missing)"; fail "turndown ss"; fail "turndown down"; fail "turndown rm pid"; fail "turndown log rotation"
fi
# 11 turnup --check ok
check "turnup --check ok" "bash \"$TURNUP\" --check > /tmp/turnup_twofile_check.txt 2>&1; grep -q 'turnup --check done\|--check done' /tmp/turnup_twofile_check.txt"
# 12 combined verification
check "verification chain" "bash \"$TURNUP\" --check >/dev/null 2>&1 && { [[ -f \"$TURNDOWN\" ]] && bash \"$TURNDOWN\" --check >/dev/null 2>&1; } && grep -q 'docker compose up -d' \"$TURNUP\" && test -f \"$TURNDOWN\""

echo "=== result PASS=$PASS FAIL=$FAIL ==="
if [[ $FAIL -gt 0 ]]; then echo "FAIL $FAIL tests"; exit 1; else echo "ALL PASS $PASS"; exit 0; fi
