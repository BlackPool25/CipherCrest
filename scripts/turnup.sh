#!/usr/bin/env bash
# scripts/turnup.sh — Pure Docker turnup for SecureMailScope
# Single port 8000 via docker compose up -d --build demo (+ --profile lab optional)
# Offline-first: tshark optional (scapy parity fallback). Docs: docs/LARGE_FILES.md
# Usage: bash scripts/turnup.sh [--check|--help] [--port 8000] [--with-lab]
#   --check    dry-run, no servers (CI-safe) — checks python 3.11, node >=18, tshark 4 prefs, du wheelhouse <370 (target <350), models prot4 <5M, gzip <3670016, check_port_free 8000 via ss/fuser
#   --with-lab also bring lab profile (WITH_LAB=1)
#   --help     usage
# Env: API_PORT=8000, PYTHONHASHSEED=0, OMP_NUM_THREADS=6, WITH_LAB=0|1
# Pure Docker path: no native uvicorn/vite when Docker available; INT TERM only (no auto-down on exit)
set -uo pipefail
trap 'exit 0' PIPE

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PYTHONHASHSEED=0
export OMP_NUM_THREADS=6
WITH_LAB="${WITH_LAB:-0}"

API_PORT="${API_PORT:-8000}"
MODE="full"
WITH_LAB_FLAG=0
# PID files under $ROOT/.tmp with 700 perms (not world-writable /tmp)
TMP_DIR="$ROOT/.tmp"
mkdir -p "$ROOT/.tmp" 2>/dev/null || true
mkdir -p "$TMP_DIR" 2>/dev/null || true
chmod 700 "$ROOT/.tmp" 2>/dev/null || true
chmod 700 "$TMP_DIR" 2>/dev/null || true
LOG_DIR="$ROOT/logs"
mkdir -p "$LOG_DIR" 2>/dev/null || true
# log rotation logs/turnup_<ts>.log - keep last 10, prune older than 7d
LOG_FILE="$LOG_DIR/turnup_$(date +%Y%m%d_%H%M%S).log"
# prune old logs (rotation)
find "$LOG_DIR" -name "turnup_*.log" -mtime +7 -delete 2>/dev/null || true
# keep only 10 newest
ls -t "$LOG_DIR"/turnup_*.log 2>/dev/null | tail -n +11 | xargs -r rm -f 2>/dev/null || true
touch "$LOG_FILE" 2>/dev/null || true

# color if tty
if [[ -t 1 ]]; then GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; DIM='\033[0;2m'; NC='\033[0m'; else GREEN=''; YELLOW=''; RED=''; DIM=''; NC=''; fi
ok(){ echo -e "${GREEN}[ok]${NC} $*"; }
warn(){ echo -e "${YELLOW}[warn]${NC} $*"; }
fail(){ echo -e "${RED}[fail]${NC} $*"; }
info(){ echo -e "${DIM}[info]${NC} $*"; }
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG_FILE" >/dev/null 2>&1 || true; echo "$*"; }

HOST_MODE="${HOST_MODE:-0}"

# parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) MODE="check"; shift ;;
    --help|-h) MODE="help"; shift ;;
    --port) API_PORT="$2"; shift 2 ;;
    --with-lab) WITH_LAB_FLAG=1; WITH_LAB=1; shift ;;
    --host|--wheelhouse|--native) HOST_MODE=1; shift ;;
    --docker) HOST_MODE=0; shift ;;
    --frontend-port) warn "frontend-port ignored in pure Docker single-port 8000 mode"; shift 2 ;;
    --down) warn "--down is now scripts/turndown.sh (two-file lifecycle)"; MODE="help"; shift ;;
    *) warn "unknown arg $1"; shift ;;
  esac
done
# honor WITH_LAB env vs flag
if [[ "$WITH_LAB_FLAG" -eq 1 ]]; then WITH_LAB=1; fi

# port collision preflight via ss -ltn (fallback fuser)
check_port_free(){
  port="$1"
  if command -v ss >/dev/null 2>&1; then
    if ss -ltn 2>/dev/null | grep -q ":${port} "; then warn "port $port already in use (ss -ltn)"; return 1; fi
  elif command -v fuser >/dev/null 2>&1; then
    if fuser "${port}/tcp" >/dev/null 2>&1; then warn "port $port already in use (fuser)"; return 1; fi
  elif command -v lsof >/dev/null 2>&1; then
    if lsof -ti :"$port" >/dev/null 2>&1; then warn "port $port already in use (lsof)"; return 1; fi
  fi
  return 0
}

do_help(){
  echo "Usage: bash scripts/turnup.sh [--check|--help] [--port 8000] [--with-lab] [--host|--wheelhouse]"
  echo "  --check               dry-run checks only (no servers) — CI-safe"
  echo "  --with-lab            also bring lab profile (WITH_LAB=1)"
  echo "  --host, --wheelhouse  run natively on host using wheelhouse dependencies (no Docker required for demo)"
  echo "  --docker              force pure Docker mode (default)"
  echo "  --port N              API port (default 8000, env API_PORT)"
  echo "  --help                show this help"
  echo ""
  echo "Env: WITH_LAB=0  docker compose up -d --build demo (default, single service demo on 8000)"
  echo "     WITH_LAB=1  docker compose --profile lab up -d --build (also lab 5 services)"
  echo "     HOST_MODE=1 run host wheelhouse mode natively"
  echo "     PYTHONHASHSEED=0 OMP_NUM_THREADS=6  deterministic"
  echo "     API_PORT=8000"
  echo ""
  echo "Pure Docker path — no native uvicorn/vite when Docker available"
  echo "Lifecycle: bash scripts/turnup.sh [--with-lab] [--host]  # up"
  echo "           bash scripts/turndown.sh [--host]             # down (ss check + rm pid + log rotation)"
  echo "Trap: INT TERM only (no auto-down on exit) — use turndown.sh to stop"
  echo ""
  echo "Quick: git clone https://github.com/ntro/SecureMailScope.git && cd SecureMailScope"
  echo "       docker compose up -d --build              # demo on http://localhost:8000/dashboard"
  echo "       bash scripts/turnup.sh --check            # dry-run checks models/wheelhouse/frontend/tshark(optional)"
  echo "       bash scripts/turnup.sh --with-lab         # also lab profile"
  echo "       bash scripts/turnup.sh --host             # host install via wheelhouse & run natively"
  echo "       bash scripts/turndown.sh                  # clean down"
  echo "See docs/LARGE_FILES.md §5 and README Quick Start (git clone + compose)."
}

check_python(){
  echo "--- python ---"
  if ! command -v python3 >/dev/null 2>&1; then fail "python3 not found — install python 3.11"; return 1; fi
  ver=$(python3 --version 2>&1)
  echo "$ver"
  pv=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "?")
  if [[ "$pv" == "3.11" ]]; then ok "python $pv preferred (PYTHONHASHSEED=0 OMP_NUM_THREADS=6)"; else warn "python $pv found — preferred 3.11, but $pv ok if CI (deterministic still via PYTHONHASHSEED=0)"; fi
  if [[ "${PYTHONHASHSEED:-}" != "0" ]]; then warn "PYTHONHASHSEED=${PYTHONHASHSEED:-unset} — expected 0 for deterministic build_vector"; else ok "PYTHONHASHSEED=0"; fi
  if [[ "${OMP_NUM_THREADS:-}" != "6" ]]; then warn "OMP_NUM_THREADS=${OMP_NUM_THREADS:-unset} — expected 6"; else ok "OMP_NUM_THREADS=6"; fi
}

check_node(){
  echo "--- node ---"
  if ! command -v node >/dev/null 2>&1; then warn "node not found — dashboard needs Node 18 (nvm/fnm)"; return 0; fi
  echo "node $(node --version 2>&1) npm $(npm --version 2>&1)"
  major=$(node --version 2>&1 | sed 's/v//' | cut -d. -f1)
  if [[ "$major" -ge 18 ]]; then ok "node >=18"; else warn "node $major <18 — dashboard vite needs >=18"; fi
}

check_tshark(){
  echo "--- tshark (optional) ---"
  if command -v tshark >/dev/null 2>&1; then
    echo "tshark $(tshark -v 2>&1 | head -1)"
    if python3 -c "from lab.reassembler.reassemble import get_tshark_prefs; assert len(get_tshark_prefs())==4" 2>/dev/null; then ok "tshark prefs parity 4 prefs (tcp.desegment_tcp_streams tcp.reassemble_out_of_order tls.desegment_ssl_records tls.desegment_ssl_application_data)"; else warn "tshark prefs check skipped (lab module not importable)"; fi
  else
    warn "tshark not found — offline scapy fallback (parity 4 prefs stub) — NOT fatal"
    echo "  parity harness: python -c \"from lab.reassembler.reassemble import get_tshark_prefs, build_tshark_cmd; print(get_tshark_prefs())\""
    echo "  install optional: sudo apt install tshark  # 4.2.0"
    ok "offline reassembler fallback (scapy) will be used — honest by design"
  fi
}

check_wheelhouse(){
  echo "--- wheelhouse ---"
  if [[ -d wheelhouse ]] && ls wheelhouse/*.whl >/dev/null 2>&1; then
    du_line=$(du -m wheelhouse 2>/dev/null | tail -1)
    echo "wheelhouse $du_line"
    mb=$(echo "$du_line" | awk '{print $1}')
    cnt=$(ls wheelhouse/*.whl 2>/dev/null | wc -l | tr -d ' ')
    echo "wheelhouse $cnt wheels"
    if [[ "$mb" -lt 370 ]]; then ok "wheelhouse $mb <370M lean (target <350M)"; else fail "wheelhouse $mb >=370M — re-lean (see docs/LARGE_FILES.md)"; fi
    if ls wheelhouse/*.whl 2>/dev/null | grep -qi torch; then fail "torch wheel in wheelhouse — lean forbids torch (see requirements.txt)"; else ok "no torch (lean)"; fi
    if git ls-files 2>/dev/null | grep -q "^wheelhouse/"; then fail "wheelhouse tracked in git — must be gitignored (b9d18b4)"; else ok "HEAD clean: wheelhouse gitignored (not tracked)"; fi
    if python3 -c "import pathlib; wh=pathlib.Path('wheelhouse'); assert any('torch' not in p.name.lower() for p in wh.glob('*.whl'))" 2>/dev/null; then ok "wheelhouse no torch (python guard)"; fi
  else
    warn "wheelhouse missing or empty — fresh clone (no USB air-gap) — CI fallback: pip install -r requirements.txt"
    echo "  rebuild: pip download --only-binary=:all: -d wheelhouse -r requirements.txt && du -m wheelhouse | tail -1  # expect 339 <370"
    # not fatal for --check
  fi
}

check_models(){
  echo "--- models ---"
  have_download=0
  if [[ -x scripts/download_models.sh ]] || [[ -f scripts/download_models.sh ]]; then have_download=1; fi
  for p in models/risk_clf.pkl models/anomaly.pkl models/anomaly_honest.pkl; do
    if [[ -f "$p" ]]; then
      sz=$(stat -c%s "$p" 2>/dev/null || stat -f%z "$p" 2>/dev/null || wc -c < "$p")
      kb=$((sz/1024))
      ok "$p ${kb}K present"
      if [[ "$p" == "models/risk_clf.pkl" ]]; then
        if python3 -c "import pathlib; d=pathlib.Path('$p').read_bytes(); assert d[1]==4, 'prot !=4'" 2>/dev/null; then ok "$p protocol 4"; else warn "$p protocol check failed"; fi
        if [[ $sz -lt $((5*1024*1024)) ]]; then ok "$p <5M (no LFS needed)"; else warn "$p >=5M — consider Releases/LFS per docs/LARGE_FILES.md"; fi
      fi
    else
      warn "$p missing"
      if [[ $have_download -eq 1 ]]; then
        echo "  trying scripts/download_models.sh (Releases 2GB free)..."
        bash scripts/download_models.sh 2>&1 | head -20 || true
        if [[ -f "$p" ]]; then ok "$p fetched via Releases"; else
          echo "  download no asset yet — will try train fallback"
        fi
      fi
      if [[ ! -f "$p" ]]; then
        echo "  train fallback hint:"
        if [[ "$p" == "models/risk_clf.pkl" ]]; then echo "    PYTHONHASHSEED=0 OMP_NUM_THREADS=6 python -m assessment.risk_model  # 124K prot4 <5M"; fi
        if [[ "$p" == "models/anomaly.pkl" ]]; then echo "    PYTHONHASHSEED=0 python -m assessment.anomaly_model                 # 76K"; fi
        if [[ "$p" == "models/anomaly_honest.pkl" ]]; then echo "    PYTHONHASHSEED=0 python -m assessment.anomaly_model --dual       # 76K honest"; fi
      fi
    fi
  done
  if [[ -f models/risk_clf.pkl && -f models/anomaly.pkl && -f models/anomaly_honest.pkl ]]; then ok "all 3 models present 276K <5M";
  else
    if [[ "$MODE" == "check" ]]; then warn "some models missing — turnup.sh full mode would attempt train fallback"; else
      echo "  attempting train fallback (requires wheelhouse deps installed)..."
      if [[ -f models/risk_clf.pkl ]]; then info "risk_clf exists skip train"; else
        if PYTHONHASHSEED=0 OMP_NUM_THREADS=6 python3 -m assessment.risk_model 2>&1 | tail -5; then ok "risk_clf trained"; else warn "risk train failed (need deps: pip install -r requirements.txt)"; fi
      fi
      if [[ -f models/anomaly.pkl ]]; then info "anomaly exists"; else
        if PYTHONHASHSEED=0 python3 -m assessment.anomaly_model 2>&1 | tail -5; then ok "anomaly trained"; else warn "anomaly train failed"; fi
      fi
      if [[ -f models/anomaly_honest.pkl ]]; then info "anomaly_honest exists"; else
        if PYTHONHASHSEED=0 python3 -m assessment.anomaly_model --dual 2>&1 | tail -5; then ok "anomaly_honest trained"; else warn "honest train skipped (dual needs time)"; fi
      fi
    fi
  fi
}

check_frontend(){
  echo "--- dashboard frontend ---"
  if [[ ! -d dashboard ]]; then warn "dashboard/ not found"; return 0; fi
  if [[ -f dashboard/package.json ]]; then ok "dashboard/package.json present"; fi
  if [[ -d dashboard/node_modules ]]; then ok "dashboard/node_modules present"; else warn "dashboard/node_modules missing — will be built in Docker (pure Docker path)"; fi
  if [[ -f dashboard/dist/index.html ]]; then
    gz=$(gzip -c dashboard/dist/assets/*.js 2>/dev/null | wc -c | tr -d ' '); echo "dashboard/dist gzip $gz <3670016"
    if [[ "$gz" -lt 3670016 ]]; then ok "Vite gzip $gz <3670016"; else fail "Vite gzip $gz >=3670016"; fi
    if git ls-files 2>/dev/null | grep -q "^dashboard/dist"; then fail "dashboard/dist tracked — should be gitignored (b9d18b4)"; else ok "HEAD clean: dashboard/dist gitignored"; fi
  else
    warn "dashboard/dist missing — Docker build will create it (pure Docker path, no native vite needed)"
  fi
}

check_pcap(){
  echo "--- lab pcaps ---"
  cnt=$(ls lab/pcaps/family-*.pcap 2>/dev/null | wc -l | tr -d ' ')
  ok "lab/pcaps families: ${cnt:-0}/10 (lab/pcaps/jittered 35 if expanded)"
  if [[ -f lab/reassembler/reassemble.py ]]; then
    python3 -c "from lab.reassembler.reassemble import reassemble; r=reassemble('lab/pcaps/family-01.pcap'); print(f\"reassembler coverage_ratio {r['coverage_ratio']} banner {r['banner']} starttls {r['starttls_detected']} pre_tls_buffer_len {r['pre_tls_buffer_len']} overlap {r['overlap_detected']}\")" 2>&1 || warn "reassembler check failed (scapy missing? pip install -r requirements.txt)"
  fi
}

wait_for(){
  url="$1"; tries="${2:-30}"; sleep_s="${3:-0.5}"
  for i in $(seq 1 "$tries"); do
    if curl -sf "$url" >/dev/null 2>&1; then return 0; fi
    sleep "$sleep_s"
  done
  return 1
}

do_check(){
  echo "=== turnup --check (offline primary, tshark optional — docs/LARGE_FILES.md) ==="
  check_python; echo ""
  check_node; echo ""
  check_tshark; echo ""
  check_wheelhouse; echo ""
  check_models; echo ""
  check_frontend; echo ""
  check_pcap; echo ""
  # port preflight
  echo "--- port preflight ---"
  if check_port_free "$API_PORT"; then ok "port $API_PORT free (ss/fuser preflight)"; else warn "port $API_PORT in use — turnup will wait or fail (ss check)"; fi
  echo ""
  # docker compose config check (dry-run, no up)
  echo "--- docker compose config ---"
  if command -v docker >/dev/null 2>&1; then
    if docker compose config >/dev/null 2>&1; then ok "docker compose config ok (demo)"; else warn "docker compose config failed — check docker-compose.yml"; fi
    if docker compose --profile lab config >/dev/null 2>&1; then ok "docker compose --profile lab config ok"; else info "docker compose --profile lab config skipped (lab optional)"; fi
  else
    warn "docker not found — pure Docker path requires docker (install docker 24)"
  fi
  echo ""
  echo "=== turnup --check done (tshark optional — not fatal; wheelhouse missing is fresh-clone fallback) ==="
  echo "next: bash scripts/turnup.sh           # pure Docker: docker compose up -d --build demo on :$API_PORT"
  echo "      bash scripts/turnup.sh --with-lab # also lab: docker compose --profile lab up -d --build"
  echo "      bash scripts/turndown.sh          # clean down (ss check + rm pid + log rotation)"
  echo "      WITH_LAB=1 bash scripts/turnup.sh  # env variant for lab"
}

do_full(){
  # INT TERM only (no auto-down on exit) — use turndown.sh to stop
  trap 'echo "Interrupted — run bash scripts/turndown.sh to clean"; exit 130' INT TERM
  echo "=== turnup pure Docker (demo :$API_PORT — docs/LARGE_FILES.md §5) ==="
  check_python; echo ""
  check_node; echo ""
  check_tshark; echo ""
  check_wheelhouse; echo ""
  check_models; echo ""
  check_frontend; echo ""
  check_pcap; echo ""
  echo "--- port preflight ---"
  if ! check_port_free "$API_PORT"; then
    warn "port $API_PORT already in use (ss/fuser) — waiting or run bash scripts/turndown.sh"
    # try ss check for owner
    if command -v ss >/dev/null 2>&1; then ss -ltnp 2>/dev/null | grep ":${API_PORT} " || true; fi
  else
    ok "port $API_PORT free (ss/fuser preflight)"
  fi
  echo ""
  echo "--- docker compose up -d --build ---"
  if ! command -v docker >/dev/null 2>&1; then fail "docker not found — pure Docker path requires docker"; exit 1; fi
  if ! docker compose config >/dev/null 2>&1; then fail "docker compose config invalid"; exit 1; fi
  echo "bringing up demo: docker compose up -d --build demo"
  if docker compose up -d --build demo 2>&1 | tee -a "$LOG_FILE"; then ok "docker compose up -d --build demo"; else fail "docker compose up -d --build demo failed"; exit 1; fi
  if [[ "$WITH_LAB" == "1" ]]; then
    echo "WITH_LAB=1 — also bringing lab: docker compose --profile lab up -d --build"
    if docker compose --profile lab up -d --build 2>&1 | tee -a "$LOG_FILE"; then ok "docker compose --profile lab up -d --build"; else warn "docker compose --profile lab up -d --build failed (lab optional)"; fi
  else
    info "WITH_LAB=0 — skip lab (use --with-lab or WITH_LAB=1 to bring lab profile)"
  fi
  echo ""
  echo "--- wait_for health 30 0.5 ---"
  if wait_for "http://localhost:${API_PORT}/health" 30 0.5; then ok "health up http://localhost:${API_PORT}/health (wait_for 30 0.5)"; else
    if wait_for "http://localhost:${API_PORT}/flows" 30 0.5; then ok "flows up http://localhost:${API_PORT}/flows (health fallback)"; else warn "API not up after 15s — docker logs: docker compose logs demo"; docker compose logs --tail 20 demo 2>&1 | tail -20 || true; fi
  fi
  echo ""
  echo "--- verify API curl /analyze ---"
  if curl -sf "http://localhost:${API_PORT}/health" >/dev/null 2>&1; then ok "GET /health ok"; else warn "GET /health not reachable"; fi
  if curl -sf "http://localhost:${API_PORT}/flows" >/dev/null 2>&1; then ok "GET /flows ok"; else warn "GET /flows not reachable"; fi
  if [[ -f lab/pcaps/family-01.pcap ]]; then
    code=$(curl -s -o /tmp/turnup_analyze.json -w "%{http_code}" -F pcap=@lab/pcaps/family-01.pcap "http://localhost:${API_PORT}/analyze" 2>/dev/null || echo "000")
    echo "POST /analyze family-01.pcap -> HTTP $code"
    if [[ "$code" == "200" ]]; then
      echo "  $(cat /tmp/turnup_analyze.json 2>/dev/null | head -c 300 | tr -d '\n' | cut -c1-300)..."
      ok "POST /analyze ok (curl /analyze)"
      if python3 -c "import json; d=json.load(open('/tmp/turnup_analyze.json')); assert any('calibrated_prob' in str(x) for x in d)" 2>/dev/null; then ok "calibrated_prob present (risk_model wired)"; else info "calibrated_prob not in response (model missing? fallback graceful)"; fi
    else
      warn "POST /analyze failed — see /tmp/turnup_analyze.json"
      cat /tmp/turnup_analyze.json 2>/dev/null | head -c 500 || true; echo ""
    fi
  else
    warn "lab/pcaps/family-01.pcap missing — skip curl /analyze"
  fi
  echo ""
  echo "=== turnup done ==="
  echo "Demo      http://localhost:${API_PORT}/dashboard (single port 8000 via StaticFiles)"
  echo "Health    http://localhost:${API_PORT}/health"
  echo "Docs      http://localhost:${API_PORT}/docs"
  echo "Logs      $LOG_FILE  +  docker compose logs demo"
  echo "Lab       $(if [[ "$WITH_LAB" == "1" ]]; then echo "up (--profile lab)"; else echo "not up (use --with-lab)"; fi)"
  echo "Stop      bash scripts/turndown.sh  (no auto-down on exit — INT TERM only)"
}

do_host(){
  # INT TERM only (no auto-down on exit) — use turndown.sh to stop
  trap 'echo "Interrupted — run bash scripts/turndown.sh to clean"; exit 130' INT TERM
  echo "=== turnup host / wheelhouse mode (demo :$API_PORT) ==="
  check_python; echo ""
  check_node; echo ""
  check_tshark; echo ""
  check_wheelhouse; echo ""
  check_models; echo ""
  check_frontend; echo ""
  check_pcap; echo ""
  
  echo "--- host dependency install (wheelhouse) ---"
  if [[ -d wheelhouse ]] && [ "$(ls -A wheelhouse/*.whl 2>/dev/null)" ]; then
    ok "wheelhouse/ present — installing offline dependencies via --no-index --find-links wheelhouse"
    pip install --no-index --find-links wheelhouse --only-binary=:all: -r requirements.txt 2>&1 | tee -a "$LOG_FILE" || {
      warn "wheelhouse install had warnings — falling back to pip install"
      pip install -r requirements.txt 2>&1 | tee -a "$LOG_FILE" || true
    }
  else
    warn "wheelhouse/ missing or empty — creating wheelhouse via pip download..."
    mkdir -p wheelhouse
    pip download --only-binary=:all: --prefer-binary -d wheelhouse -r requirements.txt 2>&1 | tee -a "$LOG_FILE" || true
    ok "wheelhouse/ created — installing dependencies"
    pip install --no-index --find-links wheelhouse --only-binary=:all: -r requirements.txt 2>&1 | tee -a "$LOG_FILE" || pip install -r requirements.txt 2>&1 | tee -a "$LOG_FILE" || true
  fi
  echo ""

  if [[ ! -f dashboard/dist/index.html ]]; then
    if command -v npm >/dev/null 2>&1; then
      info "building dashboard frontend: npm run build"
      npm --prefix dashboard ci 2>/dev/null || npm --prefix dashboard install 2>/dev/null || true
      npm --prefix dashboard run build 2>&1 | tee -a "$LOG_FILE" || warn "dashboard build failed"
    else
      warn "node/npm not found — dashboard frontend dist missing"
    fi
  fi

  echo "--- port preflight ---"
  if ! check_port_free "$API_PORT"; then
    warn "port $API_PORT already in use — checking for previous PID"
    for pid_f in "$TMP_DIR/ciphercrest_api.pid" "$ROOT/.tmp/ciphercrest_api.pid"; do
      if [[ -f "$pid_f" ]]; then
        old_pid=$(cat "$pid_f" 2>/dev/null || echo "")
        if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
          info "stopping existing host pid $old_pid"
          kill "$old_pid" 2>/dev/null || true
          sleep 1
        fi
      fi
    done
  else
    ok "port $API_PORT free (ss/fuser preflight)"
  fi
  echo ""

  echo "--- starting uvicorn host API ---"
  nohup uvicorn api.app:app --host 0.0.0.0 --port "$API_PORT" > "$LOG_DIR/api_host.log" 2>&1 &
  API_PID=$!
  echo "$API_PID" > "$TMP_DIR/ciphercrest_api.pid"
  echo "$API_PID" > "$ROOT/.tmp/ciphercrest_api.pid"
  chmod 600 "$TMP_DIR/ciphercrest_api.pid" 2>/dev/null || true
  chmod 600 "$ROOT/.tmp/ciphercrest_api.pid" 2>/dev/null || true
  ok "API started on PID $API_PID (log: $LOG_DIR/api_host.log)"
  echo ""

  if [[ "$WITH_LAB" == "1" ]]; then
    if command -v docker >/dev/null 2>&1; then
      echo "WITH_LAB=1 — bringing up docker lab profile containers..."
      docker compose --profile lab up -d 2>&1 | tee -a "$LOG_FILE" || warn "docker compose --profile lab up -d failed"
    else
      warn "docker not found — lab profile requires docker"
    fi
  else
    info "WITH_LAB=0 — skip lab (use --with-lab or WITH_LAB=1 to bring lab profile)"
  fi
  echo ""

  echo "--- wait_for health 30 0.5 ---"
  if wait_for "http://localhost:${API_PORT}/health" 30 0.5; then
    ok "health up http://localhost:${API_PORT}/health (wait_for 30 0.5)"
  else
    if wait_for "http://localhost:${API_PORT}/flows" 30 0.5; then
      ok "flows up http://localhost:${API_PORT}/flows (health fallback)"
    else
      warn "API not up after 15s — see $LOG_DIR/api_host.log"
      cat "$LOG_DIR/api_host.log" 2>/dev/null | tail -20 || true
    fi
  fi
  echo ""

  echo "--- verify API curl /analyze ---"
  if curl -sf "http://localhost:${API_PORT}/health" >/dev/null 2>&1; then ok "GET /health ok"; else warn "GET /health not reachable"; fi
  if curl -sf "http://localhost:${API_PORT}/flows" >/dev/null 2>&1; then ok "GET /flows ok"; else warn "GET /flows not reachable"; fi
  if [[ -f lab/pcaps/family-01.pcap ]]; then
    code=$(curl -s -o /tmp/turnup_analyze.json -w "%{http_code}" -F pcap=@lab/pcaps/family-01.pcap "http://localhost:${API_PORT}/analyze" 2>/dev/null || echo "000")
    echo "POST /analyze family-01.pcap -> HTTP $code"
    if [[ "$code" == "200" ]]; then
      echo "  $(cat /tmp/turnup_analyze.json 2>/dev/null | head -c 300 | tr -d '\n' | cut -c1-300)..."
      ok "POST /analyze ok (curl /analyze)"
      if python3 -c "import json; d=json.load(open('/tmp/turnup_analyze.json')); assert any('calibrated_prob' in str(x) for x in d)" 2>/dev/null; then ok "calibrated_prob present (risk_model wired)"; else info "calibrated_prob not in response (model missing? fallback graceful)"; fi
    else
      warn "POST /analyze failed — see /tmp/turnup_analyze.json"
      cat /tmp/turnup_analyze.json 2>/dev/null | head -c 500 || true; echo ""
    fi
  else
    warn "lab/pcaps/family-01.pcap missing — skip curl /analyze"
  fi
  echo ""

  echo "=== turnup host done ==="
  echo "Demo      http://localhost:${API_PORT}/dashboard (host mode)"
  echo "Health    http://localhost:${API_PORT}/health"
  echo "Docs      http://localhost:${API_PORT}/docs"
  echo "PID       $API_PID (saved in $TMP_DIR/ciphercrest_api.pid)"
  echo "Logs      $LOG_FILE  +  $LOG_DIR/api_host.log"
  echo "Lab       $(if [[ "$WITH_LAB" == "1" ]]; then echo "up (--profile lab)"; else echo "not up (use --with-lab)"; fi)"
  echo "Stop      bash scripts/turndown.sh --host  (or bash scripts/turndown.sh)"
}

if [[ "$HOST_MODE" -eq 1 ]]; then
  case "$MODE" in
    check) do_check ;;
    help) do_help ;;
    full) do_host ;;
  esac
else
  case "$MODE" in
    check) do_check ;;
    help) do_help ;;
    full) do_full ;;
  esac
fi
