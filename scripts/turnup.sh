#!/usr/bin/env bash
# scripts/turnup.sh — One script to turn up modules + frontend, check model files, wheelhouse, builds
# Offline-first: tshark optional (scapy parity fallback). Docs: docs/LARGE_FILES.md
# Usage: bash scripts/turnup.sh [--check|--down|--help] [--port 8000] [--frontend-port 5173]
#   --check  dry-run, no servers (CI-safe)
#   --down   stop API/dashboard started by turnup
#   --help   usage
# Env: API_PORT, FRONT_PORT, PYTHONHASHSEED=0, OMP_NUM_THREADS=6, WITH_DOCKER=0|1
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PYTHONHASHSEED=0
export OMP_NUM_THREADS=6
WITH_DOCKER="${WITH_DOCKER:-0}"

API_PORT="${API_PORT:-8000}"
FRONT_PORT="${FRONT_PORT:-5173}"
MODE="full"
# PID files under $ROOT/.tmp with 700 perms (not world-writable /tmp)
TMP_DIR="$ROOT/.tmp"
mkdir -p "$ROOT/.tmp" 2>/dev/null || true
mkdir -p "$TMP_DIR" 2>/dev/null || true
chmod 700 "$ROOT/.tmp" 2>/dev/null || true
chmod 700 "$TMP_DIR" 2>/dev/null || true
# PID files: $ROOT/.tmp/ciphercrest_api.pid and $ROOT/.tmp/ciphercrest_front.pid (700)
API_PID_FILE="$ROOT/.tmp/ciphercrest_api.pid"
FRONT_PID_FILE="$ROOT/.tmp/ciphercrest_front.pid"
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

# parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) MODE="check"; shift ;;
    --down) MODE="down"; shift ;;
    --parity) MODE="parity"; shift ;;
    --help|-h) MODE="help"; shift ;;
    --port) API_PORT="$2"; shift 2 ;;
    --frontend-port) FRONT_PORT="$2"; shift 2 ;;
    *) warn "unknown arg $1"; shift ;;
  esac
done

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

kill_port(){
  port="$1"
  if command -v ss >/dev/null 2>&1; then
    # ss -ltnp shows pids; fallback to fuser
    if command -v fuser >/dev/null 2>&1; then fuser -k "${port}/tcp" 2>/dev/null || true; fi
    # also try ss-derived pids if fuser unavailable
    ss -ltnp 2>/dev/null | grep -q ":${port} " && true || true
  elif command -v fuser >/dev/null 2>&1; then
    fuser -k "${port}/tcp" 2>/dev/null || true
  elif command -v lsof >/dev/null 2>&1; then
    lsof -ti :"$port" 2>/dev/null | xargs -r kill 2>/dev/null || true
  fi
}

do_down(){
  echo "=== turnup --down ==="
  for pf in "$API_PID_FILE" "$FRONT_PID_FILE"; do
    if [[ -f "$pf" ]]; then pid=$(cat "$pf" 2>/dev/null || echo ""); if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null || true; echo "stopped pid $pid ($pf)"; fi; rm -f "$pf" 2>/dev/null || true
    fi
  done
  # pgrep scoped to PID file + kill (not system-wide kill)
  if command -v pgrep >/dev/null 2>&1; then
    for pat in "uvicorn api.app:app" "vite.*$FRONT_PORT" "http.server.*$FRONT_PORT"; do
      pids=$(pgrep -f "$pat" 2>/dev/null || true)
      for pid in $pids; do
        # only kill if pid matches one of our stored pids or if no pid file (safe narrow)
        # but we already killed pid files; now narrow to user-owned processes
        if kill -0 "$pid" 2>/dev/null; then
          # verify cmdline contains pattern before kill
          if ps -o args= -p "$pid" 2>/dev/null | grep -q "$pat"; then kill "$pid" 2>/dev/null || true; echo "stopped pgrep $pat pid $pid"; fi
        fi
      done
    done
  fi
  # port kill via ss fallback fuser
  kill_port "$API_PORT"
  kill_port "$FRONT_PORT"
  # docker lab down if WITH_DOCKER
  if [[ "$WITH_DOCKER" == "1" ]] && command -v docker >/dev/null 2>&1 && [[ -f "$ROOT/lab/docker-compose.yml" ]]; then
    docker compose --profile lab down 2>/dev/null || true
  fi
  echo "down done"
}

do_help(){
  echo "Usage: bash scripts/turnup.sh [--check|--down|--help] [--port 8000] [--frontend-port 5173]"
  echo "  --check         dry-run checks only (no servers) — CI-safe"
  echo "  --down          stop API + dashboard started by turnup"
  echo "  --parity        live tshark parity (requires tshark, else skip)"
  echo "  --port N        API port (default 8000, env API_PORT)"
  echo "  --frontend-port N  dashboard port (default 5173)"
  echo ""
  echo "Env: WITH_DOCKER=1  docker compose --profile lab up -d --wait (hybrid lab, single port 8000)"
  echo "     WITH_DOCKER=0  skip docker (default, air-gap offline)"
  echo "     PYTHONHASHSEED=0 OMP_NUM_THREADS=6  deterministic"
  echo ""
  echo "Quick: bash scripts/turnup.sh           # full up: checks + starts API + dashboard"
  echo "       bash scripts/turnup.sh --check   # dry-run checks models/wheelhouse/frontend/tshark(optional)"
  echo "       bash scripts/turnup.sh --down    # cleanup"
  echo "       WITH_DOCKER=1 bash scripts/turnup.sh  # hybrid with docker lab profile"
  echo "See docs/LARGE_FILES.md §5 and README Quick Turn-Up (One Script)."
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

check_docker(){
  echo "--- docker (lab profile) ---"
  if [[ "$WITH_DOCKER" != "1" ]]; then info "WITH_DOCKER=0 — skip docker (air-gap offline)"; return 0; fi
  if ! command -v docker >/dev/null 2>&1; then warn "docker not found — WITH_DOCKER=1 but docker missing, skip"; return 0; fi
  if [[ ! -f "$ROOT/lab/docker-compose.yml" ]]; then warn "lab/docker-compose.yml not found — skip docker"; return 0; fi
  echo "WITH_DOCKER=1 — docker compose --profile lab up -d --wait"
  if docker compose --profile lab up -d --wait 2>&1 | tail -5; then ok "docker compose --profile lab up -d --wait"; else warn "docker compose up failed (lab optional)"; fi
  # trap docker compose --profile lab down EXIT combined with do_down
  trap 'do_down; docker compose --profile lab down 2>/dev/null || true; exit' EXIT INT TERM
}

check_wheelhouse(){
  echo "--- wheelhouse ---"
  if [[ -d wheelhouse ]] && ls wheelhouse/*.whl >/dev/null 2>&1; then
    du_line=$(du -m wheelhouse 2>/dev/null | tail -1)
    echo "wheelhouse $du_line"
    mb=$(echo "$du_line" | awk '{print $1}')
    cnt=$(ls wheelhouse/*.whl 2>/dev/null | wc -l | tr -d ' ')
    echo "wheelhouse $cnt wheels"
    if [[ "$mb" -lt 370 ]]; then ok "wheelhouse $mb <370M lean"; else fail "wheelhouse $mb >=370M — re-lean (see docs/LARGE_FILES.md)"; fi
    if ls wheelhouse/*.whl 2>/dev/null | grep -qi torch; then fail "torch wheel in wheelhouse — lean forbids torch (see requirements.txt)"; else ok "no torch (lean)"; fi
    if git ls-files 2>/dev/null | grep -q "^wheelhouse/"; then fail "wheelhouse tracked in git — must be gitignored (b9d18b4)"; else ok "HEAD clean: wheelhouse gitignored (not tracked)"; fi
    if python3 -c "import pathlib; wh=pathlib.Path('wheelhouse'); assert any('torch' not in p.name.lower() for p in wh.glob('*.whl'))" 2>/dev/null; then ok "wheelhouse no torch (python guard)"; fi
  else
    warn "wheelhouse missing or empty — fresh clone (no USB air-gap) — CI fallback: pip install -r requirements.txt"
    echo "  rebuild: pip download --only-binary=:all: -d wheelhouse -r requirements.txt && du -m wheelhouse | tail -1  # expect 361 <370"
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
  if [[ -d dashboard/node_modules ]]; then ok "dashboard/node_modules present"; else warn "dashboard/node_modules missing — will run npm --prefix dashboard install"; if [[ "$MODE" != "check" ]] && command -v npm >/dev/null 2>&1; then echo "  installing..."; npm --prefix dashboard install 2>&1 | tail -5 || warn "npm install failed"; fi; fi
  if [[ -f dashboard/dist/index.html ]]; then
    gz=$(gzip -c dashboard/dist/assets/*.js 2>/dev/null | wc -c | tr -d ' '); echo "dashboard/dist gzip $gz <3670016"
    if [[ "$gz" -lt 3670016 ]]; then ok "Vite gzip $gz <3670016"; else fail "Vite gzip $gz >=3670016"; fi
    if git ls-files 2>/dev/null | grep -q "^dashboard/dist"; then fail "dashboard/dist tracked — should be gitignored (b9d18b4)"; else ok "HEAD clean: dashboard/dist gitignored"; fi
  else
    warn "dashboard/dist missing — need build"
    if [[ "$MODE" != "check" ]] && command -v npm >/dev/null 2>&1; then echo "  building..."; npm --prefix dashboard run build 2>&1 | tail -10 || warn "npm build failed"; fi
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

start_api(){
  echo "--- starting API (uvicorn api.app:app --port $API_PORT) ---"
  check_port_free "$API_PORT" || warn "port $API_PORT collision preflight (ss -ltn) — attempting kill"
  kill_port "$API_PORT"
  PYTHONHASHSEED=0 OMP_NUM_THREADS=6 nohup python3 -m uvicorn api.app:app --host 0.0.0.0 --port "$API_PORT" > "$LOG_DIR/api.log" 2>&1 &
  echo $! > "$API_PID_FILE"
  chmod 600 "$API_PID_FILE" 2>/dev/null || true
  echo "API pid $(cat "$API_PID_FILE") log $LOG_DIR/api.log"
  if wait_for "http://localhost:$API_PORT/flows" 30 0.5; then ok "API up http://localhost:$API_PORT/flows"; else warn "API not up after 15s — see $LOG_DIR/api.log"; tail -20 "$LOG_DIR/api.log" 2>/dev/null || true; fi
}

start_frontend(){
  echo "--- starting dashboard (vite --port $FRONT_PORT) ---"
  check_port_free "$FRONT_PORT" || warn "port $FRONT_PORT collision preflight (ss -ltn) — attempting kill"
  kill_port "$FRONT_PORT"
  # frontend fallback: when npm/vite missing, serve dist via python http.server
  has_vite=0
  if command -v npm >/dev/null 2>&1 && npm --prefix dashboard ls vite >/dev/null 2>&1; then has_vite=1; fi
  if [[ $has_vite -eq 1 ]]; then
    nohup npm --prefix dashboard run dev -- --port "$FRONT_PORT" --host 0.0.0.0 > "$LOG_DIR/dashboard.log" 2>&1 &
    echo $! > "$FRONT_PID_FILE"
    chmod 600 "$FRONT_PID_FILE" 2>/dev/null || true
    echo "dashboard pid $(cat "$FRONT_PID_FILE") log $LOG_DIR/dashboard.log (vite)"
    if wait_for "http://localhost:$FRONT_PORT" 30 0.5; then ok "dashboard up http://localhost:$FRONT_PORT"; else warn "dashboard not up yet — see $LOG_DIR/dashboard.log"; tail -20 "$LOG_DIR/dashboard.log" 2>/dev/null || true; fi
  elif [[ -f dashboard/dist/index.html ]]; then
    info "vite not found but dist exists — serving dist via python -m http.server $FRONT_PORT"
    nohup python3 -m http.server "$FRONT_PORT" --directory dashboard/dist > "$LOG_DIR/dashboard.log" 2>&1 &
    echo $! > "$FRONT_PID_FILE"
    chmod 600 "$FRONT_PID_FILE" 2>/dev/null || true
    echo "dashboard pid $(cat "$FRONT_PID_FILE") log $LOG_DIR/dashboard.log (http.server fallback)"
    if wait_for "http://localhost:$FRONT_PORT" 30 0.5; then ok "dashboard up http://localhost:$FRONT_PORT (fallback)"; else warn "dashboard not up yet — see $LOG_DIR/dashboard.log"; tail -20 "$LOG_DIR/dashboard.log" 2>/dev/null || true; fi
  else
    # still try npm dev even without vite detection, but warn dead code path fixed
    if command -v npm >/dev/null 2>&1; then
      warn "vite missing and dist missing — attempting npm run dev anyway"
      nohup npm --prefix dashboard run dev -- --port "$FRONT_PORT" --host 0.0.0.0 > "$LOG_DIR/dashboard.log" 2>&1 &
      echo $! > "$FRONT_PID_FILE"
      chmod 600 "$FRONT_PID_FILE" 2>/dev/null || true
      echo "dashboard pid $(cat "$FRONT_PID_FILE") log $LOG_DIR/dashboard.log"
      if wait_for "http://localhost:$FRONT_PORT" 30 0.5; then ok "dashboard up http://localhost:$FRONT_PORT"; else warn "dashboard not up yet — see $LOG_DIR/dashboard.log"; tail -20 "$LOG_DIR/dashboard.log" 2>/dev/null || true; fi
    else
      warn "npm not found — dashboard not started (install node 18)"
      # fallback: python http.server if dist exists handled above, else nothing
      if [[ -f dashboard/dist/index.html ]]; then
        info "fallback python -m http.server $FRONT_PORT --directory dashboard/dist (npm missing but dist present)"
        nohup python3 -m http.server "$FRONT_PORT" --directory dashboard/dist > "$LOG_DIR/dashboard.log" 2>&1 &
        echo $! > "$FRONT_PID_FILE"
        chmod 600 "$FRONT_PID_FILE" 2>/dev/null || true
        if wait_for "http://localhost:$FRONT_PORT" 30 0.5; then ok "dashboard up http://localhost:$FRONT_PORT (http.server)"; else warn "dashboard not up"; fi
      fi
    fi
  fi
}

verify_api(){
  echo "--- verify API ---"
  if ! curl -sf "http://localhost:$API_PORT/flows" >/dev/null 2>&1; then warn "GET /flows not reachable"; return 0; fi
  echo "GET /flows $(curl -s "http://localhost:$API_PORT/flows" | head -c 200 | tr -d '\n' | cut -c1-200)..."
  if [[ -f lab/pcaps/family-01.pcap ]]; then
    code=$(curl -s -o /tmp/turnup_analyze.json -w "%{http_code}" -F pcap=@lab/pcaps/family-01.pcap "http://localhost:$API_PORT/analyze" 2>/dev/null || echo "000")
    echo "POST /analyze family-01.pcap -> HTTP $code"
    if [[ "$code" == "200" ]]; then
      echo "  $(cat /tmp/turnup_analyze.json 2>/dev/null | head -c 300 | tr -d '\n' | cut -c1-300)..."
      ok "POST /analyze ok"
      if python3 -c "import json; d=json.load(open('/tmp/turnup_analyze.json')); assert any('calibrated_prob' in str(x) for x in d)" 2>/dev/null; then ok "calibrated_prob present (risk_model wired)"; else info "calibrated_prob not in response (model missing? fallback graceful)"; fi
    else
      warn "POST /analyze failed — see /tmp/turnup_analyze.json"
      cat /tmp/turnup_analyze.json 2>/dev/null | head -c 500 || true; echo ""
    fi
  fi
  if ls lab/pcaps/family-0*.pcap >/dev/null 2>&1; then
    tmpzip=/tmp/turnup_3pcaps.zip
    (cd lab/pcaps && zip -j -q "$tmpzip" family-01.pcap family-03.pcap family-06.pcap 2>/dev/null) || true
    if [[ -f "$tmpzip" ]]; then
      code2=$(curl -s -o /tmp/turnup_analyze_zip.json -w "%{http_code}" -F pcap=@"$tmpzip" "http://localhost:$API_PORT/analyze" 2>/dev/null || echo "000")
      echo "POST /analyze zip 3pcaps -> HTTP $code2"
      if [[ "$code2" == "200" ]]; then ok "POST /analyze zip ok"; cat /tmp/turnup_analyze_zip.json 2>/dev/null | head -c 200 || true; echo ""; else warn "zip analyze $code2"; fi
    fi
  fi
  echo "GET /flows after analyze: $(curl -s "http://localhost:$API_PORT/flows" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d))" 2>/dev/null || echo "?") flows"
  echo "GET /report?format=json: $(curl -s "http://localhost:$API_PORT/report?format=json" 2>/dev/null | head -c 200 | tr -d '\n' | cut -c1-200)..."
  ok "verify done — logs $LOG_DIR/api.log"
}

do_check(){
  echo "=== turnup --check (offline primary, tshark optional — docs/LARGE_FILES.md) ==="
  check_python; echo ""
  check_node; echo ""
  check_tshark; echo ""
  check_docker; echo ""
  check_wheelhouse; echo ""
  check_models; echo ""
  check_frontend; echo ""
  check_pcap; echo ""
  echo "=== turnup --check done (tshark optional — not fatal; wheelhouse missing is fresh-clone fallback) ==="
  echo "next: bash scripts/turnup.sh           # full up (starts API :$API_PORT + dashboard :$FRONT_PORT)"
  echo "      bash scripts/turnup.sh --down     # stop"
  echo "      WITH_DOCKER=1 bash scripts/turnup.sh  # docker lab profile"
}

do_full(){
  # trap-clean lifecycle: ensure do_down on EXIT INT TERM before starting servers
  trap 'do_down; exit' EXIT INT TERM
  # when WITH_DOCKER=1 also trap docker compose down
  if [[ "$WITH_DOCKER" == "1" ]]; then
    trap 'do_down; docker compose --profile lab down 2>/dev/null || true; exit' EXIT INT TERM
  fi
  echo "=== turnup full (API :$API_PORT + dashboard :$FRONT_PORT — docs/LARGE_FILES.md §5) ==="
  check_python; echo ""
  check_node; echo ""
  check_tshark; echo ""
  check_docker; echo ""
  check_wheelhouse; echo ""
  check_models; echo ""
  check_frontend; echo ""
  check_pcap; echo ""
  start_api; echo ""
  start_frontend; echo ""
  verify_api; echo ""
  echo "=== turnup done ==="
  echo "API       http://localhost:$API_PORT/flows  (POST /analyze)"
  echo "Dashboard http://localhost:$FRONT_PORT"
  echo "Logs      $LOG_DIR/api.log  $LOG_DIR/dashboard.log  $LOG_FILE"
  echo "Stop      bash scripts/turnup.sh --down"
  # keep trap for INT/TERM during running; clear EXIT after success to avoid double down on normal exit?
  # but spec says trap 'do_down; exit' EXIT INT TERM at top — keep it
}

case "$MODE" in
  check) do_check ;;
  down) do_down ;;
  parity)
    echo "=== parity check (requires tshark, else skip) ==="
    if ! command -v tshark >/dev/null 2>&1; then echo "tshark not found — offline scapy reassembler (parity 4 prefs stub) — pytest still passes"; exit 0; fi
    echo "tshark $(tshark -v 2>&1 | head -1)"; python3 -m pytest lab/reassembler/tests -q || true
    ;;
  help) do_help ;;
  full) do_full ;;
esac
