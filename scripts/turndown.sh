#!/usr/bin/env bash
# scripts/turndown.sh — clean down for pure Docker lifecycle (two-file: turnup + turndown)
# Usage: bash scripts/turndown.sh [--check|--help]
#   --check  dry-run idempotent checks (no down) — CI-safe
#   --help   usage
# Pure Docker: down both composes, ss check port 8000, rm .tmp pid, log rotation
# Port: 8000 via ss -ltn fallback fuser; Logs: logs/turndown_<ts>.log keep last 10 prune 7d
set -uo pipefail
trap 'exit 0' PIPE

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

HOST_MODE="${HOST_MODE:-0}"
MODE="down"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) MODE="check"; shift ;;
    --help|-h) MODE="help"; shift ;;
    --host|--wheelhouse|--native) HOST_MODE=1; shift ;;
    *) echo "[warn] unknown arg $1"; shift ;;
  esac
done

LOG_DIR="$ROOT/logs"
TMP_DIR="$ROOT/.tmp"
mkdir -p "$LOG_DIR" 2>/dev/null || true
mkdir -p "$TMP_DIR" 2>/dev/null || true

# log rotation setup (mirrors turnup.sh)
LOG_FILE="$LOG_DIR/turndown_$(date +%Y%m%d_%H%M%S).log"
touch "$LOG_FILE" 2>/dev/null || true

do_help(){
  echo "Usage: bash scripts/turndown.sh [--check|--help] [--host|--wheelhouse]"
  echo "  --check               dry-run idempotent checks (no down)"
  echo "  --host, --wheelhouse  clean down host processes (PIDs and port 8000)"
  echo "  --help                show help"
  echo "Does: docker compose down + docker compose --profile lab down"
  echo "      ss check port 8000, rm .tmp/*.pid, log rotation"
}

do_check(){
  echo "=== turndown --check (idempotent) ==="
  echo "[ok] would run: docker compose down"
  echo "[ok] would run: docker compose --profile lab down (if lab up)"
  if command -v ss >/dev/null 2>&1; then
    echo "[ok] ss available for port 8000 check"
    ss -ltn 2>/dev/null | grep -q ":8000 " && echo "[info] port 8000 currently in use" || echo "[ok] port 8000 free (ss -ltn)"
  elif command -v fuser >/dev/null 2>&1; then
    echo "[ok] fuser available for port 8000 check"
  else
    echo "[info] ss/fuser not found — skip port check"
  fi
  echo "[ok] would rm $TMP_DIR/*.pid and $ROOT/.tmp/ciphercrest*.pid if exist"
  echo "[ok] would rm $TMP_DIR/ciphercrest_api.pid if exist"
  echo "[ok] log rotation: keep last 10, prune older than 7d in $LOG_DIR"
  echo "[ok] turnup logs and turndown logs rotation check"
  echo "[ok] turndown --check done (idempotent, no changes)"
}

do_down(){
  echo "=== turndown clean ==="
  # docker compose down (demo)
  if command -v docker >/dev/null 2>&1; then
    echo "docker compose down"
    docker compose down 2>&1 || true
    echo "docker compose --profile lab down"
    docker compose --profile lab down 2>&1 || true
  else
    echo "[warn] docker not found — skip docker compose down"
  fi
  # rm pid files
  for f in "$TMP_DIR"/*.pid "$ROOT/.tmp"/*.pid; do
    [[ -f "$f" ]] || continue
    pid=$(cat "$f" 2>/dev/null || echo "")
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      echo "stopped pid $pid ($f)"
    fi
    rm -f "$f" 2>/dev/null || true
    echo "rm $f"
  done
  rm -f "$TMP_DIR/ciphercrest_api.pid" 2>/dev/null || true
  rm -f "$ROOT/.tmp/ciphercrest_api.pid" 2>/dev/null || true
  rm -f "$ROOT/.tmp/ciphercrest_front.pid" 2>/dev/null || true
  echo "[ok] rm .tmp pid files cleaned"

  # cleanup port 8000 process if lingering
  if command -v fuser >/dev/null 2>&1; then
    if fuser 8000/tcp >/dev/null 2>&1; then
      echo "terminating process on port 8000 via fuser"
      fuser -k 8000/tcp 2>/dev/null || true
      sleep 0.5
    fi
  elif command -v lsof >/dev/null 2>&1; then
    lingering_pid=$(lsof -ti :8000 2>/dev/null || echo "")
    if [[ -n "$lingering_pid" ]]; then
      echo "terminating process on port 8000 (pid $lingering_pid) via lsof"
      kill $lingering_pid 2>/dev/null || true
      sleep 0.5
    fi
  fi

  # ss check port 8000
  if command -v ss >/dev/null 2>&1; then
    if ss -ltn 2>/dev/null | grep -q ":8000 "; then
      echo "[warn] port 8000 still in use (ss -ltn)"
      ss -ltnp 2>/dev/null | grep ":8000 " || true
    else
      echo "[ok] port 8000 cleaned (ss -ltn)"
    fi
  elif command -v fuser >/dev/null 2>&1; then
    if fuser 8000/tcp >/dev/null 2>&1; then
      echo "[warn] port 8000 still in use (fuser)"
    else
      echo "[ok] port 8000 cleaned (fuser)"
    fi
  else
    echo "[info] ss/fuser not found — skip port check"
  fi
  # log rotation
  mkdir -p "$LOG_DIR" 2>/dev/null || true
  find "$LOG_DIR" -name "turnup_*.log" -mtime +7 -delete 2>/dev/null || true
  find "$LOG_DIR" -name "turndown_*.log" -mtime +7 -delete 2>/dev/null || true
  ls -t "$LOG_DIR"/turnup_*.log 2>/dev/null | tail -n +11 | xargs -r rm -f 2>/dev/null || true
  ls -t "$LOG_DIR"/turndown_*.log 2>/dev/null | tail -n +11 | xargs -r rm -f 2>/dev/null || true
  echo "[ok] log rotation done (keep last 10, prune older than 7d)"
  echo "[ok] turndown logs rotation complete"
  echo "=== turndown done ==="
}

case "$MODE" in
  help) do_help ;;
  check) do_check ;;
  down) do_down ;;
esac
