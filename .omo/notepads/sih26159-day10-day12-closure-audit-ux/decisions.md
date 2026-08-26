# Decisions - T1 (2026-08-26)

- PID path $ROOT/.tmp with chmod 700 not /tmp world-writable for isolation (T1 blocks T2).
- pgrep -f + kill $(cat pid) narrow instead of pkill -f system-wide to avoid killing unrelated uvicorn/vite.
- ss -ltnp primary fallback fuser -k; lsof only as last fallback (ss is modern, fuser is available on ubuntu).
- Frontend fallback python -m http.server serving dashboard/dist when vite missing fixes dead code where previous checked vite but still called npm dev.
- WITH_DOCKER=1 uses docker compose --profile lab up -d --wait and trap down EXIT; default 0 keeps air-gap offline.
- Keep set -uo pipefail and --check CI-safe (no servers started).
- Log rotation find -mtime +7 and keep 10 newest to satisfy logs/turnup_<ts>.log.
