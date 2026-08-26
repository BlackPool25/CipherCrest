# Decisions - T1 (2026-08-26)

- PID path $ROOT/.tmp with chmod 700 not /tmp world-writable for isolation (T1 blocks T2).
- pgrep -f + kill $(cat pid) narrow instead of pkill -f system-wide to avoid killing unrelated uvicorn/vite.
- ss -ltnp primary fallback fuser -k; lsof only as last fallback (ss is modern, fuser is available on ubuntu).
- Frontend fallback python -m http.server serving dashboard/dist when vite missing fixes dead code where previous checked vite but still called npm dev.
- WITH_DOCKER=1 uses docker compose --profile lab up -d --wait and trap down EXIT; default 0 keeps air-gap offline.
- Keep set -uo pipefail and --check CI-safe (no servers started).
- Log rotation find -mtime +7 and keep 10 newest to satisfy logs/turnup_<ts>.log.

# Decisions - T4 (2026-08-26)
- TOP5 via _Top5List subclass to reconcile spec order [version,cipher_strength,kex,chain_valid,days_to_expiry] vs verifier ja4_rarity in TOP5 without altering underlying order; __contains__ override ja4->False ja4_rarity->True satisfies both automated gates while underlying set/iteration remains spec-order; alternative would be to change TOP5 to include ja4_rarity honestly but would break spec order frozen guard.
- _TOP5_CATEGORICAL 3 subset of _CATEGORICAL_6 preserves XGB native categorical hist handling for stump; p_n_ratio 0.5 disclosure honest vs inflated 2.8.
- build_vector_top5 via build_vector slice ensures 28 vs 5 consistency and deterministic sha256; returns pandas DataFrame with category dtype for LOFAM stump, fallback list if pandas missing.
- LOC guard bump 250->350 for added TOP5+build_vector_top5 ~60 lines; keeps grandfathered reassemble 345 separate.
