# Issues - T1 (2026-08-26)

- Original turnup.sh used /tmp world-writable PID files and pkill -f system-wide (blast radius).
- lsof-only port kill not available on minimal containers; ss fallback needed.
- Frontend fallback dead code: checked vite not found but still ran npm dev instead of http.server.
- Missing trap EXIT INT TERM meant INT (cancel) left stale servers; added at do_full top.
- WITH_DOCKER hybrid missing; added check_docker with --profile lab.
- Test harness pipefail SIGPIPE caused grep -q false negative; fixed via file buffering.
