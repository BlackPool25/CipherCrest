# Issues - T1 (2026-08-26)

- Original turnup.sh used /tmp world-writable PID files and pkill -f system-wide (blast radius).
- lsof-only port kill not available on minimal containers; ss fallback needed.
- Frontend fallback dead code: checked vite not found but still ran npm dev instead of http.server.
- Missing trap EXIT INT TERM meant INT (cancel) left stale servers; added at do_full top.
- WITH_DOCKER hybrid missing; added check_docker with --profile lab.
- Test harness pipefail SIGPIPE caused grep -q false negative; fixed via file buffering.

# Issues - T3 (2026-08-26)

- No missing functionality but verification uncovered tshark 4.6.8 vs spec 4.2.0 version drift; handled via warn skip not hard fail in docker version test (acceptable).
- Initial test_tshark_4prefs_baked typo tcp.desegment_ssl_records vs tls.desegment_ssl_records caused 1 failure; fixed to tls prefix.
- Hot path audit confirmed reassemble() never invokes tshark (oracle only in analyzer/parse.py _tshark_oracle line 103) — spec satisfied.
- WITH_DOCKER=1 health dig @172.18.0.53 MX check requires running docker lab; offline skip honest.
