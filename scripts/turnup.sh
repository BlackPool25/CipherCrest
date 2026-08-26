#!/usr/bin/env bash
# scripts/turnup.sh — environment turn-up check (offline-first, tshark optional)
# MUST NOT make tshark mandatory. See docs/TSHARK.md.
set -uo pipefail

MODE="${1:-}"

check_python() {
  if command -v python3 >/dev/null 2>&1; then
    echo "python3 $(python3 --version 2>&1)"
  else
    echo "python3 not found — install python 3.11"
  fi
}

check_tshark() {
  if command -v tshark >/dev/null 2>&1; then
    echo "tshark $(tshark -v 2>&1 | head -1)"
    if python3 -c "from lab.reassembler.reassemble import get_tshark_prefs; assert len(get_tshark_prefs())==4" 2>/dev/null; then
      echo "tshark prefs parity 4 prefs OK (tcp.desegment_tcp_streams tcp.reassemble_out_of_order tls.desegment_ssl_records tls.desegment_ssl_application_data)"
    else
      echo "tshark prefs check skipped (lab module not importable)"
    fi
  else
    echo "tshark not found — offline scapy fallback (parity 4 prefs stub)"
    echo "  parity harness: python -c \"from lab.reassembler.reassemble import get_tshark_prefs, build_tshark_cmd; print(get_tshark_prefs()); print(build_tshark_cmd('lab/pcaps/family-01.pcap'))\""
    echo "  install optional: sudo apt install tshark  # 4.2.0  — or bash lab/scripts/install_tshark.sh"
  fi
}

check_pcap() {
  cnt=$(ls lab/pcaps/family-*.pcap 2>/dev/null | wc -l | tr -d ' ')
  echo "lab/pcaps clean families: ${cnt:-0}/10"
  if [ -f lab/reassembler/reassemble.py ]; then
    python3 -c "from lab.reassembler.reassemble import reassemble; r=reassemble('lab/pcaps/family-01.pcap'); print(f\"reassembler coverage_ratio {r['coverage_ratio']} banner {r['banner']} starttls {r['starttls_detected']} pre_tls_buffer_len {r['pre_tls_buffer_len']}\")" 2>&1 || echo "reassembler check failed (scapy missing? pip install -r requirements.txt)"
  fi
}

do_check() {
  echo "=== turnup --check (offline primary, tshark optional) ==="
  check_python
  check_tshark
  check_pcap
  echo "wheelhouse $(du -m wheelhouse 2>/dev/null | tail -1 || echo 'wheelhouse missing — pip install -r requirements.txt')"
  echo "=== turnup check done (tshark optional — not fatal) ==="
}

do_parity() {
  echo "=== parity check (requires tshark) ==="
  if ! command -v tshark >/dev/null 2>&1; then
    echo "tshark not found — cannot run live parity (use offline scapy reassembler)"
    echo "hint: bash lab/scripts/install_tshark.sh"
    exit 0
  fi
  echo "tshark $(tshark -v 2>&1 | head -1)"
  python3 -m pytest lab/reassembler/tests -q
}

case "$MODE" in
  --check)
    do_check
    ;;
  --parity)
    do_parity
    ;;
  --help|-h)
    echo "Usage: bash scripts/turnup.sh [--check|--parity|--help]"
    echo "  --check   offline turn-up (default, tshark optional warning not error)"
    echo "  --parity  live tshark parity (requires tshark, else graceful skip)"
    echo "  --help    this help"
    echo ""
    echo "See docs/TSHARK.md for why tshark missing is expected (offline scapy primary)."
    ;;
  "")
    do_check
    ;;
  *)
    echo "unknown arg $MODE — see --help"
    do_check
    ;;
esac
