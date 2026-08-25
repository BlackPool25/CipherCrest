#!/usr/bin/env bash
# lab/scripts/install_tshark.sh — install tshark/wireshark-cli if missing
# Offline replay is primary; tshark is oracle for parity F1>95% only.
set -euo pipefail

if command -v tshark >/dev/null 2>&1; then
  echo "tshark already installed: $(tshark -v | head -1)"
  exit 0
fi

echo "tshark not found — attempting install..."

if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y --no-install-recommends wireshark-cli || apt-get install -y --no-install-recommends tshark || apt-get install -y --no-install-recommends wireshark
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache tshark wireshark-cli
elif command -v yum >/dev/null 2>&1; then
  yum install -y wireshark-cli || yum install -y wireshark
elif command -v brew >/dev/null 2>&1; then
  brew install wireshark
else
  echo "No known package manager found. Install wireshark/tshark manually and re-run."
  exit 1
fi

if command -v tshark >/dev/null 2>&1; then
  echo "tshark installed: $(tshark -v | head -1)"
  echo "Verify prefs:"
  echo "  tshark -r lab/pcaps/family-01.pcap -T json -o tcp.desegment_tcp_streams:TRUE -o tcp.reassemble_out_of_order:TRUE -o tls.desegment_ssl_records:TRUE -o tls.desegment_ssl_application_data:TRUE | head"
else
  echo "Install attempted but tshark still missing — tests will skip gracefully."
  exit 0
fi
