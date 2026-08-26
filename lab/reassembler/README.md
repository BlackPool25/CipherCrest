# lab/reassembler — Offline TCP Reassembly (tshark optional parity)

Offline replay is primary — no tshark, no live capture required. TShark is an **optional parity oracle** (see `docs/TSHARK.md`).

## What it does

- **5-tuple flow grouping** `(src, sport, dst, dport)` directed
- **Seq buffering** sorted by `TCP.seq`, handles out-of-order / overlap / gap
- **coverage_ratio** = `reassembled_bytes / total_tcp_payload_bytes` per-flow and global (`1.0` clean, `0.897` jittered legacy `lab/pcaps/jittered.pcap`)
- **Banner discriminator** `220` ESMTP vs `* OK` IMAP vs `+OK` POP3
- **STARTTLS Bennett detection** `STARTTLS`/`STLS` + `220 Ready` / `OK Begin TLS`
- **Pre-TLS buffer** bytes between `220` banner line end and TLS `ClientHello` record `0x16 0x03` via `_compute_pre_tls_buffer` (`pre_tls_buffer_len`, `pre_tls_buffer_injection_possible`)

## TShark parity harness (optional, not required)

Wireshark 3.0 turned both `tcp.*` prefs **OFF by default** (ask.wireshark #10299/#23327) — need 4 prefs, not 3:

```python
from lab.reassembler.reassemble import get_tshark_prefs, build_tshark_cmd, TSHARK_REQUIRED_PREFS
assert get_tshark_prefs() == [
    "tcp.desegment_tcp_streams:TRUE",
    "tcp.reassemble_out_of_order:TRUE",
    "tls.desegment_ssl_records:TRUE",
    "tls.desegment_ssl_application_data:TRUE",
]
build_tshark_cmd("lab/pcaps/family-01.pcap")
# ['tshark', '-r', '...', '-T', 'json', '-o', 'tcp.desegment_tcp_streams:TRUE', ...]
```

When `which tshark` not found (expected on dev/CI without install), code falls back to scapy and tests mock/skip:

```bash
which tshark || echo "tshark not found — offline scapy fallback (parity 4 prefs stub)"
python lab/reassembler/reassemble.py --verify-prefs
pytest lab/reassembler/tests -q  # 22 passed, 1 skipped when tshark missing
```

## CLI

```bash
python lab/reassembler/reassemble.py lab/pcaps/family-01.pcap --json
python lab/reassembler/reassemble.py lab/pcaps/family-01.pcap --coverage-only  # 1.0
python lab/reassembler/reassemble.py lab/pcaps/family-01.pcap --no-reassemble-out-of-order  # simulate pref OFF → gap flag
python lab/reassembler/reassemble.py --verify-prefs  # prints 4 prefs, no pcap needed
bash scripts/turnup.sh --check  # tshark optional warning, not error
```

## Install tshark (optional)

```bash
sudo apt install tshark  # 4.2.0 on ubuntu-latest
# or
bash lab/scripts/install_tshark.sh  # exits 0 even if still missing
tshark -v | head -1
tshark -r lab/pcaps/family-01.pcap -T json \
  -o tcp.desegment_tcp_streams:TRUE \
  -o tcp.reassemble_out_of_order:TRUE \
  -o tls.desegment_ssl_records:TRUE \
  -o tls.desegment_ssl_application_data:TRUE | head
```

Parity tests compare `coverage_ratio` via oracle vs offline (`F1>95%` clean). See `docs/TSHARK.md` 2-lane and `lab/LEDGER.md` coverage_ratio column.

## 4-prefs disclosure

Required 4 prefs `tcp.desegment_tcp_streams:TRUE tcp.reassemble_out_of_order:TRUE tls.desegment_ssl_records:TRUE tls.desegment_ssl_application_data:TRUE` per `lab/reassembler/reassemble.py` `TSHARK_REQUIRED_PREFS` and `docs/TSHARK.md` §2. Both tcp prefs OFF by default since Wireshark 3.0 per ask.wireshark #10299/#23327. Offline scapy 5-tuple seq buffering is primary, tshark oracle parity only when `which tshark` found. Single port 8000 `api/app.py` mounts `/dashboard` StaticFiles. Hybrid `WITH_DOCKER=1 bash scripts/turnup.sh` for mail lane. n_risk45 n_prior20 n_eff10 disclosure, WEAK SUPERVISION verbatim preserved.

## Tests

```bash
pytest lab/reassembler/tests/test_reassembly.py lab/reassembler/tests/test_coverage_ratio.py lab/reassembler/tests/test_history_triple.py -q
# without tshark: 22 passed, 1 skipped — mocked STILL passes coverage_ratio>0.95
# with tshark: live `tshark -T json` parity asserted
```
