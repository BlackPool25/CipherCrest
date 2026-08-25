# Lab — SecureMailScope Day1-Day2

Offline replay is primary (no live capture required, no NET_RAW). Live docker is stretch/demo lane.

## Docker services
- `postfix:3.9` `smtpd_tls_mandatory_protocols=>=TLSv1.2` STARTTLS 587/25
- `dovecot:2.3` `ssl=required` `ssl_min_protocol=TLSv1.2` implicit 993 + STARTTLS 143/110
- `mockdns` dnsmasq:2.90 / coredns:1.11 serving lab.local MX+MTA-STS+DANE
- `sender` alpine:3.19 with swaks openssl tcpdump
- network `lab` bridge `172.18.0.0/24`

See `lab/docker-compose.yml`, `lab/manifest.json`, `lab/LEDGER.md`.

## Traffic generation
```bash
bash lab/scripts/gen_traffic.sh --help          # shows history-triple, dry-run
bash lab/scripts/gen_traffic.sh --dry-run       # echoes Family01..10 + swaks/openssl/curl/telnet + tcpdump without executing
bash lab/scripts/gen_traffic.sh                 # offline scapy pcaps (10 families)
bash lab/scripts/gen_traffic.sh --history-triple  # adversarial triple 127.0.0.11:54330 -> 127.0.0.1:587
```

Each family loops `swaks` variants, `openssl s_client -starttls smtp`, `curl imap://`, telnet scripts, plus:
```
tcpdump -w family-{id}.pcap -i any port 25 or 587 or 143 or 110 or 993
```
(host or br-lab). Offline fallback via `python3 lab/scripts/gen_pcap.py` + `/tmp/gen10.py` (scapy wrpcap). Live lane requires docker.

Tshark oracle (both OFF by default since 3.0):
```
tshark -r lab/pcaps/family-01.pcap -T json \
  -o tcp.desegment_tcp_streams:TRUE \
  -o tcp.reassemble_out_of_order:TRUE \
  -o tls.desegment_ssl_records:TRUE \
  -o tls.desegment_ssl_application_data:TRUE
```

## Network jitter
Optional jitter for 2 families to de-uniform timings (realism, coverage_ratio logging not silent).

Apply netem on loopback or bridge:
```bash
# per-port jitter — de-uniform timings for 2 families, log coverage_ratio <1 not silent
sudo tc qdisc add dev lo root netem delay 20ms 5ms
sudo tc qdisc add dev eth0 root netem delay 20ms jitter 5ms
# alternative br-lab
sudo tc qdisc add dev br-lab root netem delay 20ms 5ms distribution normal
sudo tc qdisc show dev lo
# remove
sudo tc qdisc del dev lo root
sudo tc qdisc del dev eth0 root
```

This documents `tc qdisc` with `delay 20ms` (and jitter 5ms) for 2 families to ensure reassembly handles out-of-order/jitter and logs `coverage_ratio` rather than silently dropping. Coverage is measured as `reassembly_coverage_ratio = reassembled_bytes / total_tcp_payload_bytes` per flow in `lab/reassembler/reassemble.py` and `lab/LEDGER.md`.

## Adversarial history triple
`lab/adversarial/stripping-history-3flow/{flow1.pcap,flow2.pcap,flow3.pcap}` — same client=127.0.0.11 server=127.0.0.1:587 sport 54330 (same 5-tuple), flows 1-2 upgraded STARTTLS→220→TLS, flow3 cleartext stripped. Single-flow stripped is **High low-conf** (honest); triple history (2 prior successes + 1 stripped) escalates to **Critical**.

## Pcaps and fixtures
- `lab/pcaps/family-{01..10}.pcap` 10 families distinct ciphers
- `shared/fixtures/family-{01,06,09}.json` FlowVerdict validated
- `shared/fixtures/adversarial/history-3flow.json` synthetic 3 FlowVerdicts
- `lab/adversarial/stripping-history-3flow/` pcap triple (5-tuple identical)

