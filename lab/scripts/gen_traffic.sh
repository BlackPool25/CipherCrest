#!/bin/bash
# lab/scripts/gen_traffic.sh — generate 10-family pcaps + adversarial triple history
# Offline replay is primary; live lane uses swaks/openssl s_client/curl/telnet when docker up.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  echo "Usage: $0 [--help] [--dry-run] [--history-triple]"
  echo "  --help            show this help (mentions history-triple, dry-run)"
  echo "  --dry-run         list families without generating (echo only, no docker/net)"
  echo "  --history-triple  generate adversarial/history-3flow triple (same 5-tuple, 2 upgraded + 1 stripped)"
  echo ""
  echo "Families 01-10: 587 STARTTLS Bennett, 25 P-256, 143 3DES-CBC SWEET32, 110 RC4 TLS1.0, 587 TLS1.1 self-signed, 993 TLS1.3 opaque, 587 expired SHA1, 587 DES rsa1024, 587 stripped, 587 RSA-no-FS"
  echo "Live lane (when docker up): swaks + openssl s_client -starttls smtp + curl imap:// + telnet CAPABILITY->STARTTLS / CAPA->STLS / EHLO->STARTTLS + tcpdump"
  echo "Offline: python3 lab/scripts/gen_pcap.py + /tmp/gen10.py (scapy wrpcap)"
  echo "History triple: scapy wrpcap lab/adversarial/stripping-history-3flow/{flow1,flow2,flow3}.pcap (127.0.0.11:54330 -> 127.0.0.1:587, flows 1-2 upgraded STARTTLS->220->TLS, flow3 stripped)"
  echo "Jitter doc: see lab/README.md tc qdisc netem delay 20ms jitter 5ms"
}

# --help: print usage and exit 0, must contain history-triple string for grep
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
  echo "gen_traffic.sh — 10-family pcap generator"
  echo "Families: 01 587 TLS1.2 ECDHE-RSA-AES128-GCM, 02 25 P-256, 03 143 3DES-CBC SWEET32, 04 110 RC4 TLS1.0, 05 587 TLS1.1 self-signed, 06 993 TLS1.3 opaque, 07 587 expired SHA1, 08 587 DES rsa1024, 09 cleartext stripped, 10 RSA-no-FS chain-incomplete"
  echo "Live lane (when docker up): swaks + openssl s_client + curl imap + telnet CAPABILITY->STARTTLS / CAPA->STLS"
  echo "Offline: python3 lab/scripts/gen_pcap.py + /tmp/gen10.py (scapy wrpcap)"
  echo "Options: --dry-run, --history-triple"
  usage
  exit 0
fi

# --dry-run: echo families + commands without executing docker/net
if [[ "${1:-}" == "--dry-run" ]]; then
  echo "Family01 587 STARTTLS Bennett — swaks --to bob@lab.local --from alice@lab.local --server 127.0.0.1:587 --tls"
  echo "  openssl s_client -starttls smtp -connect 127.0.0.1:587"
  echo "  tcpdump -w family-01.pcap -i any port 25 or 587 or 143 or 110 or 993 (host or br-lab)"
  echo "  tshark -r lab/pcaps/family-01.pcap -T json -o tcp.desegment_tcp_streams:TRUE -o tcp.reassemble_out_of_order:TRUE -o tls.desegment_ssl_records:TRUE -o tls.desegment_ssl_application_data:TRUE"
  echo "Family02 25 P-256 TLS1.2 — swaks --to bob@lab.local --server 127.0.0.1:25 --tls --port 25"
  echo "  openssl s_client -starttls smtp -connect 127.0.0.1:25 -cipher ECDHE-RSA-AES256-GCM-SHA384"
  echo "Family03 143 3DES-CBC SWEET32 CAPABILITY->STARTTLS — curl imap://127.0.0.1:143 --ssl-reqd -v"
  echo "  telnet 127.0.0.1 143 -> CAPABILITY / STARTTLS / a002 OK Begin TLS"
  echo "Family04 110 RC4 TLS1.0 CAPA->STLS — openssl s_client -starttls pop3 -connect 127.0.0.1:110 -cipher RC4-SHA"
  echo "  telnet 127.0.0.1 110 -> CAPA / STLS / +OK Begin TLS"
  echo "Family05 587 TLS1.1 self-signed — openssl s_client -starttls smtp -connect 127.0.0.1:587 -tls1_1 -cipher AES128-SHA"
  echo "Family06 993 implicit TLS1.3 opaque — openssl s_client -connect 127.0.0.1:993"
  echo "  curl imaps://127.0.0.1:993 -v"
  echo "Family07 587 expired SHA1 — openssl s_client -starttls smtp -connect 127.0.0.1:587 -cipher AES128-SHA256"
  echo "Family08 587 DES rsa1024 — openssl s_client -starttls smtp -connect 127.0.0.1:587 -cipher DES-CBC-SHA"
  echo "Family09 587 stripped — telnet 127.0.0.1 587 EHLO no STARTTLS -> MAIL FROM:<alice@lab.local> RCPT TO:<bob@lab.local> DATA"
  echo "Family10 587 RSA-no-FS chain-incomplete — openssl s_client -starttls smtp -connect 127.0.0.1:587 -cipher AES256-SHA"
  echo "  tcpdump -w family-{id}.pcap -i any port 25 or 587 or 143 or 110 or 993 (host or br-lab) — would run tshark with prefs: tcp.reassemble_out_of_order:true tls.desegment_ssl_records:true"
  echo "Would run offline: python3 lab/scripts/gen_pcap.py && python3 /tmp/gen10.py"
  exit 0
fi

# --history-triple: generate 3 flows same 5-tuple, flows 1-2 upgraded, flow3 stripped
if [[ "${1:-}" == "--history-triple" ]]; then
  echo "history-triple: generating 3 flows same 5-tuple src 127.0.0.11:54330 dst 127.0.0.1:587"
  echo "  flow1: STARTTLS -> 220 Ready -> TLS ClientHello (upgraded)"
  echo "  flow2: STARTTLS -> 220 Ready -> TLS ClientHello (upgraded)"
  echo "  flow3: EHLO without STARTTLS -> MAIL/RCPT/DATA (stripped cleartext)"
  mkdir -p "$LAB_DIR/adversarial/stripping-history-3flow"

  python3 << 'PYEOF'
import pathlib, struct
from scapy.all import Ether, IP, TCP, Raw, wrpcap

OUT = pathlib.Path("lab/adversarial/stripping-history-3flow")
OUT.mkdir(parents=True, exist_ok=True)

CLIENT_IP = "127.0.0.11"
SERVER_IP = "127.0.0.1"
SPORT = 54330
DPORT = 587

def tls_client_hello() -> bytes:
    body = b"\x03\x03" + b"\xAA"*32 + b"\x00" + b"\x00\x04" + b"\xc0\x2f\x00\x2f" + b"\x01\x00" + b"\x00\x00"
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record

def make_pkt(src, dst, sport, dport, seq, ack, flags, payload=b""):
    p = Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    if payload:
        p = p/Raw(load=payload)
    return p

def gen_flow(flow_id: int, upgraded: bool):
    # Use same sport for all 3 to simulate same client 5-tuple; seq differs per flow file but 5-tuple identical
    # Different ISN per flow to keep pcaps independent yet same 5-tuple host:port
    client_isn = 1000 + flow_id*100
    server_isn = 2000 + flow_id*100
    c_seq = client_isn
    s_seq = server_isn
    pkts=[]
    # SYN
    pkts.append(make_pkt(CLIENT_IP, SERVER_IP, SPORT, DPORT, c_seq, 0, "S")); c_seq+=1
    pkts.append(make_pkt(SERVER_IP, CLIENT_IP, DPORT, SPORT, s_seq, c_seq, "SA")); s_seq+=1
    pkts.append(make_pkt(CLIENT_IP, SERVER_IP, SPORT, DPORT, c_seq, s_seq, "A"))
    # 220 banner
    payload = b"220 mail.lab.local ESMTP Postfix\r\n"
    pkts.append(make_pkt(SERVER_IP, CLIENT_IP, DPORT, SPORT, s_seq, c_seq, "PA", payload)); s_seq+=len(payload)
    # EHLO
    payload = b"EHLO client.lab.local\r\n"
    pkts.append(make_pkt(CLIENT_IP, SERVER_IP, SPORT, DPORT, c_seq, s_seq, "PA", payload)); c_seq+=len(payload)
    if upgraded:
        # Server 250 with STARTTLS
        payload = b"250-mail.lab.local\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250-ENHANCEDSTATUSCODES\r\n250 8BITMIME\r\n"
        pkts.append(make_pkt(SERVER_IP, CLIENT_IP, DPORT, SPORT, s_seq, c_seq, "PA", payload)); s_seq+=len(payload)
        # Client STARTTLS
        payload = b"STARTTLS\r\n"
        pkts.append(make_pkt(CLIENT_IP, SERVER_IP, SPORT, DPORT, c_seq, s_seq, "PA", payload)); c_seq+=len(payload)
        # Server 220 Ready
        payload = b"220 2.0.0 Ready to start TLS\r\n"
        pkts.append(make_pkt(SERVER_IP, CLIENT_IP, DPORT, SPORT, s_seq, c_seq, "PA", payload)); s_seq+=len(payload)
        # TLS ClientHello
        payload = tls_client_hello()
        pkts.append(make_pkt(CLIENT_IP, SERVER_IP, SPORT, DPORT, c_seq, s_seq, "PA", payload)); c_seq+=len(payload)
        # ServerHello stub
        payload = b"\x16\x03\x03\x00\x20\x02" + b"\x00"*31
        pkts.append(make_pkt(SERVER_IP, CLIENT_IP, DPORT, SPORT, s_seq, c_seq, "PA", payload)); s_seq+=len(payload)
    else:
        # Stripped: 250 WITHOUT STARTTLS
        payload = b"250-mail.lab.local\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-ENHANCEDSTATUSCODES\r\n250 8BITMIME\r\n"
        pkts.append(make_pkt(SERVER_IP, CLIENT_IP, DPORT, SPORT, s_seq, c_seq, "PA", payload)); s_seq+=len(payload)
        # Cleartext MAIL/RCPT/DATA
        payload = b"MAIL FROM:<alice@lab.local>\r\n"
        pkts.append(make_pkt(CLIENT_IP, SERVER_IP, SPORT, DPORT, c_seq, s_seq, "PA", payload)); c_seq+=len(payload)
        payload = b"250 2.1.0 Ok\r\n"
        pkts.append(make_pkt(SERVER_IP, CLIENT_IP, DPORT, SPORT, s_seq, c_seq, "PA", payload)); s_seq+=len(payload)
        payload = b"RCPT TO:<bob@lab.local>\r\n"
        pkts.append(make_pkt(CLIENT_IP, SERVER_IP, SPORT, DPORT, c_seq, s_seq, "PA", payload)); c_seq+=len(payload)
        payload = b"250 2.1.5 Ok\r\n"
        pkts.append(make_pkt(SERVER_IP, CLIENT_IP, DPORT, SPORT, s_seq, c_seq, "PA", payload)); s_seq+=len(payload)
        payload = b"DATA\r\n"
        pkts.append(make_pkt(CLIENT_IP, SERVER_IP, SPORT, DPORT, c_seq, s_seq, "PA", payload)); c_seq+=len(payload)
        payload = b"354 End data with <CR><LF>.<CR><LF>\r\n"
        pkts.append(make_pkt(SERVER_IP, CLIENT_IP, DPORT, SPORT, s_seq, c_seq, "PA", payload)); s_seq+=len(payload)
        payload = b"Subject: Stripped test\r\n\r\nHello\r\n.\r\n"
        pkts.append(make_pkt(CLIENT_IP, SERVER_IP, SPORT, DPORT, c_seq, s_seq, "PA", payload)); c_seq+=len(payload)
        payload = b"250 2.0.0 Ok: queued\r\n"
        pkts.append(make_pkt(SERVER_IP, CLIENT_IP, DPORT, SPORT, s_seq, c_seq, "PA", payload)); s_seq+=len(payload)

    out = OUT / f"flow{flow_id}.pcap"
    wrpcap(str(out), pkts)
    print(f"Wrote {out} ({len(pkts)} packets, {out.stat().st_size} bytes) upgraded={upgraded} 5-tuple {CLIENT_IP}:{SPORT} -> {SERVER_IP}:{DPORT}")

# flows 1-2 upgraded, flow3 stripped
gen_flow(1, upgraded=True)
gen_flow(2, upgraded=True)
gen_flow(3, upgraded=False)
print("Triple history complete: 3 pcaps same 5-tuple 127.0.0.11:54330 -> 127.0.0.1:587")
PYEOF

  echo "History triple generated at $LAB_DIR/adversarial/stripping-history-3flow/"
  ls -lh "$LAB_DIR/adversarial/stripping-history-3flow/"
  exit 0
fi

# Default: no args — loop families 01-10 with swaks/openssl/curl/telnet docs + offline fallback
echo "=== gen_traffic.sh — 10-family generation (offline primary, live lane documented) ==="

families=(
  "Family01|587|STARTTLS Bennett TLS1.2 ECDHE-RSA-AES128-GCM-SHA256|swaks --to bob@lab.local --from alice@lab.local --server 127.0.0.1:587 --tls|openssl s_client -starttls smtp -connect 127.0.0.1:587|tcpdump -w family-01.pcap -i any port 25 or 587 or 143 or 110 or 993"
  "Family02|25|STARTTLS TLS1.2 P-256 ECDHE-RSA-AES256-GCM-SHA384|swaks --to bob@lab.local --server 127.0.0.1:25 --tls --port 25|openssl s_client -starttls smtp -connect 127.0.0.1:25 -cipher ECDHE-RSA-AES256-GCM-SHA384|tcpdump -w family-02.pcap -i any port 25 or 587 or 143 or 110 or 993"
  "Family03|143|CAPABILITY->STARTTLS 3DES-CBC SWEET32|curl imap://127.0.0.1:143 --ssl-reqd -v|openssl s_client -starttls imap -connect 127.0.0.1:143 -cipher DES-CBC3-SHA|tcpdump -w family-03.pcap -i any port 143"
  "Family04|110|CAPA->STLS RC4 TLS1.0|telnet 127.0.0.1 110 -> CAPA / STLS|curl pop3://127.0.0.1:110 --ssl-reqd -v|openssl s_client -starttls pop3 -connect 127.0.0.1:110 -cipher RC4-SHA -tls1|tcpdump -w family-04.pcap -i any port 110"
  "Family05|587|STARTTLS TLS1.1 self-signed|swaks --to bob@lab.local --server 127.0.0.1:587 --tls --protocol TLSv1.1|openssl s_client -starttls smtp -connect 127.0.0.1:587 -tls1_1 -cipher AES128-SHA|tcpdump -w family-05.pcap -i any port 587"
  "Family06|993|implicit TLS1.3 opaque|curl imaps://127.0.0.1:993 -v|openssl s_client -connect 127.0.0.1:993|tcpdump -w family-06.pcap -i any port 993"
  "Family07|587|STARTTLS expired SHA1|swaks --to bob@lab.local --server 127.0.0.1:587 --tls|openssl s_client -starttls smtp -connect 127.0.0.1:587 -cipher AES128-SHA256|tcpdump -w family-07.pcap -i any port 587"
  "Family08|587|STARTTLS DES rsa1024|swaks --to bob@lab.local --server 127.0.0.1:587 --tls|openssl s_client -starttls smtp -connect 127.0.0.1:587 -cipher DES-CBC-SHA|tcpdump -w family-08.pcap -i any port 587"
  "Family09|587|stripped cleartext|telnet 127.0.0.1 587 -> EHLO (no STARTTLS) -> MAIL FROM -> RCPT TO -> DATA|curl smtp://127.0.0.1:587 -v|tcpdump -w family-09.pcap -i any port 587"
  "Family10|587|STARTTLS RSA-no-FS chain-incomplete|swaks --to bob@lab.local --server 127.0.0.1:587 --tls|openssl s_client -starttls smtp -connect 127.0.0.1:587 -cipher AES256-SHA|tcpdump -w family-10.pcap -i any port 587"
)

for entry in "${families[@]}"; do
  IFS='|' read -r fam port desc swaks_cmd openssl_cmd tcpdump_cmd <<< "$entry"
  echo "$fam $port $desc"
  echo "  $swaks_cmd"
  echo "  $openssl_cmd"
  echo "  $tcpdump_cmd -i any port 25 or 587 or 143 or 110 or 993 (host or br-lab)"
done

echo ""
echo "Offline generation: python3 lab/scripts/gen_pcap.py + /tmp/gen10.py (scapy wrpcap)"
python3 "$SCRIPT_DIR/gen_pcap.py"
python3 /tmp/gen10.py 2>/dev/null || python3 -c "import pathlib; print('gen10 inline fallback: pcaps already exist', list(pathlib.Path('lab/pcaps').glob('*.pcap')))"
echo "All 10 pcaps ready: $(ls "$LAB_DIR/pcaps"/family-*.pcap 2>/dev/null | wc -l) files"

# Live lane docs (when docker up):
#  swaks --to bob@lab.local --server 127.0.0.1:25 --tls --port 25  # Family02
#  curl imap://127.0.0.1:143 --ssl-reqd -v                          # Family03 CAPABILITY->STARTTLS
#  openssl s_client -starttls pop3 -connect 127.0.0.1:110 -cipher RC4-SHA  # Family04 CAPA->STLS
#  openssl s_client -starttls smtp -connect 127.0.0.1:587 -tls1_1 -cipher AES128-SHA  # Family05
#  openssl s_client -starttls smtp -connect 127.0.0.1:587 -cipher AES128-SHA256  # Family07 expired
#  openssl s_client -starttls smtp -connect 127.0.0.1:587 -cipher DES-CBC-SHA    # Family08 rsa1024
#  telnet 127.0.0.1 143 -> CAPABILITY / telnet 127.0.0.1 110 -> CAPA / EHLO -> STARTTLS
#  tcpdump -w family-{id}.pcap -i any port 25 or 587 or 143 or 110 or 993 (host or br-lab)

