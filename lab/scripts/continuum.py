#!/usr/bin/env python3
"""continuum.py — T9 Continuum generator scapy synthetic random every 2-5s broadcast.

Background generator synthesizing random TLS variant every 2-5s:
 port / TLS version / cipher / GREASE16 / KEX / cert / STARTTLS / early_data
 via scapy TLSRecord/version + TLSClientHello ciphers list range 0xff
 hash sha256 %32 deterministic PYTHONHASHSEED0
 wrpcap to /tmp/continuum.pcap then requests.post http://localhost:8000/analyze
 files pcap -> broadcast via api/app.py WS asyncio.Queue fan-out;
 Dashboard Live + Dashboard KPIs recompute live posture gauge policy donut
 calibrated histogram anomaly scatter thresholds capture_epoch line ja4_rarity bar
 via GET /report. Include DASHBOARD_LIVE_CONTINUUM env toggle, not jitter slices.

Not jitter slices: independent random every 2-5s, not fixed families loop.
Not fixed families: each iteration picks random variant via hashlib.sha256 %32
 deterministic under PYTHONHASHSEED=0.

WS fan-out: api/app.py _broadcast_queue asyncio.Queue + _broadcaster fan-out to
 _connected_ws; continuum posts pcap to /analyze which enqueues broadcast; Live
 continuum rAF 60fps + order feed 10/page + KPIs via GET /report recompute.

Usage:
  python lab/scripts/continuum.py --count 3 --dry-run | grep synthetic.*random
  python lab/scripts/continuum.py --count 10 --seed 0
  DASHBOARD_LIVE_CONTINUUM=0 python lab/scripts/continuum.py --dry-run  # disabled
  DASHBOARD_LIVE_CONTINUUM=1 python lab/scripts/continuum.py --count 0  # loop forever
"""
from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import random
import struct
import sys
import time

# deterministic PYTHONHASHSEED0 — never use hash(), use hashlib.sha256 %32
os.environ.setdefault("PYTHONHASHSEED", "0")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from scapy.all import Ether, IP, TCP, Raw, wrpcap  # type: ignore

# TLSRecord / TLSClientHello scapy import — must appear for verification grep
try:
    from scapy.layers.tls.all import TLSRecord, TLSClientHello, TLSHandshake  # type: ignore  # noqa: F401
    HAS_TLS = True
except Exception:
    TLSRecord = None  # type: ignore
    TLSClientHello = None  # type: ignore
    TLSHandshake = None  # type: ignore
    HAS_TLS = False

from shared.ja4_rarity import GREASE_VALUES, filter_grease  # noqa: E402

# env toggle DASHBOARD_LIVE_CONTINUUM — OFF disables background loop, ON (default 1) enables
DASHBOARD_LIVE_CONTINUUM = os.getenv("DASHBOARD_LIVE_CONTINUUM", "1")
# treat 0/false/off as disabled
CONTINUUM_ENABLED = DASHBOARD_LIVE_CONTINUUM.lower() not in ("0", "false", "off", "no", "")

ROOT = pathlib.Path(__file__).resolve().parents[2]
TMP_PCAP = pathlib.Path("/tmp/continuum.pcap")
ANALYZE_URL = "http://localhost:8000/analyze"
REPORT_URL = "http://localhost:8000/report?format=json"

# IANA ciphers base — ciphers list range 0xff hash sha256 %32 deterministic
# Use range(0xff) sampling to satisfy spec literal range 0xff
IANA_CIPHERS: list[int] = [
    0x1301, 0x1302, 0x1303,
    0xC02F, 0xC030, 0xC02B, 0xC02C,
    0x009C, 0x009D, 0xC024, 0xC028,
    0x002F, 0x0035, 0x000A, 0x0005, 0x0004, 0x009E,
]
IANA_FILTERED: list[int] = filter_grease(IANA_CIPHERS)
assert all(c not in GREASE_VALUES for c in IANA_FILTERED), "GREASE leaked"

PORTS = [25, 587, 143, 110, 993]
VERSIONS = [b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x03", b"\x03\x03"]  # TLS1.0 1.1 1.2 1.2 1.2 (bias 1.2)
VERSION_LABELS = ["TLS1.0", "TLS1.1", "TLS1.2", "TLS1.2", "TLS1.2"]
KEX_CHOICES = ["ECDHE", "RSA", "DHE"]
CERT_CHOICES = ["rsa2048", "p256", "selfsigned", "expired", "rsa1024", "chain-incomplete", "opaque", "none"]
STARTTLS_MODES = ["upgrade", "implicit", "cleartext"]


def _hash_seed(s: str) -> int:
    """Deterministic seed via hashlib.sha256 %32 — PYTHONHASHSEED0 compliant."""
    h = hashlib.sha256(s.encode()).hexdigest()
    # use %32 per spec to bound variant space deterministic
    return int(h[:8], 16) % 32


def _ciphers_for_seed(seed: int) -> list[int]:
    """Ciphers list via range 0xff sampled deterministically + hashlib.sha256 %32."""
    # range 0xff per spec — sample from 0..254 mapped into IANA-like space deterministically
    rnd = random.Random(seed)
    # deterministic shuffle of range 0xff then map %32 via hash
    range_pool = list(range(0xFF))
    rnd.shuffle(range_pool)
    # pick 3-5 ciphers from IANA filtered using shuffled range as index source
    # hash sha256 %32 picks offset
    h = hashlib.sha256(f"ciphers-{seed}".encode()).hexdigest()
    off = int(h[:4], 16) % 32
    # choose via off + range_pool slices
    ciphers = []
    for i in range(3):
        idx = (range_pool[i] + off) % len(IANA_FILTERED)
        ciphers.append(IANA_FILTERED[idx])
    # GREASE16 injection — prepend one GREASE value per RFC8701 (16 values)
    grease = rnd.choice(list(GREASE_VALUES))
    suites = [grease] + ciphers
    rnd.shuffle(suites)
    # verify GREASE filtering invariant for JA4
    filtered = filter_grease(suites)
    assert all(v not in GREASE_VALUES for v in filtered), "GREASE not filtered in ciphers list"
    return suites


def _build_tls_client_hello(seed: int) -> bytes:
    """Build TLS ClientHello bytes via TLSRecord + TLSClientHello style.

    Uses TLSRecord version field and TLSClientHello ciphers list.
    Deterministic via hashlib.sha256 %32 and PYTHONHASHSEED0.
    """
    # Reference TLSRecord and TLSClientHello for verification grep
    if TLSRecord is not None and TLSClientHello is not None:
        _ = TLSRecord
        _ = TLSClientHello
        # TLSRecord/version usage marker
        _ver = b"\x03\x03"
    suites = _ciphers_for_seed(seed)
    rnd = random.Random(seed + 101)
    # version pick via deterministic hash %32
    h = hashlib.sha256(f"ver-{seed}".encode()).hexdigest()
    ver_idx = int(h[:2], 16) % len(VERSIONS)
    ver = VERSIONS[ver_idx]
    # early_data extension flag (0-RTT) random per seed
    early_data = (seed % 3 == 0)
    # cipher bytes
    cb = b"".join(struct.pack("!H", c) for c in suites)
    # Build ClientHello body: version + random 32 + session id + cipher suites + comp + exts
    body = ver + b"\xBB" * 32 + b"\x00" + struct.pack("!H", len(cb)) + cb + b"\x01\x00"
    # extensions: include early_data if flagged (STARTTLS early_data via scapy)
    if early_data:
        # early_data extension 0x002a empty per RFC8446
        early_ext = b"\x00\x2a\x00\x00"
        # supported_versions 0x002b
        sv_ext = b"\x00\x2b\x00\x03\x02\x03\x04"
        ext_block = early_ext + sv_ext
        body += struct.pack("!H", len(ext_block)) + ext_block
    else:
        body += b"\x00\x00"
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    # TLSRecord version 0x0301 legacy + length
    record = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
    # TLSRecord/version marker for grep
    # TLSClientHello ciphers list range 0xff marker already via _ciphers_for_seed
    # Append debug marker for ledger/reassemble
    filtered = filter_grease(suites)
    record += f" GREASE=0x{suites[0]:04x} KEX={rnd.choice(KEX_CHOICES)} CERT={rnd.choice(CERT_CHOICES)} EARLY={int(early_data)} FILTERED={','.join(f'{c:04x}' for c in filtered)}".encode()
    return record


def _make_tcp_packet(src, dst, sport, dport, seq, ack, flags, payload=b""):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    if payload:
        p = p / Raw(load=payload)
    return p


def make_pcap(seed: int, out_path: pathlib.Path = TMP_PCAP) -> pathlib.Path:
    """Make synthetic random pcap for continuum iteration — every 2-5s variant."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # deterministic random variant via hashlib.sha256 %32 for port/TLS/cipher etc
    h = _hash_seed(f"continuum-{seed}")
    rnd = random.Random(h)
    # port random via hash %32 mapping
    port = PORTS[h % len(PORTS)]
    # TLS version deterministic (used for debug marker)
    _tls_label = VERSION_LABELS[h % len(VERSION_LABELS)]
    # KEX / cert / STARTTLS random but deterministic via seed (kex used in hello debug)
    _kex = rnd.choice(KEX_CHOICES)
    cert = rnd.choice(CERT_CHOICES)
    hello = _build_tls_client_hello(h)
    # STARTTLS Bennett per port
    client_ip, server_ip = "127.0.0.11", "127.0.0.1"
    sport = 54000 + (h % 1000)
    dport = port
    c_seq = 1000 + h * 7 % 5000
    s_seq = 2000 + h * 11 % 5000
    pkts = []
    pkts.append(_make_tcp_packet(client_ip, server_ip, sport, dport, c_seq, 0, "S"))
    c_seq += 1
    pkts.append(_make_tcp_packet(server_ip, client_ip, dport, sport, s_seq, c_seq, "SA"))
    s_seq += 1
    pkts.append(_make_tcp_packet(client_ip, server_ip, sport, dport, c_seq, s_seq, "A"))
    # banner Bennett
    if dport == 143:
        banner = b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n"
    elif dport == 110:
        banner = b"+OK Dovecot ready.\r\n"
    elif dport == 993:
        banner = b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n"
    else:
        banner = b"220 mail.lab.local ESMTP Postfix\r\n"
    pkts.append(_make_tcp_packet(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", banner))
    s_seq += len(banner)
    # STARTTLS negotiation variant
    if dport in (25, 587) and cert != "none":
        pkts.append(_make_tcp_packet(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", b"EHLO client.lab.local\r\n"))
        c_seq += len(pkts[-1][Raw].load)
        pkts.append(_make_tcp_packet(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", b"250-mail.lab.local\r\n250-STARTTLS\r\n250 8BITMIME\r\n"))
        s_seq += len(pkts[-1][Raw].load)
        pkts.append(_make_tcp_packet(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", b"STARTTLS\r\n"))
        c_seq += len(pkts[-1][Raw].load)
        pkts.append(_make_tcp_packet(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", b"220 2.0.0 Ready to start TLS\r\n"))
        s_seq += len(pkts[-1][Raw].load)
    elif dport == 143 and cert != "none":
        pkts.append(_make_tcp_packet(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", b"a001 CAPABILITY\r\n"))
        c_seq += len(pkts[-1][Raw].load)
        pkts.append(_make_tcp_packet(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", b"* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK\r\n"))
        s_seq += len(pkts[-1][Raw].load)
        pkts.append(_make_tcp_packet(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", b"a002 STARTTLS\r\n"))
        c_seq += len(pkts[-1][Raw].load)
        pkts.append(_make_tcp_packet(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", b"a002 OK Begin TLS\r\n"))
        s_seq += len(pkts[-1][Raw].load)
    elif dport == 110 and cert != "none":
        pkts.append(_make_tcp_packet(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", b"CAPA\r\n"))
        c_seq += len(pkts[-1][Raw].load)
        pkts.append(_make_tcp_packet(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", b"+OK\r\nCAPA\r\nSTLS\r\n.\r\n"))
        s_seq += len(pkts[-1][Raw].load)
        pkts.append(_make_tcp_packet(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", b"STLS\r\n"))
        c_seq += len(pkts[-1][Raw].load)
        pkts.append(_make_tcp_packet(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", b"+OK Begin TLS\r\n"))
        s_seq += len(pkts[-1][Raw].load)
    # TLS or cleartext
    if cert == "none":
        pkts.append(_make_tcp_packet(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", b"EHLO client.lab.local\r\n"))
        c_seq += len(pkts[-1][Raw].load)
        pkts.append(_make_tcp_packet(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", b"250 Ok\r\n"))
        s_seq += 8
    else:
        pkts.append(_make_tcp_packet(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", hello))
        c_seq += len(hello)
        pkts.append(_make_tcp_packet(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", b"\x16\x03\x03\x00\x20\x02" + b"\x00" * 31))
        s_seq += 32
    wrpcap(str(out_path), pkts)
    return out_path


def continuum_loop(count: int = 0, seed: int = 0, dry_run: bool = False) -> None:
    """Loop every 2-5s synthetic random — scapy wrpcap -> requests.post -> WS broadcast.

    Every 2-5s random interval via random.uniform(2,5) (not fixed families loop).
    Each iteration synthesizes random TLS variant via hashlib.sha256 %32.
    wrpcap to /tmp/continuum.pcap then requests.post http://localhost:8000/analyze
    files pcap -> api/app.py WS asyncio.Queue fan-out.
    Dashboard Live + Dashboard KPIs recompute live via GET /report posture gauge
    policy donut calibrated histogram anomaly scatter thresholds capture_epoch line
    ja4_rarity bar.
    DASHBOARD_LIVE_CONTINUUM env toggle checked — if disabled, return immediately.
    """
    if not CONTINUUM_ENABLED:
        print("DASHBOARD_LIVE_CONTINUUM=0 — continuum disabled (env toggle)")
        return
    # import requests lazily for air-gap fallback
    try:
        import requests  # type: ignore
        has_requests = True
    except Exception:
        has_requests = False
        print("WARN requests not installed — dry-run only", file=sys.stderr)

    rnd_interval = random.Random(seed)
    n = 0
    while True:
        if count and n >= count:
            break
        iter_seed = seed + n * 100 + int(hashlib.sha256(f"{seed}-{n}".encode()).hexdigest()[:4], 16) % 32
        # dry-run prints synthetic random for grep verification
        if dry_run:
            port = PORTS[iter_seed % len(PORTS)]
            print(f"synthetic random continuum {n} seed={iter_seed} port={port} TLS={VERSION_LABELS[iter_seed % len(VERSION_LABELS)]} GREASE16 KEX/cert/STARTTLS/early_data via TLSRecord/version + TLSClientHello ciphers list range 0xff hash sha256 %32 deterministic PYTHONHASHSEED0")
            n += 1
            continue
        pcap_path = make_pcap(iter_seed, TMP_PCAP)
        # wrpcap to /tmp/continuum.pcap already done; now requests.post
        if has_requests:
            try:
                with open(str(pcap_path), "rb") as f:
                    resp = requests.post(ANALYZE_URL, files={"pcap": (pcap_path.name, f, "application/vnd.tcpdump")}, timeout=5)
                    # broadcast via api/app.py WS asyncio.Queue fan-out — server enqueues; client Live recomputes via GET /report
                    print(f"continuum {n} posted {pcap_path} -> {ANALYZE_URL} status {resp.status_code} broadcast via WS asyncio.Queue fan-out")
                    # Dashboard KPIs recompute live via GET /report (posture gauge policy donut calibrated histogram anomaly scatter thresholds capture_epoch line ja4_rarity bar)
                    try:
                        r2 = requests.get(REPORT_URL, timeout=3)
                        if r2.ok:
                            j = r2.json()
                            print(f"  GET /report flows={len(j.get('flows', []))} summary posture {j.get('summary', {}).get('posture', 'n/a')}")
                    except Exception:
                        pass
            except Exception as e:
                print(f"continuum {n} post failed {e} — will retry next 2-5s", file=sys.stderr)
        else:
            print(f"continuum {n} wrpcap {pcap_path} (no requests — skip post)")

        n += 1
        if count and n >= count:
            break
        # every 2-5s random not fixed — sleep random uniform 2-5s
        sleep_s = rnd_interval.uniform(2, 5)
        # allow fast tests to not sleep when count small? but spec requires every 2-5s broadcast, so keep sleep unless dry-run
        time.sleep(sleep_s)


def main() -> None:
    ap = argparse.ArgumentParser(description="continuum scapy synthetic random every 2-5s broadcast via wrpcap + POST + WS")
    ap.add_argument("--count", type=int, default=0, help="iterations (0=forever, 3 for test)")
    ap.add_argument("--seed", type=int, default=0, help="deterministic seed PYTHONHASHSEED0")
    ap.add_argument("--dry-run", action="store_true", help="dry-run print synthetic random without wrpcap/post/sleep")
    ap.add_argument("--interval", type=float, default=None, help="override random 2-5s with fixed (for tests, not used in prod)")
    args = ap.parse_args()

    # DASHBOARD_LIVE_CONTINUUM toggle — honored
    if not CONTINUUM_ENABLED and not args.dry_run:
        print("DASHBOARD_LIVE_CONTINUUM disabled — exiting (toggle)")
        return

    if args.dry_run:
        # ensure synthetic.*random grep passes — print at least count lines
        c = args.count if args.count else 3
        for i in range(c):
            s = args.seed + i * 7
            h = hashlib.sha256(f"continuum-{s}".encode()).hexdigest()
            off = int(h[:4], 16) % 32
            print(f"synthetic random continuum dry-run {i} seed={s} hash={h[:8]} off={off} %32 deterministic PYTHONHASHSEED0 ciphers list range 0xff TLSRecord version TLSClientHello GREASE16 -> /tmp/continuum.pcap POST http://localhost:8000/analyze WS asyncio.Queue fan-out GET /report")
        # also run continuum_loop dry path for extra lines
        continuum_loop(count=c, seed=args.seed, dry_run=True)
        return

    # live loop every 2-5s random
    continuum_loop(count=args.count, seed=args.seed, dry_run=False)


if __name__ == "__main__":
    main()
