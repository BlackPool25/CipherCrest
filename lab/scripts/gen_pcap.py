#!/usr/bin/env python3
"""Generate 3 synthetic pcaps via scapy (offline, no docker required).

- family-01.pcap: 587 STARTTLS Bennett (220 banner, EHLO, 250-STARTTLS, STARTTLS, 220 Ready, ClientHello TLS1.2)
- family-06.pcap: 993 implicit TLS1.3 (* OK Dovecot, then ClientHello TLS1.3)
- family-09.pcap: 587 cleartext stripped (220 banner, EHLO without STARTTLS, MAIL/RCPT/DATA)

Each pcap is a valid Ethernet/IP/TCP flow with seq/ack progression.
TLS bytes are minimal but contain 0x16 0x03 0x01 handshake header so tshark dissects.
"""
from __future__ import annotations

import pathlib
import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap  # type: ignore

OUT = pathlib.Path(__file__).parent.parent / "pcaps"
OUT.mkdir(parents=True, exist_ok=True)

# Helpers to build raw TCP packets with seq tracking
# We use simple seq increments; not strictly accurate to real TCP but valid pcap with payload.


def make_flow(
    sport: int,
    dport: int,
    server_ip: str = "127.0.0.1",
    client_ip: str = "127.0.0.11",
    client_isn: int = 1000,
    server_isn: int = 2000,
) -> tuple[int, int]:
    """Return initial seq numbers for client and server."""
    return client_isn, server_isn


def write_pcap(path: pathlib.Path, pkts) -> None:
    wrpcap(str(path), pkts)
    print(f"Wrote {path} ({len(pkts)} packets, {path.stat().st_size} bytes)")


def tls_client_hello_tls12() -> bytes:
    """Minimal TLS 1.2 ClientHello record: 0x16 0x03 0x01 len ... 0x01 (handshake) ..."""
    # TLS record header + handshake: ContentType 22, Version 0x0301 (TLS1.0 legacy), length
    # Followed by ClientHello with legacy_version 0x0303, random 32B, etc. Keep minimal valid.
    # Use bytes that tshark will dissect as tls.handshake.type == 1
    # Build: record(5) + handshake(4) + clienthello body
    # For simplicity craft 0x16 0x03 0x01 + len + 0x01 + 3B len + version 0x0303 + 32B random + session_id_len 0 + cipher_suites len + ciphers + comp_methods
    body = (
        b"\x03\x03"  # legacy_version TLS1.2
        + b"\xAA" * 32  # random
        + b"\x00"  # session_id len
        + b"\x00\x04"  # cipher_suites len 4
        + b"\xc0\x2f"  # ECDHE-RSA-AES128-GCM-SHA256 (0xC02F)
        + b"\x00\x2f"  # RSA-AES128-CBC-SHA (fallback)
        + b"\x01\x00"  # compression methods
        + b"\x00\x00"  # extensions len 0 (minimal)
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body  # type 1, 3B len
    record_len = len(handshake)
    record = b"\x16\x03\x01" + struct.pack("!H", record_len) + handshake
    return record


def tls_client_hello_tls13() -> bytes:
    """Minimal TLS1.3 ClientHello: legacy_version 0x0303 but supported_versions 0x0304."""
    # Same as above but add supported_versions extension indicating TLS1.3
    # extensions: supported_versions (0x002b) with len 3, versions 0x0304
    ext_supported_versions = b"\x00\x2b\x00\x03\x02\x03\x04"
    # also key_share minimal x25519
    ext_key_share = b"\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20" + b"\xBB" * 32
    extensions = ext_supported_versions + ext_key_share
    ext_block = struct.pack("!H", len(extensions)) + extensions
    body = (
        b"\x03\x03"  # legacy_version
        + b"\xBB" * 32  # random
        + b"\x00"  # session_id len
        + b"\x00\x04"
        + b"\x13\x01"  # TLS_AES_128_GCM_SHA256
        + b"\x13\x02"  # TLS_AES_256_GCM_SHA384
        + b"\x01\x00"
        + ext_block
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


def gen_family01() -> None:
    """587 STARTTLS upgrade."""
    client_ip, server_ip = "127.0.0.11", "127.0.0.1"
    sport, dport = 54321, 587
    c_seq, s_seq = 1000, 2000
    pkts = []

    def tcp_pkt(src, dst, sport_, dport_, seq, ack, flags, payload=b""):
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport_, dport=dport_, seq=seq, ack=ack, flags=flags)
        if payload:
            p = p / Raw(load=payload)
        return p

    # 3-way handshake
    pkts.append(tcp_pkt(client_ip, server_ip, sport, dport, c_seq, 0, "S"))
    c_seq += 1
    pkts.append(tcp_pkt(server_ip, client_ip, dport, sport, s_seq, c_seq, "SA"))
    s_seq += 1
    pkts.append(tcp_pkt(client_ip, server_ip, sport, dport, c_seq, s_seq, "A"))

    # Server: 220 banner
    payload = b"220 mail.lab.local ESMTP Postfix\r\n"
    pkts.append(tcp_pkt(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", payload))
    s_seq += len(payload)

    # Client: EHLO
    payload = b"EHLO client.lab.local\r\n"
    pkts.append(tcp_pkt(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", payload))
    c_seq += len(payload)

    # Server: 250 with STARTTLS
    payload = b"250-mail.lab.local\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250-ENHANCEDSTATUSCODES\r\n250 8BITMIME\r\n"
    pkts.append(tcp_pkt(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", payload))
    s_seq += len(payload)

    # Client: STARTTLS Bennett command
    payload = b"STARTTLS\r\n"
    pkts.append(tcp_pkt(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", payload))
    c_seq += len(payload)

    # Server: 220 Ready to start TLS
    payload = b"220 2.0.0 Ready to start TLS\r\n"
    pkts.append(tcp_pkt(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", payload))
    s_seq += len(payload)

    # Client: TLS ClientHello (TLS1.2)
    payload = tls_client_hello_tls12()
    pkts.append(tcp_pkt(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", payload))
    c_seq += len(payload)

    # Server: TLS ServerHello stub (fake)
    payload = b"\x16\x03\x03\x00\x20" + b"\x02" + b"\x00" * 31  # minimal ServerHello record
    pkts.append(tcp_pkt(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", payload))
    s_seq += len(payload)

    write_pcap(OUT / "family-01.pcap", pkts)


def gen_family06() -> None:
    """993 implicit TLS1.3."""
    client_ip, server_ip = "127.0.0.11", "127.0.0.1"
    sport, dport = 54322, 993
    c_seq, s_seq = 3000, 4000
    pkts = []

    def tcp_pkt(src, dst, sport_, dport_, seq, ack, flags, payload=b""):
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport_, dport=dport_, seq=seq, ack=ack, flags=flags)
        if payload:
            p = p / Raw(load=payload)
        return p

    pkts.append(tcp_pkt(client_ip, server_ip, sport, dport, c_seq, 0, "S"))
    c_seq += 1
    pkts.append(tcp_pkt(server_ip, client_ip, dport, sport, s_seq, c_seq, "SA"))
    s_seq += 1
    pkts.append(tcp_pkt(client_ip, server_ip, sport, dport, c_seq, s_seq, "A"))

    # Server: * OK Dovecot ready (IMAP banner) — note this is typically sent AFTER TLS in implicit mode,
    # but we include it as cleartext before ClientHello for banner discriminator testing;
    # for implicit TLS we send banner then immediate ClientHello (some pcaps show banner after handshake — we do before for simplicity, still * OK)
    payload = b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n"
    pkts.append(tcp_pkt(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", payload))
    s_seq += len(payload)

    # Client: TLS ClientHello TLS1.3 (implicit)
    payload = tls_client_hello_tls13()
    pkts.append(tcp_pkt(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", payload))
    c_seq += len(payload)

    # Server: TLS ServerHello TLS1.3 stub
    payload = b"\x16\x03\x03\x00\x20" + b"\x02" + b"\x00" * 31
    pkts.append(tcp_pkt(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", payload))
    s_seq += len(payload)

    write_pcap(OUT / "family-06.pcap", pkts)


def gen_family09() -> None:
    """587 cleartext stripped — no STARTTLS."""
    client_ip, server_ip = "127.0.0.11", "127.0.0.1"
    sport, dport = 54323, 587
    c_seq, s_seq = 5000, 6000
    pkts = []

    def tcp_pkt(src, dst, sport_, dport_, seq, ack, flags, payload=b""):
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport_, dport=dport_, seq=seq, ack=ack, flags=flags)
        if payload:
            p = p / Raw(load=payload)
        return p

    pkts.append(tcp_pkt(client_ip, server_ip, sport, dport, c_seq, 0, "S"))
    c_seq += 1
    pkts.append(tcp_pkt(server_ip, client_ip, dport, sport, s_seq, c_seq, "SA"))
    s_seq += 1
    pkts.append(tcp_pkt(client_ip, server_ip, sport, dport, c_seq, s_seq, "A"))

    payload = b"220 mail.lab.local ESMTP Postfix\r\n"
    pkts.append(tcp_pkt(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", payload))
    s_seq += len(payload)

    payload = b"EHLO client.lab.local\r\n"
    pkts.append(tcp_pkt(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", payload))
    c_seq += len(payload)

    # Server: 250 WITHOUT STARTTLS (stripped)
    payload = b"250-mail.lab.local\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-ENHANCEDSTATUSCODES\r\n250 8BITMIME\r\n"
    pkts.append(tcp_pkt(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", payload))
    s_seq += len(payload)

    # Client continues cleartext: MAIL FROM, RCPT TO, DATA
    payload = b"MAIL FROM:<alice@lab.local>\r\n"
    pkts.append(tcp_pkt(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", payload))
    c_seq += len(payload)
    payload = b"250 2.1.0 Ok\r\n"
    pkts.append(tcp_pkt(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", payload))
    s_seq += len(payload)

    payload = b"RCPT TO:<bob@lab.local>\r\n"
    pkts.append(tcp_pkt(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", payload))
    c_seq += len(payload)
    payload = b"250 2.1.5 Ok\r\n"
    pkts.append(tcp_pkt(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", payload))
    s_seq += len(payload)

    payload = b"DATA\r\n"
    pkts.append(tcp_pkt(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", payload))
    c_seq += len(payload)
    payload = b"354 End data with <CR><LF>.<CR><LF>\r\n"
    pkts.append(tcp_pkt(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", payload))
    s_seq += len(payload)
    payload = b"Subject: Test\r\n\r\nHello world\r\n.\r\n"
    pkts.append(tcp_pkt(client_ip, server_ip, sport, dport, c_seq, s_seq, "PA", payload))
    c_seq += len(payload)
    payload = b"250 2.0.0 Ok: queued as 12345\r\n"
    pkts.append(tcp_pkt(server_ip, client_ip, dport, sport, s_seq, c_seq, "PA", payload))
    s_seq += len(payload)

    write_pcap(OUT / "family-09.pcap", pkts)


if __name__ == "__main__":
    gen_family01()
    gen_family06()
    gen_family09()
    print("All pcaps generated.")
