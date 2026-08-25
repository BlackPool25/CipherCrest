# Lab Ledger — SecureMailScope

Offline replay is primary (no live capture required, no NET_RAW). Live docker is stretch/demo lane.

| Family | pcap sha256 | STARTTLS | Cipher | Cert | tshark parity | coverage_ratio |
|--------|-------------|----------|--------|------|---------------|----------------|
| 01 | 025b6d173877d48139d4c61d1d83bc846642a62bcbf33446e14eb78636129b72 | upgrade | ECDHE-RSA-AES128-GCM-SHA256 | rsa2048 | PASS (F1=1.0 clean) | 1.0 |
| 02 | 1386a65157876d2000d64a4030cebe6919ee06778163e13b5718899dd6e974d3 | upgrade | ECDHE-RSA-AES256-GCM-SHA384 P-256 | p256 | PASS (F1=1.0 clean) | 1.0 |
| 03 | e902c8ee191a0c12d1677d3ab6bc58d0db6f4dbf68b43b985e74f4a24c31ed0e | upgrade | DES-CBC3-SHA SWEET32 3DES | rsa2048 | PASS (F1=1.0 clean) | 1.0 |
| 04 | 3a0bd89421cede9f593c3629e704a30c5432b5b876d8da6a11ca2843af2b774a | upgrade | RC4-SHA TLS1.0 | rsa2048 | PASS (F1=1.0 clean) | 1.0 |
| 05 | b69609c25152f39c8980ade0496f4bebd86b2cb5f5d68698f7d00f9d2db1fe4f | upgrade | AES128-SHA TLS1.1 | selfsigned | PASS (F1=1.0 clean) | 1.0 |
| 06 | 45c5294ed6ba7463c0739bc192145b21f289ebd6ee495bc3c6d1f2803bb6ce42 | implicit TLS1.3 opaque | TLS_AES_128_GCM_SHA256 x25519 | opaque | PASS (F1=1.0 clean) | 1.0 |
| 07 | 613490c5550d7bcb173ba1533702615764eef4dfd4e175f33991930f1eb3c559 | upgrade | AES128-SHA256 SHA1 expired | expired | PASS (F1=1.0 clean) | 1.0 |
| 08 | fd0e548309c7acf041535afea98cce562ac84db86821dfb2adf93e11768a77c4 | upgrade | DES-CBC-SHA rsa1024 | rsa1024 | PASS (F1=1.0 clean) | 1.0 |
| 09 | 3a439cd21854a8172a97ed2dd64e18a22584e5d680291908475a535b36682f4e | cleartext stripped | none | none | PASS (F1=1.0 clean) | 1.0 |
| 10 | ec37b0a7fe67500c71fff44fb5043a922dd1cff14df658452cb1fd1b641f4e06 | upgrade | RSA-AES256-SHA no-FS | chain-incomplete | PASS (F1=1.0 clean) | 1.0 |

Notes:
- STARTTLS Bennett: 220 banner discriminator (220 ESMTP vs * OK IMAP), STARTTLS keyword + 220 Ready → upgraded_at, else cleartext. IMAP uses CAPABILITY→STARTTLS / a002 OK Begin TLS, POP3 uses CAPA→STLS / +OK Begin TLS.
- Coverage: `reassembly_coverage_ratio = reassembled_bytes / total_tcp_payload_bytes` per 5-tuple seq buffering; overlap flag + gap detection; tshark prefs `tcp.reassemble_out_of_order:TRUE tls.desegment_ssl_records:TRUE tls.desegment_ssl_application_data:TRUE`. Jittered pcap lab/pcaps/jittered.pcap coverage_ratio <1.0 (0.897 overlap duplicate, logged not silent — honesty R1-R8). pre_tls_buffer_len bytes between 220 and ClientHello (\x16\x03) flags injection_possible when >0 (family-01 138/171, family-09 0).
- Certs: CA lab.local (RSA2048 SHA256 365d), rsa2048 SHA256 90d, p256 prime256v1, expired (notAfter 2026-08-24 past, SHA1 weakness in ledger/manifest), selfsigned, chain-incomplete (withheld intermediate), rsa1024 (1024-bit SHA256 90d).
- Network: lab bridge 172.18.0.0/24, postfix:3.9 `smtpd_tls_mandatory_protocols=>=TLSv1.2` + `smtpd_tls_chain_files`, dovecot:2.3 `ssl=required` `ssl_min_protocol=TLSv1.2` `disable_plaintext_auth=yes`, mockdns dnsmasq:2.90 placeholder Day1. Per-family overrides documented in docker-compose.yml comments Family02 25 P-256, Family03 143 3DES-CBC, Family04 110 RC4 TLS1.0, Family05 587 TLS1.1 self-signed, Family07 587 expired SHA1, Family08 587 DES rsa1024, Family10 587 RSA-no-FS chain-incomplete.
- tshark smoke F1>95% vs reassembler on clean pcaps; lossy/weberblog deferred to Day2+.
- 10-family matrix pcaps generated via scapy synthetic (gen_pcap.py + gen10.py) with distinct ciphers per F.2 (no reuse of Family01 ECDHE-RSA-AES128-GCM-SHA256 for weak families). Each pcap contains STARTTLS/CAPA markers and cipher-specific Raw CIPHER= payload for tshark regex.
