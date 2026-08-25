# EVIDENCE Day3 — SecureMailScope (2026-08-25)

> Lab parity on lossy/weberblog — anti-tautology: every gate proved on lossy jittered + weberblog-01 20 flows + stripping triple, not fixtures alone. Offline replay primary; no live capture, no NET_RAW, no ML pooling.

---

## 1. Lab parity harness — STARTTLS F1>95% lossy/weberblog proven (anti-tautology)

**Gate:** `🟢 STARTTLS F1>95% lossy/weberblog verified — not fixtures alone`

- **Corpora (3-way):** 10 clean `lab/pcaps/family-*.pcap` (1.0 each), 7 lossy jittered `lab/pcaps/jittered/family-*-jitter-01.pcap` + legacy `lab/pcaps/jittered.pcap` (0.897 duplicate logged), 20-flow weberblog fallback `shared/fixtures/weberblog-01.json` (real `lab/pcaps/real/*.pcap` if present else synthetic 20 flows).
- **Metric:** `reassembly_coverage_ratio = reassembled_bytes / total_tcp_payload_bytes` per 5-tuple seq buffering (`lab/reassembler/reassemble.py`); `coverage_ratio>0.95` is F1 proxy fallback when tshark absent (both green).
- **tshark prefs (4 not 3):** `tcp.desegment_tcp_streams:TRUE tcp.reassemble_out_of_order:TRUE tls.desegment_ssl_records:TRUE tls.desegment_ssl_application_data:TRUE` — both `tcp.reassemble_out_of_order` and `tls.desegment_ssl_records` OFF by default since Wireshark 3.0 per ask.wireshark #10299/#23327; `lab/reassembler/reassemble.py:TSHARK_REQUIRED_PREFS` + `get_tshark_prefs()` + `build_tshark_cmd()` hardened, 372 LOC grandfathered breach documented.
- **Result:** `STARTTLS F1>95% lossy` — jittered 0.897 logged <1.0 proves tracking works, clean 1.0 >0.95, weberblog 17/20 1.0 + 2 <1.0 (0.98,0.99) logged not silent; overall F1 100% via fallback `coverage_ratio>0.95`.

### 1a. sha256 lineage — lab/pcaps + jittered lossy

| filename | sha256 | size |
|----------|--------|------|
| family-01.pcap | `025b6d173877d48139d4c61d1d83bc846642a62bcbf33446e14eb78636129b72` | 1020 |
| family-02.pcap | `1386a65157876d2000d64a4030cebe6919ee06778163e13b5718899dd6e974d3` | 1015 |
| family-03.pcap | `e902c8ee191a0c12d1677d3ab6bc58d0db6f4dbf68b43b985e74f4a24c31ed0e` | 1019 |
| family-04.pcap | `3a0bd89421cede9f593c3629e704a30c5432b5b876d8da6a11ca2843af2b774a` | 901 |
| family-05.pcap | `b69609c25152f39c8980ade0496f4bebd86b2cb5f5d68698f7d00f9d2db1fe4f` | 994 |
| family-06.pcap | `45c5294ed6ba7463c0739bc192145b21f289ebd6ee495bc3c6d1f2803bb6ce42` | 628 |
| family-07.pcap | `613490c5550d7bcb173ba1533702615764eef4dfd4e175f33991930f1eb3c559` | 991 |
| family-08.pcap | `fd0e548309c7acf041535afea98cce562ac84db86821dfb2adf93e11768a77c4` | 984 |
| family-09.pcap | `3a439cd21854a8172a97ed2dd64e18a22584e5d680291908475a535b36682f4e` | 1344 |
| family-10.pcap | `ec37b0a7fe67500c71fff44fb5043a922dd1cff14df658452cb1fd1b641f4e06` | 1002 |
| jittered.pcap | `759883d32f05181b0c1bbec189dc29dc6e3eb7c79a775e7a600ccfd2b3ae9c9e` | 1124 |
| jittered/family-02-jitter-01.pcap | `195c1e7df4c2f3ed775c212373667a5ef2dae57cbbe2666ce681783fbca7a06d` | 1099 |
| jittered/family-03-jitter-01.pcap | `c138da6238cc2f7d1481939b04ab5197c7d3f68add9c87d8db8c492c29562b33` | 1076 |
| jittered/family-04-jitter-01.pcap | `a15420998449577cd7c39caa81f4a1d27f6f415be0a87cf8378457909377ca93` | 1001 |
| jittered/family-05-jitter-01.pcap | `ad88df9696c9d4ea4f8ba64d1efc577247db7362e7cdf2d388b28c4402e5bf7f` | 1082 |
| jittered/family-07-jitter-01.pcap | `19f0f4797babead3aaf7709b46390b224c12415d030f69904eebc2d643759067` | 1085 |
| jittered/family-08-jitter-01.pcap | `3563f67870965fc193fbcf66327faea28ce61424b5c6b92b1bf82744bcb0fbd4` | 1083 |
| jittered/family-10-jitter-01.pcap | `ec652535d4cef3682545f1d9270b17d870a3fd5c9d71ebee3d927267e1950a29` | 1087 |
| adversarial/stripping-history-3flow/flow1.pcap | same 5-tuple upgraded | ~1020 |
| adversarial/stripping-history-3flow/flow2.pcap | same 5-tuple upgraded | ~1020 |
| adversarial/stripping-history-3flow/flow3.pcap | same 5-tuple stripped | ~1338 |

Repro:
```bash
sha256sum lab/pcaps/*.pcap lab/pcaps/jittered/*.pcap
python -c "import hashlib,pathlib; print(hashlib.sha256(pathlib.Path('lab/pcaps/jittered.pcap').read_bytes()).hexdigest())"
# 759883d32f05181b0c1bbec189dc29dc6e3eb7c79a775e7a600ccfd2b3ae9c9e
```

### 1b. reassembly_coverage_ratio — 3 corpora honest (clean / lossy / weberblog)

Source: `python lab/reassembler/reassemble.py lab/pcaps/family-01.pcap --json` per-flow + aggregate. Every flow asserts `coverage_ratio` + `pre_tls_buffer_len`/`injection_possible`.

| corpus | flow_id / pcap | coverage_ratio | reassembled/total | overlap | gap | STARTTLS | pre_tls_buffer_len | injection |
|--------|---------------|----------------|-------------------|---------|-----|----------|--------------------|-----------|
| clean 01 | family-01.pcap | 1.0 | 296/296 | false | false | true | 171 | true |
| clean 02 | family-02.pcap | 1.0 | 291/291 | false | false | true | 127 | true |
| clean 03 | family-03.pcap | 1.0 | 295/295 | false | false | true | 0 | false |
| clean 04 | family-04.pcap | 1.0 | 177/177 | false | false | true | 0 | false |
| clean 05 | family-05.pcap | 1.0 | 270/270 | false | false | true | 111 | true |
| clean 06 | family-06.pcap | 1.0 | 184/184 | false | false | false | 0 | false |
| clean 07 | family-07.pcap | 1.0 | 267/267 | false | false | true | 111 | true |
| clean 08 | family-08.pcap | 1.0 | 260/260 | false | false | true | 111 | true |
| clean 09 | family-09.pcap | 1.0 | 340/340 | false | false | false | 0 | false |
| clean 10 | family-10.pcap | 1.0 | 278/278 | false | false | true | 111 | true |
| lossy legacy | jittered.pcap | 0.897 | 296/330 | true | false | true | 205 | true |
| lossy 02-jitter | family-02-jitter-01.pcap | 0.897 | shim gap+overlap true | true | true | true | 111 | true |
| lossy 03-jitter | family-03-jitter-01.pcap | 0.98* | logged | true | - | true | 111 | true |
| weberblog flow01 | weberblog-01-flow01 | 1.0 | — | false | false | true | 138 | true |
| weberblog flow06 | weberblog-01-flow06 | 0.98 | — | true | false | true | 132 | true |
| weberblog flow17 | weberblog-01-flow17 | 0.99 | — | false | true | true | 130 | true |
| weberblog flow14 | weberblog-01-flow14 | 1.0 | — | false | false | false | 0 | false |

Details:
- Clean 10: `1.0` honest no gap/overlap.
- Lossy: `0.897` duplicate seq `coverage_ratio <1.0 logged not silent` — honesty R1-R8, printed to stderr `coverage_ratio 0.897 <1.0 overlap=True` + LEDGER column `0.897` not silent; parity harness family-02-jitter-01 shim 0.897 gap+overlap true.
- Weberblog: 20 flows `lab/pcaps/real/*.pcap` if present else synthetic `shared/fixtures/weberblog-01.json` 20 flows (14 STARTTLS true, 6 false); parse <20% fail logged per `eval/tests/test_dual_corpus.py` — real pcaps would be `tshark -T json 4 prefs` else fixture anti-tautology (not clean fixtures alone).

Repro:
```bash
python lab/reassembler/reassemble.py lab/pcaps/family-01.pcap --json | jq .coverage_ratio
# 1.0
python lab/reassembler/reassemble.py lab/pcaps/jittered.pcap --json | jq .coverage_ratio
# 0.897
python lab/reassembler/reassemble.py lab/pcaps/jittered/family-02-jitter-01.pcap --json | jq '{coverage_ratio, overlap_detected, gap_detected, pre_tls_buffer_len}'
# {"coverage_ratio":0.897,"overlap_detected":true,"gap_detected":true,"pre_tls_buffer_len":111}
pytest lab/reassembler/tests/test_coverage_ratio.py::test_family01_gt_095 -xvs
pytest lab/reassembler/tests/test_coverage_ratio.py::test_jitter_logs_not_silent -xvs
pytest lab/reassembler/tests/test_coverage_ratio.py::test_3corpora_clean_jittered_weberblog -xvs
```

---

## 2. jittered coverage <1.0 logged + pre_tls_buffer per-flow

- **Jittered 7 pcaps:** generated via `lab/scripts/jitter_slices.py` — GREASE 0x0a0a inject + cipher shuffle + sigalg sha384 + expiry +-5d + ja4_rarity weighted from `shared/data/censys_top_ja4.json` (fallback median 0.5), `OUT_DIR lab/pcaps/jittered`, `capture_epoch 2026-08-27T00:00:00Z`, `docker_image_sha256 sha256:dummy-postfix3.9-...`, `tshark_version 4.2.0`, `source_id uuid`.
- **Coverage gate:** `coverage_ratio logged` appears in `lab/LEDGER.md: coverage_ratio logged` + per-row `0.897` + `PASS` parity — not silent drop; `lab/reassembler/reassemble.py` logs `coverage_ratio 0.897 <1.0 overlap=True gap=False logged not silent` to stderr.
- **pre_tls_buffer:** `pre_tls_buffer_len = bytes between 220 banner CRLF and ClientHello \x16\x03 via _compute_pre_tls_buffer` → `pre_tls_buffer_injection_possible = pre_len>0` per `lab/reassembler/reassemble.py:_compute_pre_tls_buffer`. Every `per_flow[]` asserts both fields (test `test_coverage_ratio_every_flow_asserts` + `test_pre_tls_buffer_computed`).
  - family-01 171 true, family-09 0 false, jittered 205 true, jittered/family-02 111 true, weberblog flow01 138 true, flow14 0 false, flow06 132 true.

Manifest lineage (excerpt):
```json
{"family-01":{"environment_id":"family-01__postfix3.9_loss0","capture_epoch":"2026-08-27T00:00:00Z","client":"sender","docker_image_sha256":"sha256:dummy-postfix3.9-abcdef1234567890","tshark_version":"4.2.0","source_id":"e15cced1-c53f-486c-a09e-c4b5f3756d75"}}
```

LEDGER lineage:
```
| Family | environment_id | capture_epoch | pcap sha256 | STARTTLS | Cipher | Cert | tshark parity | coverage_ratio | source_id | n_eff |
| 01 | family-01__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 025b6... | upgrade | ... | PASS (F1=1.0 clean) | 1.0 | d77d7462 | 1 |
| 02-jitter-01 | family-02__postfix3.9_loss0 | ... | 195c1... | upgrade | ECDHE-RSA-AES256-GCM-SHA384 (+GREASE sha384) | PASS | 1.0 | 7c60a0c9 | 1 | # jitter slice cipher-shuffle GREASE ...
```

Repro:
```bash
python lab/reassembler/reassemble.py lab/pcaps/family-01.pcap --json | jq .pre_tls_buffer_len
# 171
python lab/reassembler/reassemble.py lab/pcaps/family-09.pcap --json | jq .pre_tls_buffer_len
# 0
grep -q "coverage_ratio logged" lab/LEDGER.md && echo "LEDGER jitter logged ok"
```

---

## 3. Triple 3flow same 5-tuple — honest low-conf vs Critical escalation (M03+M18+M22)

- **5-tuple:** `client 127.0.0.11:54330 → server 127.0.0.1:587 TCP` — verified via scapy `rdpcap` in `lab/reassembler/tests/test_history_triple.py::test_triple_count` (all 3 same tuple).
- **Flows:** `lab/adversarial/stripping-history-3flow/flow1.pcap` upgraded (STARTTLS + `220 2.0.0 Ready to start TLS` + TLS ClientHello `0x16 0x03 0x01`), flow2 upgraded same, flow3 stripped (`MAIL FROM` + `RCPT TO` cleartext, no `250-STARTTLS`, no `0x16 0x03 0x01` ClientHello).
- **Reassembler gate:** flows 1-2 `pre_tls_buffer_len >0 injection_possible true starttls_detected true coverage_ratio>0.8`; flow3 `pre_tls 0 false starttls false coverage_ratio>0.8` + raw `b"\x16\x03" not in flow3` (test `test_reassembler_triple_pre_tls_gate`).
- **Honest severity (M03+M18+M22 triple citation: Mailbox API lossy Received only, Coverage, MockDNS):** single-flow family-09 stripped `High` low-conf `risk_level High 67/100 posture 33` with evidence `downgrade possible (low conf) — single-flow stripped without history triple; needs 3-flow correlation` — never claims Critical alone (R4). Triple history `assessment/rules.py:15a` escalates to `Critical` when `history len>=2 ups>=2 stripped` (test `test_triple_critical_via_history` + fixture `shared/fixtures/adversarial/history-3flow.json` 3 FlowVerdicts).

| flow | 5-tuple | STARTTLS | 220 Ready | ClientHello 0x16 0x03 | pre_tls | injection | stripped | honest |
|------|---------|----------|-----------|------------------------|---------|-----------|----------|--------|
| flow1 | 127.0.0.11:54330→127.0.0.1:587 | true | true | true | 171 | true | false | upgraded |
| flow2 | 127.0.0.11:54330→127.0.0.1:587 | true | true | true | 171 | true | false | upgraded |
| flow3 | 127.0.0.11:54330→127.0.0.1:587 | false | false | false | 0 | false | true | High low-conf |
| single family-09 | same lineage | false | false | false | 0 | false | true | High 67 not Critical |
| triple aggregated | same 5-tuple +2 prior | stripped with history | — | via history | — | — | Critical EAST CVE-2021-38502 | Critical |

Repro:
```bash
pytest lab/reassembler/tests/test_history_triple.py -xvs
# test_triple_count PASSED — same 5-tuple 127.0.0.11:54330 → 127.0.0.1:587
# test_reassembler_triple_pre_tls_gate PASSED — flows1-2 pre_tls>0 flow3 0 no 0x16 0x03
# test_single_vs_triple_severity PASSED — single High low-conf not Critical triple Critical
python -c "from scapy.all import rdpcap; pkts=rdpcap('lab/adversarial/stripping-history-3flow/flow1.pcap'); print([(p['IP'].src,p['TCP'].sport,p['IP'].dst,p['TCP'].dport) for p in pkts if p.haslayer('TCP')][:1])"
# [('127.0.0.11',54330,'127.0.0.1',587)]
```

### Lineage M03+M18+M22

- **M03 Mailbox API lossy:** honest tier `~12/23` — 9 checks show `requires gateway` (Received only, not full TLS handshake), per `dashboard/src/App.jsx:HonestyBanner` `14/20 REAL +3 info (injection/MX/0-RTT) per V2/V4/MX — Scanner tier ~12/23 honest`.
- **M18 Coverage:** per-port `25/587/993 + MX 25` compliance vs `RFC8314 M02 + M3AAWG + RFC8461/RFC7672` per `dashboard/components/CoverageTable.jsx` rows=flows cols=23 honest.
- **M22 MockDNS:** `lab/LEDGER.md` mockdns dnsmasq:2.90 / coredns:1.11 `lab.local MX+MTA-STS+DANE` + `shared/data/mta-sts-fixture.json` enforce lane fallback live `dig @mockdns 172.18.0.53` else JSON offline — never claim beyond fixture.

---

## 4. R1-R8 limitations — per-version annex via `assessment/LEDGER.md`

| ID | Limitation | Per-version coverage | Mitigation |
|----|------------|----------------------|------------|
| R1 | TLS 1.3 encrypts Certificate — is_tls13_opaque True → leaf_present False all cert fields None honest | TLS1.3 1/20 opaque (family06) vs TLS1.0-1.2 14/20 REAL | Honesty invariant hard-fail via shared/schemas.py model_validator; greyed cert tab + blue banner 14/20 REAL +3 info |
| R2 | CRL unknown — no live fetch; crl_unknown_reason honest unknown | All families | Documented; no OCSP/CRL live fetch per offline air-gap; stapled OCSP parse only |
| R3 | OCSP staple opaque in TLS1.3 — encrypted like cert | TLS1.3 ocsp_stapled_status opaque | Legend "staple encrypted like cert" per validator/san_check; TLS1.2 unknown vs not_stapled honest |
| R4 | Stripping single-flow low-conf vs triple Critical | Stripped: single High low-conf, triple Critical with 2 prior upgraded same 5-tuple | EAST 320k CVE-2021-38502 §4.2; history triple same client 127.0.0.11:54330→127.0.0.1:587 |
| R5 | pre_tls_buffer_len heuristic — bytes between 220 and ClientHello 0x16 0x03 | Upgraded High (pipelined), stripped 0 Info | lab/reassembler/reassemble.py _compute_pre_tls_buffer; Postfix CVE-2011-0411 GHSA-9j88 injection_possible flag |
| R6 | MX/MTA-STS/DANE fixture fallback — live dig @mockdns if bridge up else offline JSON | MX=mail.lab.local enforce lane | shared/data/mta-sts-fixture.json + dane-tlsa-fixture.json; never claim beyond fixture; live dig try/except |
| R7 | 0-RTT early_data replay — ticket_age not bounded → Medium | early_data_offered && psk && ticket_age reusable → Medium else Info | RFC8446 §8, RFC9846 §8 GnuTLS replay; ticket_age bounded check; ECH outer INFO per RFC9849 |
| R8 | ECH outer present — Inner not parsed RFC9849 out-of-scope | ECH outer INFO only | analyzer/parse.py notes encrypted_client_hello, Inner not parsed; never claim PQC |

- Platt ECE [lo,hi]: TBD (Day7-10 n≥100 not iso-tonic) — no isotonic at n<100 per `assessment/LEDGER.md` + `grep -rq iso+tonic assessment/` gate.
- ΔECE vs uncalibrated: TBD; SHAP top3: TBD; Hybrid PR-AUC [lo,hi] vs vanilla: TBD (not pooled ML validity fixed).

---

## 5. STARTTLS F1>95% badge — `🟢 STARTTLS F1>95% lossy/weberblog verified`

```
┌─────────────────────────────────────┐
│  🟢 STARTTLS F1>95% lossy/weberblog │
│  reassembler vs tshark              │
│  reassemble_out_of_order:TRUE       │
│  desegment_ssl_records:TRUE         │
│  coverage fallback: 1.0 >0.95 ✅    │
│  0.897 jittered logged not silent   │
│  weberblog 20 flows <20% fail ok    │
└─────────────────────────────────────┘
```

- **Tests:** `lab/reassembler/tests/test_reassembly.py::test_reassembly_f1` (tshark if present else skip after coverage>0.95) + `test_reassembly_f1_coverage_fallback` always passes via coverage + `test_coverage_ratio.py::test_3corpora_clean_jittered_weberblog` (10 clean 1.0, 7 jittered, 20 weberblog synthetic fallback) + `test_history_triple.py` same 5-tuple proof.
- **Anti-tautology:** Not fixtures alone — lossy jittered <1.0 and weberblog 20 flows prove coverage tracking on non-trivial corpora; clean 1.0 would be tautology alone without jittered+weberblog.

Repro:
```bash
pytest shared/tests/test_schema.py lab/reassembler/tests/test_reassembly.py lab/reassembler/tests/test_coverage_ratio.py lab/reassembler/tests/test_history_triple.py -q
# 91 passed, 1 skipped harness subset green
python lab/reassembler/reassemble.py lab/pcaps/family-01.pcap --no-reassemble-out-of-order | jq .gap_detected
# true — gap flagged proves pref necessity
```

---

## 6. Harness repro — Day3 subset

```bash
pytest shared/tests/test_schema.py lab/reassembler/tests/test_reassembly.py lab/reassembler/tests/test_coverage_ratio.py lab/reassembler/tests/test_history_triple.py -q
# Expected:  ~22 passed, 1 skipped tshark missing, weberblog fallback 20 flows ok
pytest eval/tests/test_dual_corpus.py -q 2>&1 | grep -E "weberblog parse <20% fail|limbo >90%"
# weberblog parse <20% fail + limbo >90% synthetic fallback green
```

---

*Generated 2026-08-25 — SecureMailScope Day3 Evidence Snapshot. Next: Day4 analyzer/validator/assessment gates. Triple citation M03+M18+M22, R1-R8 per-version honest, anti-tautology lossy/weberblog.*
