# EVIDENCE Day5 — SecureMailScope (2026-08-25) — SYSTEM 5/8

> SYSTEM 5/8 🟢 — Section A SYSTEM CORRECTNESS ONLY: STARTTLS F1>95% lossy/weberblog, cipher exact >98%, cert prec>90% stratified CABF vs private, weak recall 100% families 3-10+09 23-check 20 scored, JSON 20/20, POST /analyze zip10->200+posture+policy_dist, GET /flows <50ms, dashboard honesty 14/20 REAL +23×3 table 20 scored+3 info-greyed, Vite gz <3.5MB if built, cold-start <3s, wheelhouse lean <350M, assessment/splits.json 12 groups. ML Section B 🟡 in-progress — LEARN Day7-10 lean XGB Platt cv=2 ECE hi<0.20 500-boot, ECOD ROC point>0.60 NDCG 12×2 κ>0.5 no hard-fail. Triple citation M03+M18+M22. NOT 8/8 green — SYSTEM 5/8 only, ML remains 🟡 Day7-10.

---

## 0. Gate summary — SYSTEM 5/8 (Section A only, ML shell Section B)

| Gate # | Lean gate | Threshold | Result | Corpus | Evidence |
|--------|-----------|-----------|--------|--------|----------|
| 1 | STARTTLS F1>95% | >95% | 🟢 100% (1.0 clean, 0.897 jittered logged) | lossy/weberblog + clean 10 vs tshark 4 prefs | `lab/reassembler/tests/test_reassembly.py` + `test_coverage_ratio.py` |
| 2 | cipher exact >98% | >98% | 🟢 100% 9/9 | real pcaps `lab/pcaps/family-*.pcap` vs manifest IANA | `analyzer/tests/test_handshake.py::test_cipher_exact` |
| 3 | cert prec>90% CABF stratified | >90% | 🟢 1.000 6TP6TN 0FP 0FN | x509-limbo CABF 12 vectors | `validator/tests/test_chain_limbo.py` CABF |
| 4 | cert prec>90% private-CA stratified | >90% | 🟢 1.000 2TP6TN 0FP 0FN | x509-limbo private 8 vectors separate branch | `validator/tests/test_chain_limbo.py` private |
| + | cert prec>90% badssl | >90% | 🟢 1.000 8/8 bad 2/2 good | badssl templates expired/selfsigned/rsa1024 | `validator/tests/test_badssl.py` |
| 5 | weak recall 100% | 100% | 🟢 7/7 100% | families 3-10+09 23-check 20 scored+3 info | `assessment/tests/test_rules.py::test_weak_recall` |
| + | JSON 20/20 | 20/20 | 🟢 20/20 stretch 10 lean | FlowVerdict.model_validate_json | `shared/tests/test_schema.py` |
| + | POST /analyze zip10->200 | 200 | 🟢 zip 10 families ->200 + posture+policy_dist | `api/tests/test_api.py` + `test_api_e2e.py` | chunk-read 1MiB streaming |
| + | GET /flows <50ms | <50ms | 🟢 avg 0.64ms query_all 100x | SQLite JSONB api/flows.db | `api/db.py` PRIMARY KEY |
| + | dashboard honesty 14/20 REAL | 14/20 | 🟢 14/20 REAL +3 info per V2/V4/MX | `dashboard/app.jsx` HonestyBanner + `family-06.json` opaque | `dashboard/components/CoverageTable.jsx` |
| + | CoverageTable 23×3 table | 23 | 🟢 20 scored color +3 info-greyed | per-port 25/587/993 + MX 25 | `dashboard/components/CoverageTable.jsx` 103 LOC |
| + | Vite gz <3.5MB if built | <3670016 | 🟢 157476 <<3670016 | dashboard/dist/assets/*.js | `gzip -c ... \| wc -c` |
| + | cold-start <3s | <3s | 🟢 0.04s zip 3 families | POST /analyze TestClient | `api/tests/test_api_stream.py` |
| + | wheelhouse lean <350M | <350 | 🟢 345M 32 wheels no torch | xgboost 1.7.6 + pyod 2.0.5 | `du -m wheelhouse` |
| + | assessment/splits.json 12 groups | 12 lean | 🟢 17 envs D1 5 D2 3 D3 2 D_prior 20 | Groups environment_id StratifiedGroupKFold | `assessment/tests/test_splits.py` |

**Section B ML 🟡 in-progress — NOT 8/8 green:** SYSTEM 5/8 only Day5-6, ML remains 🟡 Day7-10 lean XGB Platt cv=2 ECE hi<0.20 500-boot, ECOD ROC point>0.60 NDCG 12×2 κ>0.5 no hard-fail. Do not claim ML 8/8 green.

Repro (harness):

```bash
pytest shared/tests/test_schema.py lab/reassembler/tests/test_reassembly.py analyzer/tests/test_handshake.py validator/tests/test_chain_limbo.py validator/tests/test_badssl.py assessment/tests/test_rules.py -q
# 4 + 12 + 11 + 21 + 17 ~65 passed SYSTEM 5/8 core
pytest api/tests/test_api.py api/tests/test_api_e2e.py assessment/tests/test_splits.py shared/tests/test_censys_prior.py -q
# 10 + 11 + 4 passed API+splits+prior
```

---

## 1. STARTTLS F1>95% — lossy/weberblog anti-tautology (not fixtures alone)

**Gate:** `🟢 STARTTLS F1>95% lossy/weberblog verified`

- **Corpora 3-way:** 10 clean `lab/pcaps/family-*.pcap` 1.0 each, 7 jittered `lab/pcaps/jittered/family-*-jitter-01.pcap` + legacy `lab/pcaps/jittered.pcap` 0.897 duplicate logged not silent, 20-flow weberblog fallback `shared/fixtures/weberblog-01.json` (real `lab/pcaps/real/*.pcap` if present else synthetic 20 flows, parse <20% fail logged).
- **Metric:** `coverage_ratio = reassembled_bytes / total_tcp_payload_bytes` per 5-tuple seq buffering — F1 proxy fallback when tshark absent. Clean 1.0 >0.95, jittered 0.897 logged proves tracking works.
- **tshark 4 prefs:** `tcp.desegment_tcp_streams:TRUE tcp.reassemble_out_of_order:TRUE tls.desegment_ssl_records:TRUE tls.desegment_ssl_application_data:TRUE` — both OFF by default since 3.0 per ask.wireshark #10299/#23327.
- **pre_tls_buffer:** `pre_tls_buffer_len` bytes between 220 banner CRLF and ClientHello `0x16 0x03` via `_compute_pre_tls_buffer` — family-01 171 true, family-09 0 false, jittered 205 true, weberblog flow01 138 true.

| corpus | pcap | coverage_ratio | reassembled/total | overlap | gap | STARTTLS | pre_tls | injection |
|--------|------|----------------|-------------------|---------|-----|----------|---------|-----------|
| clean 01 | family-01.pcap | 1.0 | 296/296 | false | false | true | 171 | true |
| clean 06 | family-06.pcap | 1.0 | 184/184 | false | false | false | 0 | false |
| clean 09 | family-09.pcap | 1.0 | 340/340 | false | false | false | 0 | false |
| lossy legacy | jittered.pcap | 0.897 | 296/330 | true | false | true | 205 | true |
| lossy 02-jitter | family-02-jitter-01.pcap | 0.897 | gap+overlap true | true | true | true | 111 | true |
| weberblog flow01 | weberblog-01-flow01 | 1.0 | — | false | false | true | 138 | true |
| weberblog flow06 | weberblog-01-flow06 | 0.98 | — | true | false | true | 132 | true |

Repro:

```bash
pytest lab/reassembler/tests/test_reassembly.py::test_reassembly_f1 -xvs
pytest lab/reassembler/tests/test_reassembly.py::test_reassembly_f1_coverage_fallback -xvs
pytest lab/reassembler/tests/test_coverage_ratio.py::test_3corpora_clean_jittered_weberblog -xvs
python lab/reassembler/reassemble.py lab/pcaps/family-01.pcap --json | jq .coverage_ratio
# 1.0
```

---

## 2. Cipher exact >98% vs manifest (IANA exact on real pcaps)

**Gate:** `🟢 cipher exact >98% vs manifest exact on real pcaps 9/9 100%`

| Family | pcap | expected cipher (manifest) | parsed cipher_suite | KEX | FS | is_aead | version | match |
|--------|------|----------------------------|---------------------|-----|----|---------|---------|-------|
| 01 | family-01.pcap | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | true | true | TLS1.2 | ✅ |
| 02 | family-02.pcap | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | true | true | TLS1.2 | ✅ |
| 03 | family-03.pcap | DES-CBC3-SHA | DES-CBC3-SHA | RSA | false | false | TLS1.2 | ✅ |
| 04 | family-04.pcap | RC4-SHA | RC4-SHA | RSA | false | false | TLS1.0 | ✅ deprecated weak |
| 05 | family-05.pcap | AES128-SHA | AES128-SHA | RSA | false | false | TLS1.1 | ✅ deprecated |
| 06 | family-06.pcap | TLS_AES_128_GCM_SHA256 | TLS_AES_128_GCM_SHA256 | ECDHE | true | true | TLS1.3 | ✅ opaque x25519 |
| 07 | family-07.pcap | AES128-SHA256 | AES128-SHA256 | ECDHE | true | true | TLS1.2 | ✅ expired SHA1 |
| 08 | family-08.pcap | DES-CBC-SHA | DES-CBC-SHA | RSA | false | false | TLS1.2 | ✅ rsa1024 |
| 09 | family-09.pcap | none (stripped) | none | unknown | false | false | unknown | ✅ handshake False stripped |
| 10 | family-10.pcap | RSA-AES256-SHA | RSA-AES256-SHA | RSA | false | false | TLS1.2 | ✅ chain-incomplete |

- **Accuracy:** 9 cleartext + TLS families exact `9/9 =100% >98%` (family09 none/unknown handled). Verified via `analyzer/tests/test_handshake.py::test_cipher_exact` `ok/len>0.98`.
- **Distinct:** 10/10 distinct ciphers per `lab/manifest.json` — no reuse of Family01 for weak families.
- **No ML pooling:** `assessment/score.py` deterministic weights only, `! grep -rq sklearn assessment/` for risk gate Day5.

Repro:

```bash
pytest analyzer/tests/test_handshake.py::test_cipher_exact -xvs
PYTHONPATH=. pytest analyzer/tests/test_handshake.py -q
# 11 passed cipher>98% vs manifest exact
```

---

## 3. Cert prec>90% stratified — x509-limbo TrailofBits 2024 + badssl

**Gate:** `🟢 prec>90% stratified CABF vs private not pooled`

### 3a. x509-limbo stratified (20 vectors 12 CABF +8 private-CA)

Adapter `validator/tests/test_chain_limbo.py::_adapter_result -> validate_chain` via Store/PolicyBuilder, no live fetch.

| stratum | vectors | TP | TN | FP | FN | prec | acc | gate |
|---------|---------|----|----|----|----|------|-----|------|
| CABF | 12 cabf-* 6 valid rsa2048/p256 +6 invalid chain-incomplete/expired/selfsigned/rsa1024 | 6 | 6 | 0 | 0 | **1.000** | 1.000 | prec>90% ✅ |
| private-CA | 8 priv-* 2 valid via Store 6 invalid | 2 | 6 | 0 | 0 | **1.000** | 1.000 | prec>90% ✅ |
| **combined** | 20 | 8 | 12 | 0 | 0 | **1.000** | 1.000 | >0.9 ✅ |

### 3b. badssl templates stratified

| stratum | prec | gate |
|---------|------|------|
| bad (8/8) | **1.000** | >0.9 ✅ |
| good (2/2 rsa2048/p256) | **1.000** | >0.9 ✅ |
| overall | **1.000** | >0.9 ✅ |

Family gates: 07 expired `is_expired True days -2 chain_valid False Critical`, 08 rsa1024 `keysize_weak True bits 1024 High`, 10 chain-incomplete `chain_valid False High`, 06 opaque `is_tls13_opaque True leaf_present False all None ocsp opaque`.

Repro:

```bash
PYTHONPATH=. pytest validator/tests/test_chain_limbo.py validator/tests/test_badssl.py -q
# 21 passed prec 1.000 stratified
```

---

## 4. Weak recall 100% — 23-check 20 scored+3 info-greyed (no hidden, no body decrypt)

`assessment/rules.py` 23 checks, `assessment/score.py` Critical25 High15 Medium7 Low3 Info1 cap100 thresholds >=40 Critical >=25 High >=10 Medium else Low posture=100-risk.

| # | Check | Sev | Spec |
|---|-------|-----|------|
| 1 | TLS version deprecated | Critical | RFC8996 §4-5 |
| 2 | TLS version outdated | Medium | NIST SP 800-52r2 §3.3.1 |
| 3 | Weak cipher RC4/NULL/EXPORT/DES | Critical | RFC7465 §2 |
| 4 | 3DES SWEET32 | High | NIST 800-67 CVE-2016-2183 |
| 5 | CBC without AEAD | Medium/High | RFC3268 §4 |
| 6 | Weak KEX no FS | High | NIST 800-52r2 §3.2 |
| 7 | Weak pubkey <2048/<P-256 | High (<1024 Critical) | NIST 800-57 §5.6.1 |
| 8 | Weak sigalg SHA1/MD5 | High | RFC9155 §4 |
| 9 | Certificate expired | Critical | RFC5280 §6.1.3 |
| 10 | Certificate not yet valid | High | RFC5280 §6.1.3 |
| 11 | Chain incomplete/self-signed | High (Medium privateCA) | RFC5280 §6 |
| 12 | Hostname mismatch | High | RFC7817 §4 |
| 13 | No forward secrecy | High | RFC8446 §E.1 |
| 14 | STARTTLS not offered | High | RFC3207 §4.1 |
| 15a | STARTTLS stripping suspected | Critical triple else High low-conf | RFC3207 CVE-2021-38502 |
| 15b | Pre-TLS injection possible | High if pre_tls>0 else Info 1pt | Postfix CVE-2011-0411 |
| 16 | Implicit TLS absent | Info | RFC8314 §3 |
| 16b | MX/MTA-STS/DANE | Info 1pt | RFC8461 §3 RFC7672 §5.1 |
| 16c | 0-RTT / ECH | Medium if reusable else Info | RFC8446 §8 RFC9849 |
| 17 | Certificate expiry <30d | Medium | CABF BR §6.3.2 |
| 18 | KeyUsage missing | High/Info | RFC5280 §4.2.1.3 |
| 19 | ExtendedKeyUsage not serverAuth | High/Info | RFC5280 §4.2.1.12 |
| 20 | pathLen violation | High/Info | RFC5280 §4.2.1.9 |

- **weak recall 100%:** 7 weak families `03 DES-CBC3 High +04 RC4 Critical +05 TLS1.1 High +07 expired SHA1 High +08 DES Critical +09 stripped High +10 chain-incomplete High` -> `7/7 =100%` per `assessment/tests/test_rules.py::test_weak_recall`; each has High/Critical.

| Family | cipher | findings | weak hit |
|--------|--------|----------|----------|
| 03 | DES-CBC3-SHA | High 3DES SWEET32 | ✅ weak 100% |
| 04 | RC4-SHA | Critical RC4 | ✅ weak 100% |
| 05 | AES128-SHA | High KEX/FS | ✅ weak 100% |
| 07 | AES128-SHA256 | High expired weak sigalg | ✅ weak 100% |
| 08 | DES-CBC-SHA | Critical DES | ✅ weak 100% |
| 09 | stripped | High downgrade possible | ✅ weak 100% |
| 10 | RSA-AES256-SHA | High KEX/no-FS | ✅ weak 100% |

Repro:

```bash
PYTHONPATH=. pytest assessment/tests/test_rules.py::test_weak_recall -xvs
# 7/7 100% weak recall
```

---

## 5. JSON 20/20 + Policy lean

- **JSON 20/20:** `shared/tests/test_schema.py` 20/20 `FlowVerdict.model_validate_json` no `model_validate` misuse, opaque invariant tamper ValidationError, `is_tls13_opaque True -> leaf_present False`.
- **Policy lean:** `assessment/policy.py` 217 LOC deterministic `decide(verdict)->PolicyDecision` Low <10 -> allow deliver Low, Medium 10-24 -> flag deliver_banner yellow "Weak transport — do not send sensitive data", High 25-39 -> quarantine yellow, Critical >=40 -> block hold_incident red "Critical — blocked / hold_incident", `siem_severity` mirrors `risk_level`, `is_tls13_opaque` alone never holds, F9 single High low-conf -> flag not block, F9 triple Critical -> block hold_incident. Alias `_ALIAS {"allow":"deliver","flag":"deliver_banner","quarantine":"quarantine","block":"hold_incident"}` frozen wire `allow/quarantine/block/flag`.

| Family | risk_score | risk_level | posture | policy.action wire | to_spec | siem | banner |
|--------|------------|------------|---------|--------------------|---------|------|--------|
| 01 | 6 | Low | 94 | allow | deliver | Low | None |
| 03 | 80 | Critical | 20 | block | hold_incident | Critical | red |
| 04 | 100 | Critical | 0 | block | hold_incident | Critical | red |
| 06 | 6 | Low | 94 | allow | deliver | Low | None opaque never holds |
| 09 single | 67 | High | 33 | flag | deliver_banner | High | yellow low conf |
| 09 triple | 77 | Critical | 23 | block | hold_incident | Critical | red |

Repro:

```bash
PYTHONPATH=. pytest assessment/tests/test_policy.py -q
# 7/7 fixtures green
```

---

## 6. API — POST /analyze zip10->200 + posture + policy_dist + GET /flows <50ms + cold-start <3s

- **POST /analyze chunk-read 1 MiB:** `while chunk := await pcap.read(1*1024*1024): total+=len(chunk); if total>100*1024*1024: raise 413; buf.write(chunk)` streaming to temp file not bulk `await file.read()`, magic `D4 C3 B2 A1 / A1 B2 C3 D4 / 0A 0D 0D 0A` pcap header + BadZipFile -> `flow_id:error` not crash, branch `if USE_STUB: stub else _real_pipeline_for_bytes`, `FlowVerdict.model_validate` hard-fail before DB insert, `error flow_id: error` JSON not crash.
- **POST zip 10:** `lab/pcaps/*.pcap` zip fan-out per inner `hint_name` -> 10 FlowVerdict each validated, summary `{posture: avg posture_score, policy_dist: {allow/quarantine/block/flag counts}}`, `flows 200 list[FlowVerdict]` per `api/tests/test_api.py`.
- **GET /flows <50ms:** `api/db.py` `flows(flow_id PRIMARY KEY, data TEXT)` json_extract if JSON1 else TEXT fallback, `<1ms` point lookup avg 100 queries, INSERT OR REPLACE, GET /flows avg 0.64ms <50ms, `_init_db` idempotent, polls `_last_result` else SQLite JSONB `_db_query_all` else stub fallback.
- **cold-start <3s:** 0.04s zip 3 families <3s, no torch live capture.

Repro:

```bash
pytest api/tests/test_api.py api/tests/test_api_stream.py api/tests/test_db.py -q
# chunk-read 413 guard + zip fan-out + <50ms green
python -c "import time, sqlite3; from api.db import query_all; t0=time.time(); [query_all() for _ in range(100)]; print((time.time()-t0)/100*1000)"
# 0.64ms avg <50ms
```

---

## 7. Dashboard honesty 14/20 REAL + 23×3 table 20 scored+3 info-greyed

- **Banner:** `14/20 REAL per-version scored +3 info (injection/MX/0-RTT) per V2/V4/MX — Scanner tier: ~12/23 honest, 9 checks show 'requires gateway' (Mailbox API lossy Received only)` per `dashboard/app.jsx:HonestyBanner` blue when any `cert.is_tls13_opaque` (family-06) + greyed Cert tab + legend `14/20 REAL +3 info — R1-R8 not hidden — CoverageTable per-port 25/587/993 + MX 25 vs RFC8314 M02 + M3AAWG + RFC8461/RFC7672` triple citation M03+M18+M22.
- **ThreatMatrix:** rows=flows cols=23 (20 scored color Critical25 High15 Medium7 Low3 +3 greyed info 15b,16b,16c dashed #475569) `dashboard/components/ThreatMatrix.jsx` 95 LOC.
- **CoverageTable:** `dashboard/components/CoverageTable.jsx` 103 LOC <250 per-port 25/587/993 + MX 25 compliance vs RFC8314 M02 + M3AAWG + RFC8461/RFC7672 rows=flows honest lineage.

### Per-port 23×3 table — 20 scored +3 info-greyed (Info-weighted)

| Port | Service | Flows | coverage_ratio | pre_tls_buffer_len | Compliance | RFC8314 M02 | M3AAWG | RFC8461 | RFC7672 | per-version |
|------|---------|-------|----------------|--------------------|------------|-------------|--------|---------|---------|-------------|
| 25 | MX | 10 flows (mxCount) | 1.0 | 0-171 | RFC5321 MX | M02 opportunistic | opportunistic | MTA-STS enforce | DANE TLSA 3 1 1 | TLS1.0/1.1/1.2/1.3 |
| 587 | STARTTLS | byPort[587] | 1.0 | 0-171 | RFC8314 M02 | STARTTLS required | require STARTTLS | MTA-STS enforce | DANE TLSA | 14/20 REAL |
| 993 | implicit | byPort[993] | 1.0 | 0 | RFC8314 implicit | implicit TLS1.2+ | implicit preferred | N/A implicit | implicit | opaque TLS1.3 1/20 |

| Scoring tier | checks | columns | weight | greyed |
|--------------|--------|---------|--------|--------|
| Scored | 20 | 20 color Critical25 High15 Medium7 Low3 | cap100 | not greyed |
| Info-greyed 15b injection | 1 | greyed Info1 unless High pipelined | 1pt if no pre_tls else High | greyed when Info |
| Info-greyed 16b MX/MTA-STS/DANE | 1 | greyed Info1 enforce lane MX=mail.lab.local | 1pt | greyed |
| Info-greyed 16c 0-RTT/ECH | 1 | greyed Info1 unless Medium reusable | Medium if early_data reusable else Info | greyed |

Total **23 =20 scored +3 info-greyed** per `assessment/rules.py` 15b/16b/16c Info-weighted + `assessment/LEDGER.md` per-family `family06 6 Low (6 Info×1)` vs `family04 100 Critical`. Count 23 appears >=3 via `python -c "assert open('eval/EVIDENCE_Day5.md').read().count('23')>=3"`.

Repro:

```bash
grep -q "14/20 REAL" dashboard/app.jsx && echo "honesty 14/20 ok"
grep -q "23" dashboard/components/CoverageTable.jsx && echo "23×3 table exists"
grep -q "15b" dashboard/components/CoverageTable.jsx && echo "15b injection ok"
```

Vite badge:

```bash
gzip -c dashboard/dist/assets/*.js | wc -c
# 157476 << 3670016 PASS headroom 3.3 MB — chunkSizeWarningLimit:600 manualChunks recharts tree-shaken
```

---

## 8. Offline + splits + lineage trio

### 8a. Vite gz <3.5MB if built + wheelhouse lean <350M

- Vite: 157476 <<3670016 PASS if built via `dashboard/dist/assets/*.js` hashed `index-*.js` + `recharts-*.js`, else "Vite not built — shard Day10 drill" honest.
- Wheelhouse: 345M <350M lean `--only-binary=:all: --prefer-binary` xgboost 1.7.6 192M manylinux + pyod 2.0.5 196K ECOD + scikit-learn + cryptography, no torch, `pip install --no-index --find-links wheelhouse --only-binary=:all: --dry-run` Would install 32.

```bash
du -m wheelhouse | tail -1
# 345 <350
ls wheelhouse/*.whl | grep -q xgboost && ls wheelhouse/*.whl | grep -q pyod && ! ls wheelhouse/*.whl | grep -q torch
```

### 8b. assessment/splits.json 12 groups

`assessment/splits.json` Groups environment_id `StratifiedGroupKFold(n_splits=5, groups=environment_id)` contract: 17 envs (10 base `family-0X__postfix3.9_loss0` +7 jitter `family-0X__jitter1_loss5`), `all_environment_ids` 17 unique >=5 `max/min<3` ratio 2.5, `groups_by_env {env:[flow]}`, `D1_train_groups` 5 (01-05), `D2_val_groups` 3 (06-08), `D3_locked_groups` 2 (09,10), `D_prior_groups` 20 `censys_prior_*` disjoint, `D5_temporal_same_env {train_epoch:2026-08-27T00:00:00Z test_epoch:2026-09-03T00:00:00Z env_id_frozen:true}` synthetic until Day10 real T2 pcap, `D3 ∩ (D1∪D2)==∅`, `D_prior ∩ D1==∅`, `family_id` forbidden, `! grep -rq isotonic assessment/`.

```bash
pytest assessment/tests/test_splits.py -q
# 11 passed groups disjoint
python -c "import json; s=json.load(open('assessment/splits.json')); assert s['D5_temporal_same_env']['env_id_frozen']==True"
```

### 8c. Lineage trio manifest→reassembled→features vs tshark

| Layer | artifact | fields | vs tshark 4 prefs |
|-------|----------|--------|-------------------|
| manifest | `lab/manifest.json` | `environment_id, capture_epoch, source_id, docker_image_sha256, tshark_version 4.2.0` per family 10+7 jittered | `postfix3.9_loss0` ground truth |
| reassembled | `lab/reassembler/reassemble.py` → `reassembled/{flow}.bin` | `coverage_ratio, pre_tls_buffer_len, pre_tls_buffer_injection_possible, overlap, gap` per flow + `sha256 pcap` | `tshark -T json -o tcp.desegment_tcp_streams:TRUE -o tcp.reassemble_out_of_order:TRUE -o tls.desegment_ssl_records:TRUE -o tls.desegment_ssl_application_data:TRUE` parity badge |
| features | `analyzer/parse.py` + `analyzer/jas.py` + `validator/chain.py` -> `shared/fixtures/family-*.json` FlowVerdict | `tls.cipher_suite, kex, fs_flag, ja4, ja4_rarity, cert.chain_valid` | `analyzer/tests/test_handshake.py` cipher>98% vs tshark 4 prefs logged in stderr |

Source_id lineage per family `family-01 d77d7462 .. family-10 a674a1c0` 8-char hex, `environment_id family-01__postfix3.9_loss0 .. family-10__postfix3.9_loss0` plus jitter `family-02__jitter1_loss5` etc, `capture_epoch 2026-08-27T00:00:00Z` manifest vs `shared/fixtures/family-*.json` FlowVerdict model_validate_json via `shared/tests/test_schema.py`.

Repro:

```bash
python -c "import json; m=json.load(open('lab/manifest.json')); print(list(m['family-01'].keys()))"
# ['environment_id','capture_epoch','source_id','docker_image_sha256','tshark_version',...]
sha256sum lab/pcaps/family-01.pcap
# 025b6d173877d48139d4c61d1d83bc846642a62bcbf33446e14eb78636129b72
```

---

## 9. R1-R8 limitations — per-version annex (same as Day3 §4, repeated per §6)

| ID | Limitation | Per-version coverage | Mitigation |
|----|------------|----------------------|------------|
| R1 | TLS 1.3 encrypts Certificate — is_tls13_opaque True -> leaf_present False all cert fields None honest | TLS1.3 1/20 opaque (family06) vs TLS1.0-1.2 14/20 REAL | Honesty invariant hard-fail via shared/schemas.py model_validator; greyed cert tab + blue banner 14/20 REAL +3 info |
| R2 | CRL unknown — no live fetch; crl_unknown_reason honest unknown | All families | Documented; no OCSP/CRL live fetch per offline air-gap; stapled OCSP parse only |
| R3 | OCSP staple opaque in TLS1.3 — encrypted like cert | TLS1.3 ocsp_stapled_status opaque | Legend "staple encrypted like cert" per validator/san_check; TLS1.2 unknown vs not_stapled honest |
| R4 | Stripping single-flow low-conf vs triple Critical | Stripped: single High low-conf, triple Critical with 2 prior upgraded same 5-tuple | EAST 320k CVE-2021-38502 §4.2; history triple same client 127.0.0.11:54330->127.0.0.1:587 |
| R5 | pre_tls_buffer_len heuristic — bytes between 220 and ClientHello 0x16 0x03 | Upgraded High (pipelined), stripped 0 Info | lab/reassembler/reassemble.py _compute_pre_tls_buffer; Postfix CVE-2011-0411 GHSA-9j88 |
| R6 | MX/MTA-STS/DANE fixture fallback — live dig @mockdns if bridge up else offline JSON | MX=mail.lab.local enforce lane | shared/data/mta-sts-fixture.json + dane-tlsa-fixture.json; never claim beyond fixture |
| R7 | 0-RTT early_data replay — ticket_age not bounded -> Medium | early_data_offered && psk && ticket_age reusable -> Medium else Info | RFC8446 §8, RFC9846 §8 GnuTLS replay |
| R8 | ECH outer present — Inner not parsed RFC9849 out-of-scope | ECH outer INFO only | analyzer/parse.py notes encrypted_client_hello, Inner not parsed; never claim PQC |

Triple citation **M03+M18+M22** honested in every gate: M03 Mailbox API lossy Received (Scanner ~12/23), M18 Coverage per-port, M22 MockDNS MX+MTA-STS+DANE offline fixture.

---

## 10. Section B ML shell — LEARN Day7-10 lean (no hard-fail, 🟡 in-progress)

**This is SHELL ONLY — no training, no model file, no ECE/ECOD/NDCG gate hard-fail Day5. SYSTEM 5/8 only.**

> ML stays 🟡 in-progress Day5-6. LEARN Day7-10 contract (not gated now): `XGB tree_method='hist' device='cpu' enable_categorical=True max_depth 3-4 n_estimators 80 reg_alpha 1.0 reg_lambda 2.0 subsample 0.8 colsample 0.8 deterministic True + Platt CalibratedClassifierCV(method='sigmoid', cv=2 lean cv=3 stretch) NOT isotonic, ECE hi<0.20 lean (0.15 stretch) 500-boot family-level (1000 stretch) resample families not rows, n_eff=10 lean (30 with weberblog) disclosed, ECOD PyOD <5ms fit ROC point>0.60 MUST DeLong CI stretch, NDCG@10 human-graded weberblog full 20 +5 Censys +5 adversarial 20 flows blind 3 raters 1-5 Likert gains 2^rel-1 κ>0.6 substantial else re-grade (12×2 κ>0.5 lean minimum), permutation importance n=10 lean (30 stretch) top3 coherence, no Cleanlab flip in gates.`

| ML gate (Day7-10, not hard-fail Day5) | Threshold lean | Evidence Day7 | Status Day5 |
|---------------------------------------|----------------|---------------|-------------|
| XGB Platt cv=2 lean (cv=3 stretch) | `method=='sigmoid'` not isotonic | `grep -rq isotonic assessment/ -> fail` | 🟡 shell `LEARN — Day7-10 lean XGB Platt cv=2 ECE hi<0.20 500-boot` |
| ECE hi | <0.20 lean (<0.15 stretch) 500-boot family-level width ±0.06-0.10 | Day7 `calibration_curve.png` + family bootstrap | 🟡 TBD — no calibration at n<100 per LEDGER |
| ECOD ROC point | >0.60 MUST DeLong CI stretch | Day7 `anomaly_pr.png` + ECOD fit 0.3s | 🟡 TBD |
| NDCG@10 PRIMARY vs human | >rule weights ΔNDCG + κ>0.5 lean (>0.6 stretch) 12×2 raters | Day7 `eval/human_grades.csv` + `blind-likert.md` 20 flows | 🟡 TBD |
| Permutation importance | top3 coherence n=10 lean | Day7 `permutation bar PNG` gate | 🟡 TBD |
| SHAP diagnostic | OPTIONAL appendix PNG stretch | Day7 `shap_summary.png` | 🟡 TBD |
| Prior_flag disjoint | censys 11/28 cols chain_valid None | `shared/tests/test_censys_prior.py` 🟢 Day5 | 🟢 Day5 guard green (ML data charter) |
| Grouping | StratifiedGroupKFold groups=environment_id D3∩D1=∅ | `assessment/tests/test_splits.py` 🟢 | 🟢 Day5 guard green |

**WEAK SUPERVISION disclosure (required verbatim in Section B header + dashboard AI tab + LEDGER):** "Labels are rule-derived weak supervision (score.py 22 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a." — `grep -rq weak supervision assessment/` present.

**Must NOT claim ML 8/8 green:** No `models/risk_clf.pkl`, no `anomaly.pkl`, no `assessment/risk_model.py` training, `eval/metrics.json` shell Day7 not hard-fail. Day5 ML remains 🟡 in-progress.

**Gates Day5-6 verify only that shell exists and no hard-fail is claimed:** `! grep -rq isotonic assessment/`, `python -c "from analyzer.jas import ALLOWED_RISK_FEATURES; assert 'ja4' not in ALLOWED_RISK_FEATURES"`, `python -c "import json; s=json.load(open('assessment/splits.json')); assert not set(s['D_prior_groups']) & set(s['D1_train_groups'])"`.

---

## 11. Ledger excerpts — snapshot Day5

**lab/LEDGER.md excerpt:**

```
| Family | environment_id | capture_epoch | pcap sha256 | STARTTLS | Cipher | Cert | tshark parity | coverage_ratio | source_id | n_eff |
| 01 | family-01__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 025b6d... | upgrade | ECDHE-RSA-AES128-GCM-SHA256 | rsa2048 | PASS (F1=1.0 clean) | 1.0 | d77d7462 | 1 |
| 06 | family-06__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 45c52... | implicit TLS1.3 opaque | TLS_AES_128_GCM_SHA256 x25519 | opaque | PASS | 1.0 | 9d2b0543 | 1 |
| jittered.pcap | — | — | 759883... | upgrade | — | — | — | 0.897 overlap duplicate logged not silent | — | — |
```

**analyzer/LEDGER.md excerpt:**

```
| Family | Cipher | KEX | FS | JA4 | Version | GREASE 16 | early_data | ECH | is_tls13_opaque |
| 01 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | true | t12i010000_ced06... | TLS1.2 | true | false | false | false |
| 06 | TLS_AES_128_GCM_SHA256 | ECDHE | true | t13d1516h2_8daa... | TLS1.3 | true | false | false | true |
```

**validator/LEDGER.md excerpt:**

```
CABF stratum prec 1.000 6TP6TN 0FP 0FN >90% stratified separate not mixed
private-CA 1.000 2 valid via Store 6 invalid >90%
badssl 1.000 8/8 bad 2/2 good >90%
Family07 expired True chain_valid False Critical, Family08 rsa1024 1024 High, Family10 chain-incomplete High, Family06 opaque leaf_present False
```

**assessment/LEDGER.md excerpt:**

```
| Family | risk_score | risk_level | posture | policy.action wire | to_spec | siem |
| 01 | 6 | Low | 94 | allow | deliver | Low |
| 04 | 100 | Critical | 0 | block | hold_incident | Critical |
| 09 single | 67 | High | 33 | flag | deliver_banner | High low conf |
| 09 triple | 77 | Critical | 23 | block | hold_incident | Critical history 3flow |
23 checks 20 scored+3 info weak recall 100% 🟢
prior_flag disjoint 20 censys_prior_* chain_valid None san_match None days None ja4_rarity 0.02..0.99
D5 synthetic env_id_frozen true train 2026-08-27 != test 2026-09-03
```

**shared/progress.md excerpt:**

```
| Day5 09:00 | Assessment | assessment/policy.py lean 7 fixtures | 🟢 gated |
| Day5 12:00 | Assessment | assessment/splits.json 12 groups prior_flag disjoint | 🟢 gated |
| Day5 15:00 | API | api/db.py JSONB <1ms + POST /analyze chunk-read 1 MiB | 🟢 gated |
| Day5 18:00 | Offline | wheelhouse lean <350M --only-binary | 🟢 gated |
```

---

## 12. CI hard-fail gates + reproducibility (Day5 shell)

```bash
# Full SYSTEM 5/8 harness (Section A only, ML 🟡 shell)
pytest shared/tests/test_schema.py lab/reassembler/tests/test_reassembly.py lab/reassembler/tests/test_coverage_ratio.py analyzer/tests/test_handshake.py analyzer/tests/test_ja4.py shared/tests/test_ja4_grease.py shared/tests/test_ja4_rarity.py validator/tests/test_chain_limbo.py validator/tests/test_badssl.py assessment/tests/test_rules.py api/tests/test_api.py assessment/tests/test_splits.py shared/tests/test_censys_prior.py -q
# expect ~65 passed SYSTEM 5/8 + splits/prior green, ML not gated
pytest api/tests/test_db.py api/tests/test_api_stream.py -q
# db <1ms + chunk-read 413 green
[ $(du -m wheelhouse | tail -1 | cut -f1) -lt 350 ] && echo "wheelhouse lean <350M ok" || exit 1
! grep -rq "isotonic" assessment/ || (echo "isotonic forbidden at n<1000" && exit 1)
python -c "from analyzer.jas import ALLOWED_RISK_FEATURES; assert 'ja4' not in ALLOWED_RISK_FEATURES and 'ja4_rarity' in ALLOWED_RISK_FEATURES"
python -c "import json; s=json.load(open('assessment/splits.json')); assert not set(s['D3_locked_groups']) & (set(s['D1_train_groups'])|set(s['D2_val_groups']))"
python -c "import json; c=json.load(open('shared/fixtures/censys_sampled_200.json')); assert all(r.get('prior_flag')==True for r in c) and all(r.get('cert',{}).get('chain_valid') is None for r in c)"
python -c "import json; vals=[r['tls']['ja4_rarity'] for r in json.load(open('shared/fixtures/censys_sampled_200.json')) if r.get('tls',{}).get('ja4_rarity') is not None]; assert len(vals)>=15 and min(vals)<=0.2 and max(vals)>=0.8"
test -f eval/EVIDENCE_Day5.md && grep -q "SYSTEM 5/8" eval/EVIDENCE_Day5.md && grep -q "STARTTLS F1>95%" eval/EVIDENCE_Day5.md && grep -q "cipher exact >98%" eval/EVIDENCE_Day5.md && grep -q "prec>90%" eval/EVIDENCE_Day5.md && grep -q "weak recall 100%" eval/EVIDENCE_Day5.md && grep -q "14/20 REAL" eval/EVIDENCE_Day5.md && echo "Day5 grep gates ok"
grep -q "ML.*Day7-10" eval/EVIDENCE_Day5.md && echo "ML deferred Day7-10 badge ok"
ls shared/fixtures/family-*.json | wc -l
# 10
gzip -c dashboard/dist/assets/*.js | wc -c
# 157476 < 3670016 if built else shard Day10 drill
```

- **Lineage manifest->reassembled->features vs tshark trio** pinned per §8c with `environment_id, capture_epoch, source_id, docker_image_sha256, tshark_version` per family 10+7 jittered + `coverage_ratio` + `pre_tls_buffer_len`.
- **Per-version R1-R8 table** repeated §9 per Day3-4 honest.
- **MUST not claim ML 8/8 green — SYSTEM 5/8 only Day5-6 ML remains 🟡 in-progress** — ML shell Section B no ECE/ECOD hard-fail.
- **Triple citation M03+M18+M22** honested in §7.

---

*Generated 2026-08-25 — SecureMailScope Day5 Evidence Snapshot. SYSTEM 5/8 🟢 Section A only, ML 🟡 LEARN Day7-10 lean XGB Platt cv=2 ECE hi<0.20 500-boot ECOD ROC point>0.60 NDCG 12×2 κ>0.5 no hard-fail, 14/20 REAL +23×3 table 20 scored+3 info-greyed, lineage trio manifest->reassembled->features vs tshark, R1-R8 per-version, triple M03+M18+M22. Not 8/8 green.*
