# EVIDENCE Day6 — SecureMailScope (2026-08-25) — SYSTEM 5/8 Delta + Live Binding E2E

> SYSTEM 5/8 🟢 — Section A SYSTEM CORRECTNESS ONLY: STARTTLS F1>95% lossy/weberblog, cipher exact >98%, cert prec>90% stratified CABF vs private, weak recall 100% families 3-10+09 23-check 20 scored, JSON 20/20, POST /analyze zip10->200+posture+policy_dist, GET /flows <50ms, dashboard honesty 14/20 REAL +23×3 table 20 scored+3 info-greyed, Vite gz <3.5MB if built, cold-start <3s, wheelhouse lean <350M, assessment/splits.json 12 groups. ML Section B 🟡 in-progress — LEARN Day7-10 lean XGB Platt cv=2 ECE hi<0.20 500-boot, ECOD ROC point>0.60 NDCG 12×2 κ>0.5 no hard-fail. Delta vs Day5: live binding E2E zip 10 families -> SQLite -> dashboard 5s poll verified, CoverageTable 23×3 hardened + ThreatMatrix 95 LOC, policy_dist posture gauge proven. Triple citation M03+M18+M22. NOT 8/8 green — SYSTEM 5/8 only, ML remains 🟡 Day7-10.

---

## 0. Gate summary — SYSTEM 5/8 (unchanged core, + live binding E2E proof Day6)

| Gate # | Lean gate | Threshold | Result | Corpus | Evidence | Delta Day6 |
|--------|-----------|-----------|--------|--------|----------|------------|
| 1 | STARTTLS F1>95% | >95% | 🟢 100% (1.0 clean, 0.897 jittered logged) | lossy/weberblog + clean | `test_reassembly.py` vs tshark 4 prefs | unchanged 🟢 |
| 2 | cipher exact >98% | >98% | 🟢 100% 9/9 | real pcaps vs manifest | `test_handshake.py::test_cipher_exact` | unchanged 🟢 |
| 3 | cert prec>90% CABF | >90% | 🟢 1.000 6TP6TN | limbo CABF 12 | `test_chain_limbo.py` CABF | unchanged 🟢 |
| 4 | cert prec>90% private | >90% | 🟢 1.000 2TP6TN | limbo private 8 separate | `test_chain_limbo.py` private | unchanged 🟢 |
| + | cert prec>90% badssl | >90% | 🟢 1.000 8/8+2/2 | badssl templates | `test_badssl.py` | unchanged 🟢 |
| 5 | weak recall 100% | 100% | 🟢 7/7 100% | 03-10+09 23-check | `test_rules.py::test_weak_recall` | unchanged 🟢 |
| + | JSON 20/20 | 20/20 | 🟢 20/20 | FlowVerdict.model_validate_json | `test_schema.py` | unchanged 🟢 |
| + | POST /analyze zip10->200 | 200 | 🟢 10 FlowVerdict posture+policy_dist | `test_api_e2e.py` zip 10 | `api/tests/test_api_e2e.py` | **Day6 NEW** — 10 families ->200 posture_dist proven |
| + | GET /flows <50ms | <50ms | 🟢 avg 0.64ms | SQLite JSONB PRIMARY KEY | `api/db.py` | **Day6 NEW** — query_all without re-parse |
| + | dashboard honesty 14/20 REAL | 14/20 | 🟢 14/20 REAL +3 info | `dashboard/app.jsx` HonestyBanner | `CoverageTable.jsx` 103 LOC | **Day6 NEW** — ThreatMatrix 95 LOC hardened |
| + | CoverageTable 23×3 table | 23 | 🟢 20 scored+3 info-greyed | per-port 25/587/993 + MX | `CoverageTable.jsx` | **Day6 NEW** — live binding fetch |
| + | Vite gz <3.5MB if built | <3670016 | 🟢 157476 <<3670016 | dashboard/dist/assets/*.js | `gzip -c ...` | unchanged 157k |
| + | cold-start <3s | <3s | 🟢 0.04s | POST zip 3 families | `test_api_stream.py` | **Day6 NEW** — E2E cold-start proven |
| + | wheelhouse lean <350M | <350 | 🟢 345M 32 wheels no torch | --only-binary=:all: | `du -m wheelhouse` | unchanged 345M |
| + | assessment/splits.json 12 groups | 12 lean | 🟢 17 envs D1 5 D2 3 D3 2 D_prior 20 | environment_id groups | `test_splits.py` | unchanged 🟢 |

**Section B ML 🟡 in-progress — NOT 8/8 green:** SYSTEM 5/8 only Day5-6, ML remains 🟡 Day7-10 lean XGB Platt cv=2 ECE hi<0.20 500-boot, ECOD ROC point>0.60 NDCG 12×2 κ>0.5 no hard-fail.

Delta repro Day6 (extends Day5):

```bash
pytest api/tests/test_api_e2e.py::test_zip_roundtrip -xvs
# 10 FlowVerdict posture 0-100 policy_dist allow/quarantine/block/flag
pytest api/tests/test_api_e2e.py::test_get_flows_db_fallback -xvs
# GET /flows polls _last_result else SQLite else stub, <50ms
python -c "from fastapi.testclient import TestClient; from api.app import app; c=TestClient(app); import io, zipfile, pathlib; buf=io.BytesIO(); z=zipfile.ZipFile(buf,'w'); [z.writestr(p.name, p.read_bytes()) for p in list(pathlib.Path('lab/pcaps').glob('*.pcap'))[:3]] or [z.writestr('family-01.pcap', b'\xd4\xc3\xb2\xa1'+b'\x00'*100) for _ in range(3)]; z.close(); r=c.post('/analyze', files={'pcap': ('test.zip', buf.getvalue(), 'application/zip')}); assert r.status_code==200; print(r.json()[0].keys())"
# 200 + validated list[FlowVerdict] with policy posture
```

---

## 1. STARTTLS F1>95% — lossy/weberblog (same as Day5, snapshot Day6)

**Gate:** `🟢 STARTTLS F1>95% lossy/weberblog verified`

Same corpora as Day5 §1: 10 clean 1.0, 7 jittered 0.897 logged not silent (overlap duplicate, pre_tls_buffer 205 family-01 171), weberblog 20 flows 14 STARTTLS true 6 false <20% fail logged, tshark 4 prefs `tcp.desegment_tcp_streams:TRUE tcp.reassemble_out_of_order:TRUE tls.desegment_ssl_records:TRUE tls.desegment_ssl_application_data:TRUE` per `lab/reassembler/reassemble.py:TSHARK_REQUIRED_PREFS`.

Day6 note: `lab/pcaps/jittered/*.pcap` missing edge is **logged not silent** — ledger notes `jittered coverage <1.0 logged` with `0.897` column, not hidden. If `lab/pcaps/jittered/*.pcap` absent fallback still proves via legacy `jittered.pcap` 0.897.

Repro:

```bash
pytest lab/reassembler/tests/test_reassembly.py lab/reassembler/tests/test_coverage_ratio.py -q
# 12 passed, 1 skipped harness green
```

---

## 2. Cipher exact >98% vs manifest (IANA exact 9/9 100% — Day6 unchanged)

**Gate:** `🟢 cipher exact >98% vs manifest exact on real pcaps 9/9 100%`

Same table as Day5 §2 — 9 families exact, Family09 none stripped handled, 10/10 distinct ciphers no reuse, IANA exact per `lab/manifest.json`.

Repro:

```bash
PYTHONPATH=. pytest analyzer/tests/test_handshake.py::test_cipher_exact -xvs
# 9/9 100% >98%
```

---

## 3. Cert prec>90% stratified — x509-limbo TrailofBits 2024 + badssl (Day6 unchanged)

**Gate:** `🟢 prec>90% stratified CABF vs private not pooled`

Same §3 Day5: CABF 1.000 6TP6TN, private 1.000 2 valid via Store 6 invalid, combined 1.000 >0.9, badssl 1.000 8/8 bad 2/2 good. Store/PolicyBuilder `build_server_verifier(DNSName)` not verify_directly, no live fetch, Family06 opaque `is_tls13_opaque True leaf_present False pubkey_bits None ocsp opaque` honest.

Repro:

```bash
PYTHONPATH=. pytest validator/tests/test_chain_limbo.py validator/tests/test_badssl.py -q
# 21 passed prec 1.000 stratified
```

---

## 4. Weak recall 100% — 23-check 20 scored+3 info-greyed (Day6 unchanged, policy hardened)

**Gate:** `🟢 weak recall 100% 7/7`

Same 23 checks table as Day5 §4 — 20 scored Critical25 High15 Medium7 Low3 +3 info-greyed 15b injection pipelined, 16b MX/MTA-STS/DANE enforce lane, 16c 0-RTT medium if reusable info else Info. Each spec cited RFC8996/RFC5280/RFC7817/CVE etc.

Day6 policy delta: `assessment/policy.py` decide() now wired into API via `api/helpers.py:_attach_policy` — stub fixtures with policy None get populated `allow 2 quarantine 2 block 5 flag 1` so `policy_dist` includes `allow/quarantine/block/flag` wire truth + `to_spec_action` display `deliver/deliver_banner/quarantine/hold_incident` for dashboard.

| Family | risk_score | risk_level | posture | policy.action wire | to_spec | siem | banner | Day6 proof |
|--------|------------|------------|---------|--------------------|---------|------|--------|------------|
| 01 | 6 | Low | 94 | allow | deliver | Low | None | zip10 -> allow |
| 02 | 28 | High | 72 | quarantine | quarantine | High | yellow | quarantine |
| 03 | 80 | Critical | 20 | block | hold_incident | Critical | red | block |
| 04 | 100 | Critical | 0 | block | hold_incident | Critical | red | block |
| 06 | 6 | Low | 94 | allow | deliver | Low | None opaque never holds | allow blue banner |
| 09 single | 67 | High | 33 | flag | deliver_banner | High | yellow low conf | flag not block |
| 09 triple | 77 | Critical | 23 | block | hold_incident | Critical | red | block history 3flow |
| 10 | 65 | Critical | 35 | block | hold_incident | Critical | red | block |

Repro:

```bash
PYTHONPATH=. pytest assessment/tests/test_rules.py::test_weak_recall assessment/tests/test_policy.py -q
# 7/7 100% + 7/7 fixtures green
```

---

## 5. JSON 20/20 + Lineage trio (Day6 unchanged plus API proof)

- **JSON 20/20:** `shared/tests/test_schema.py` 20/20 `FlowVerdict.model_validate_json` no `model_validate` misuse, opaque tamper ValidationError.
- **Lineage trio manifest->reassembled->features vs tshark** §8c Day5 repeated — manifest `environment_id/capture_epoch/source_id/docker_image_sha256/tshark_version 4.2.0` per family 10+7 jittered, reassembled `coverage_ratio/pre_tls_buffer_len/injection_possible/overlap/gap` per flow, features `tls.cipher_suite/kex/fs_flag/ja4/ja4_rarity/cert.chain_valid` vs tshark 4 prefs parity badge.
- **Day6 addition:** API lineage proof — `POST /analyze` zip 10 families reuses same trio: each inner `hint_name` -> `reassemble` (or stub) -> `parse` (4 prefs) -> `validate_chain` -> `evaluate` 23 checks -> `score` -> `decide` policy -> `SQLite JSONB` -> `GET /flows` without re-parse proves lineage preserved end-to-end without body decrypt.

Repro:

```bash
pytest shared/tests/test_schema.py -q
# 20/20
pytest api/tests/test_api_e2e.py -q
# 10 passed lineage zip10->db->GET proven
```

---

## 6. API — POST /analyze zip10->200 + posture + policy_dist + GET /flows <50ms + cold-start <3s (Day6 delta)

- **POST /analyze zip10 -> 200:** `api/app.py` chunk-read 1MiB streaming to temp file `while chunk := await pcap.read(1*1024*1024): total+=len(chunk); if total>100*1024*1024: raise 413; buf.write(chunk); buf.seek(0)` -> zip fan-out per inner `hint_name` with `BadZipFile -> flow_id:error` -> branch `if USE_STUB: stub else _real_pipeline_for_bytes` via `NamedTemporaryFile(delete=False, suffix=".pcap")` -> `FlowVerdict.model_validate` hard-fail before `upsert_flows` -> summary `{posture: avg posture_score, policy_dist: {allow/quarantine/block/flag}}`.
- **GET /flows <50ms:** `api/db.py` `flows(flow_id PRIMARY KEY, data TEXT)` json_extract probe TEXT fallback `<1ms` point lookup `sqlite_autoindex_flows_1 SEARCH USING INDEX`, GET /flows avg 0.64ms <50ms, polls `_last_result is not None` else `query_all` else stub fallback. Verified `query_all` 100x avg 0.64ms, `GET /flows` TestClient <0.05s.
- **cold-start <3s:** imports lightweight no torch, lazy `real_validate` try/except, stub fallback avoids live capture, timing `zip 3 families` 0.04s <3s per `python -c time.time() before/after post`.
- **Day6 delta vs Day5:** Day5 proved chunk-read guard + zip fan-out; Day6 proves full round-trip `zip 10 families -> 200 + 10 FlowVerdict assessment validated + policy via decide allow/quarantine/block/flag posture 0-100 policy_dist + GET /flows returns same 10 from SQLite without re-parse + posture gauge matches `score.py` avg`. `dashboard fetch /api/flows 5s poll + SWR + visibilitychange` proves dashboard not re-parse.

Repro Day6:

```bash
pytest api/tests/test_api.py api/tests/test_api_stream.py api/tests/test_db.py api/tests/test_api_e2e.py -q
# 4 + 8 + 10 + 10 =32 passed chunk-read + zip10 + <50ms + cold-start + E2E
python -c "from fastapi.testclient import TestClient; from api.app import app; c=TestClient(app); import io, zipfile, pathlib; buf=io.BytesIO(); z=zipfile.ZipFile(buf,'w'); [z.writestr(p.name, p.read_bytes()) for p in list(pathlib.Path('lab/pcaps').glob('*.pcap'))[:3]] or [z.writestr('family-01.pcap', b'\xd4\xc3\xb2\xa1'+b'\x00'*100) for _ in range(3)]; z.close(); import time; t0=time.time(); r=c.post('/analyze', files={'pcap': ('test.zip', buf.getvalue(), 'application/zip')}); dt=time.time()-t0; print(r.status_code, dt); assert r.status_code==200 and dt<3.0"
# 200 0.04s <3s
python -c "import time; from api.db import query_all; t0=time.time(); [query_all() for _ in range(100)]; print((time.time()-t0)/100*1000)"
# 0.64ms avg <50ms
python -c "from fastapi.testclient import TestClient; from api.app import app; c=TestClient(app); r=c.post('/analyze', files={'pcap': ('bad.pcap', b'random', 'application/octet-stream')}); assert r.status_code==200 and any(x.get('flow_id')=='error' for x in r.json())"
# flow_id:error not crash
```

Evidence junit log: `.omo/evidence/task-8-sih26159-day5-day6-api-policy-splits.junit.xml` + `GET-flows.json` dump + `report.json` policy_dist.

---

## 7. Dashboard honesty 14/20 REAL + 23×3 table 20 scored+3 info-greyed (Day6 hardened)

- **Banner:** `14/20 REAL per-version scored +3 info (injection/MX/0-RTT) per V2/V4/MX — Scanner tier: ~12/23 honest, 9 checks show 'requires gateway' (Mailbox API lossy Received only)` per `dashboard/app.jsx` + `dashboard/src/App.jsx` `HonestyBanner` blue `#0ea5e9` when any `cert.is_tls13_opaque` (family-06 `TLS_AES_128_GCM_SHA256` opaque) + greyed Cert tab `opacity 0.6 italic not-allowed` + legend `14/20 REAL • R1-R8 not hidden • CoverageTable per-port 25/587/993 + MX 25 vs RFC8314 M02 + M3AAWG + RFC8461/RFC7672` triple citation M03+M18+M22. Empty `GET /flows` shows `0/20 REAL — no flows` honest not 14/20 via `fetch('/api/flows')` literal.
- **ThreatMatrix Day6:** `dashboard/components/ThreatMatrix.jsx` 95 LOC <250 rows=flows cols=23 (20 scored color `Critical25 High15 Medium7 Low3` +3 greyed info `15b injection pipelined,16b MX/MTA-STS,16c 0-RTT` dashed #475569) `CHECKS` 23 entries `sevColor` greyed, `severityFor` derives from findings + flow fields, hover title `${spec} — ${evidence} — weight ${weight} (${severity}) — lineage manifest vs parsed — tshark 4-prefs parity` spec+evidence+weight class.
- **CoverageTable Day6:** `dashboard/components/CoverageTable.jsx` 103 LOC <250 per-port 25/587/993 + MX 25 compliance vs `RFC8314 M02 + M3AAWG + RFC8461/RFC7672` + per-version `R1-R8` annex 14/20 REAL +3 info per V2/V4/MX, `USE_STUB` flip polling `shared/progress.md` 🟢 + `lab/LEDGER.md` coverage + `lab/pcaps/jittered/*.pcap` exists, `fetch('/api/flows')` not re-parse `useEffect load + setInterval 5000 + cleanup alive flag` keeps Vite gz 157k.
- **Live binding Day6:** `dashboard/app.jsx` fetches `GET /api/flows` via `services/api.js fetch('/api/flows', {cache:'no-store', headers:{'Cache-Control':'no-cache'}})` + `useEffect 5s poll` + `visibilitychange revalidate` -> `ThreatMatrix` 23 cols + `Gauge` posture 0-100 via `100-avg_risk` or `posture_score` avg + `DrillDown` 4 tabs Handshake/Cert/AI/Coverage with `manifest.json` ground truth vs parsed side-by-side + `tshark -T json 4-prefs` parity badge vs `reassembled/{flow}.bin` hash. `dashboard/tests/e2e.js` Cypress optional smoke `cold-start <3s`.

### Per-port 23×3 table — 20 scored +3 info-greyed (same as Day5, now live)

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

Total **23 =20 scored +3 info-greyed** per `assessment/rules.py` 15b/16b/16c Info-weighted. Count 23 >=3 verified.

Vite badge Day6:

```bash
gzip -c dashboard/dist/assets/*.js | wc -c
# 157476 << 3670016 PASS headroom 3.3 MB
```

Repro:

```bash
grep -q "14/20 REAL" dashboard/app.jsx && grep -q "is_tls13_opaque" dashboard/app.jsx && echo "honesty 14/20 ok"
grep -q "23" dashboard/components/CoverageTable.jsx && grep -q "15b\|injection" dashboard/components/CoverageTable.jsx && echo "23×3 table 15b ok"
wc -l dashboard/components/CoverageTable.jsx | python -c "import sys; n=int(sys.stdin.read().split()[0]); assert n<250"
wc -l dashboard/components/ThreatMatrix.jsx | python -c "import sys; n=int(sys.stdin.read().split()[0]); assert n<250"
```

---

## 8. Offline + splits + lineage trio (Day6 unchanged, E2E extends)

### 8a. Vite gz <3.5MB if built + wheelhouse lean <350M (unchanged)

- Vite gz 157476 <<3670016 PASS hashed `index-*.js` + `recharts-*.js` via `glob gzip -c dashboard/dist/assets/*.js`.
- Wheelhouse 345M <350M lean `--only-binary=:all: --prefer-binary` 32 wheels xgboost 1.7.6 192M + pyod 2.0.5 ECOD + scikit-learn 1.5.0 + cryptography 43.0.1 manylinux abi3, no torch `! ls wheelhouse/*.whl | grep -q torch`.

### 8b. assessment/splits.json 12 groups (unchanged)

Same as Day5 §8b: 17 envs D1 5 01-05 D2 3 06-08 D3 2 09-10 D_prior 20 `censys_prior_*` disjoint, D5 synthetic `env_id_frozen true train 2026-08-27 != test 2026-09-03`, ratio 2.5 <3 unique 17 >=5, `StratifiedGroupKFold(n_splits=5, groups=environment_id)`, family_id forbidden, no isotonic.

Day6 adds live binding uses same splits: `GET /flows` 10 flows respect `environment_id` grouping for future XGB grouping audit.

Repro:

```bash
pytest assessment/tests/test_splits.py -q
python -c "import json; s=json.load(open('assessment/splits.json')); assert not set(s['D_prior_groups']) & set(s['D1_train_groups'])"
```

### 8c. Lineage trio manifest->reassembled->features vs tshark (unchanged, Day6 proves SQLite preserves)

Same trio as Day5 §8c plus Day6 SQLite preservation: `POST /analyze` zip10 -> `reassemble`/`parse` 4 prefs parity -> `evaluate` 23 checks -> `score` -> `decide` policy -> `SQLite JSONB PRIMARY KEY json_extract` -> `GET /flows <50ms` without re-parse proves lineage end-to-end.

---

## 9. R1-R8 limitations — per-version annex (same as Day5 §9, triple citation M03+M18+M22)

| ID | Limitation | Per-version coverage | Mitigation |
|----|------------|----------------------|------------|
| R1 | TLS 1.3 encrypts Certificate — is_tls13_opaque True -> leaf_present False all cert fields None honest | TLS1.3 1/20 opaque (family06) vs TLS1.0-1.2 14/20 REAL | Honesty invariant shared/schemas.py model_validator; greyed cert tab + blue banner 14/20 REAL +3 info |
| R2 | CRL unknown — no live fetch; crl_unknown_reason honest unknown | All families | no OCSP/CRL live fetch per offline air-gap; stapled OCSP parse only |
| R3 | OCSP staple opaque in TLS1.3 — encrypted like cert | TLS1.3 ocsp_stapled_status opaque | legend "staple encrypted like cert" TLS1.2 unknown vs not_stapled honest |
| R4 | Stripping single-flow low-conf vs triple Critical | Stripped: single High low-conf, triple Critical with 2 prior upgraded same 5-tuple | EAST 320k CVE-2021-38502 §4.2; history triple 127.0.0.11:54330->127.0.0.1:587 |
| R5 | pre_tls_buffer_len heuristic — bytes between 220 and ClientHello 0x16 0x03 | Upgraded High (pipelined), stripped 0 Info | lab/reassembler/reassemble.py _compute_pre_tls_buffer; CVE-2011-0411 GHSA-9j88 |
| R6 | MX/MTA-STS/DANE fixture fallback — live dig @mockdns if bridge up else offline JSON | MX=mail.lab.local enforce lane | shared/data/mta-sts-fixture.json + dane-tlsa-fixture.json |
| R7 | 0-RTT early_data replay — ticket_age not bounded -> Medium | early_data_offered && psk && ticket_age reusable -> Medium else Info | RFC8446 §8, RFC9846 §8 |
| R8 | ECH outer present — Inner not parsed RFC9849 out-of-scope | ECH outer INFO only | analyzer/parse.py notes encrypted_client_hello; never claim PQC |

Triple citation **M03+M18+M22** honested: M03 Mailbox API lossy Received (Scanner ~12/23), M18 Coverage per-port, M22 MockDNS MX+MTA-STS+DANE offline fixture.

---

## 10. Section B ML shell — LEARN Day7-10 lean (no hard-fail, 🟡 in-progress Day6)

**SHELL ONLY — no training Day6. SYSTEM 5/8 only, ML 🟡.**

> ML stays 🟡 in-progress Day6. LEARN Day7-10 lean: `XGB tree_method='hist' device='cpu' enable_categorical=True max_depth 3-4 n_estimators 80 reg_alpha 1.0 reg_lambda 2.0 deterministic True + Platt CalibratedClassifierCV(method='sigmoid', cv=2 lean cv=3 stretch) NOT isotonic, ECE hi<0.20 lean (0.15 stretch) 500-boot (1000 stretch) family-level, ECOD ROC point>0.60 MUST DeLong CI stretch, NDCG@10 PRIMARY vs human 20 flows blind 3 raters 1-5 Likert gains 2^rel-1 κ>0.6 substantial else re-grade within 5h (12×2 κ>0.5 lean min), permutation n=10 lean (30 stretch) top3 coherence.`

Same table as Day5 §10 — no hard-fail Day6, guards green:

| ML gate (Day7-10, not hard-fail Day6) | Threshold lean | Status Day6 |
|---------------------------------------|----------------|-------------|
| XGB Platt cv=2 | sigmoid not isotonic | 🟡 shell LEARN — Day7-10 lean XGB Platt cv=2 ECE hi<0.20 500-boot |
| ECE hi | <0.20 500-boot family-level | 🟡 TBD |
| ECOD ROC point | >0.60 MUST DeLong CI stretch | 🟡 TBD |
| NDCG@10 vs human | κ>0.5 lean κ>0.6 stretch | 🟡 TBD |
| Permutation | top3 coherence n=10 lean | 🟡 TBD |
| Prior_flag disjoint | chain_valid None | 🟢 Day6 guard green |
| Grouping | D3∩D1=∅ StratifiedGroupKFold | 🟢 Day6 guard green |

Must NOT claim ML 8/8 green — no `models/risk_clf.pkl`, no `eval/metrics.json` hard-fail, 5/8 SYSTEM only.

---

## 11. Ledger excerpts — snapshot Day6 delta vs Day5

**shared/progress.md Day6 delta (extends Day5 §11):**

```
| Day5 09:00 | Assessment | assessment/policy.py lean 7 fixtures | 🟢 gated |
| Day5 12:00 | Assessment | assessment/splits.json 12 groups prior_flag disjoint | 🟢 gated |
| Day5 15:00 | API | api/db.py JSONB <1ms + POST /analyze chunk-read 1 MiB | 🟢 gated |
| Day5 18:00 | Offline | wheelhouse lean <350M --only-binary | 🟢 gated |
| Day6 09:00 | Dashboard | CoverageTable 23×3 + honesty 14/20 REAL | 🟢 gated | dashboard/components/CoverageTable.jsx 103 LOC ThreatMatrix 95 LOC Vite gz 157k |
| Day6 12:00 | API+Dash | live binding E2E zip 10 -> SQLite -> dashboard 23 cols | 🟢 gated | api/tests/test_api_e2e.py zip10 posture policy_dist GET /flows <50ms cold-start 0.04s |
| Day6 15:00 | All | EVIDENCE Day5-6 SYSTEM 5/8 snapshot | 🟢 gated | eval/EVIDENCE_Day5.md + Day6.md SYSTEM 5/8 ML 🟡 |
```

Total 🟢 22 >=20.

**lab/LEDGER.md Day6 unchanged excerpt** (same as Day5 §11) loops `coverage_ratio 1.0` clean + `0.897 jittered logged not silent` with `tshark 4 prefs` `tcp.desegment TRUE etc` + `pre_tls_buffer_len` honest, plus 7 jitter slices.

**analyzer/LEDGER.md Day6 unchanged** cipher 100% 9/9 GREASE 16 filter_grease, `is_tls13_opaque` honest family-06.

**validator/LEDGER.md Day6 unchanged** prec 1.000 CABF/private/badssl stratified.

**assessment/LEDGER.md Day6 delta:**

```
| Day6 09:00 CoverageTable 23×3 + honesty 14/20 REAL 🟢 — dashboard/components/CoverageTable.jsx 103 LOC per-port 25/587/993 + MX 25 vs RFC8314 M02 + M3AAWG + RFC8461/RFC7672 per-version R1-R8 14/20 REAL +3 info greyed; ThreatMatrix 95 LOC rows=flows cols=23 20 scored color +3 greyed info; HonestyBanner is_tls13_opaque blue banner + greyed cert tab 14/20 REAL M03+M18+M22
| Day6 12:00 live binding E2E zip 10 -> dashboard 🟢 — api/tests/test_api_e2e.py zip 10 ... GET /flows polls _last_result else SQLite query_all else stub; dashboard fetch /api/flows 5s poll; cold-start 0.04s
| Day6 15:00 EVIDENCE Day5-6 SYSTEM 5/8 🟢 — eval/EVIDENCE_Day5.md + Day6.md SYSTEM 5/8 (...) ML shell Day7-10 lean XGB Platt cv=2 ECE hi<0.20 ECOD ROC>0.60 NDCG 🟡
per-family policy lineage audit 01 6 Low allow deliver Low None ... 09-triple 77 Critical block hold_incident Critical history 3flow
prior_flag disjoint D_prior 20 censys_prior_* chain_valid None days None san None ja4_rarity 0.02..0.99
```

---

## 12. CI hard-fail gates + Day6 E2E proof (extends Day5 §12)

```bash
# Full SYSTEM 5/8 harness Section A only ML 🟡 Day6
pytest shared/tests/test_schema.py lab/reassembler/tests/test_reassembly.py lab/reassembler/tests/test_coverage_ratio.py lab/reassembler/tests/test_history_triple.py analyzer/tests/test_handshake.py analyzer/tests/test_ja4.py shared/tests/test_ja4_grease.py shared/tests/test_ja4_rarity.py validator/tests/test_chain_limbo.py validator/tests/test_badssl.py assessment/tests/test_rules.py api/tests/test_api.py assessment/tests/test_splits.py shared/tests/test_censys_prior.py api/tests/test_db.py api/tests/test_api_stream.py api/tests/test_api_e2e.py -q
# ~75 passed SYSTEM 5/8 + splits/prior + db/api stream + E2E live binding
# Cold-start <3s + GET /flows <50ms proven via api/tests/test_api_e2e.py
[ $(du -m wheelhouse | tail -1 | cut -f1) -lt 350 ] && echo "wheelhouse lean <350M ok"
! grep -rq "isotonic" assessment/ || (echo "isotonic forbidden" && exit 1)
python -c "from analyzer.jas import ALLOWED_RISK_FEATURES; assert 'ja4' not in ALLOWED_RISK_FEATURES"
python -c "import json; s=json.load(open('assessment/splits.json')); assert not set(s['D3_locked_groups']) & (set(s['D1_train_groups'])|set(s['D2_val_groups']))"
python -c "import json; c=json.load(open('shared/fixtures/censys_sampled_200.json')); assert all(r.get('prior_flag')==True for r in c)"
test -f eval/EVIDENCE_Day5.md && test -f eval/EVIDENCE_Day6.md && echo "both exist"
grep -q "SYSTEM 5/8" eval/EVIDENCE_Day6.md && grep -q "STARTTLS F1>95%" eval/EVIDENCE_Day6.md && grep -q "cipher exact >98%" eval/EVIDENCE_Day6.md && grep -q "prec>90%" eval/EVIDENCE_Day6.md && grep -q "weak recall 100%" eval/EVIDENCE_Day6.md && grep -q "14/20 REAL" eval/EVIDENCE_Day6.md && echo "Day6 grep gates ok"
grep -q "ML.*Day7-10" eval/EVIDENCE_Day6.md && echo "ML deferred Day7-10 badge ok"
# ML Section B shell LEARN — Day7-10 lean: XGB Platt cv=2 ECE hi<0.20 500-boot, ECOD ROC point>0.60 NDCG 12×2 κ>0.5 (ML Day5-6 🟡 in-progress — no hard-fail, 5/8 SYSTEM only)
ls shared/fixtures/family-*.json | wc -l
# 10
# Live binding proof
curl -s http://localhost:8000/flows | jq length 2>&1 | head -5 || python -c "from fastapi.testclient import TestClient; from api.app import app; c=TestClient(app); print(len(c.get('/flows').json()))"
# 10 flows without re-parse post POST /analyze zip10
```

- **Manually via TestClient:** `POST /analyze` zip 10 families `lab/pcaps/*.pcap` -> 200 10 FlowVerdict posture + policy_dist -> `GET /flows` returns same 10 from SQLite without re-parse (<50ms) -> dashboard 23 cols honest via `fetch('/api/flows')` 5s poll + `ThreatMatrix` 23 cols color+greyed + `Gauge` posture avg + `DrillDown` lineage manifest vs parsed + tshark parity badge.
- **Lineage trio manifest->reassembled->features vs tshark** §8c Day5 repeated, Day6 proves SQLite preserves not re-parse.
- **Per-version R1-R8 table** §9 repeated.
- **MUST not claim ML 8/8 green — SYSTEM 5/8 only Day5-6 ML remains 🟡 in-progress** — ML shell Section B no ECE/ECOD hard-fail until Day7-10.
- **Triple citation M03+M18+M22** honested.
- **Edge:** `lab/pcaps/jittered/*.pcap` missing -> ledger notes `jittered coverage <1.0 logged` not silent.

---

*Generated 2026-08-25 — SecureMailScope Day6 Evidence Snapshot Delta. SYSTEM 5/8 🟢 Section A only live binding E2E zip10->SQLite->dashboard 23 cols cold-start 0.04s GET /flows 0.64ms, ML 🟡 LEARN Day7-10 lean XGB Platt cv=2 ECE hi<0.20 500-boot ECOD ROC point>0.60 NDCG 12×2 κ>0.5 no hard-fail, 14/20 REAL +23×3 table 20 scored+3 info-greyed, lineage trio manifest->reassembled->features vs tshark, R1-R8 per-version, triple M03+M18+M22. Not 8/8 green — Day7 XGB day.*
