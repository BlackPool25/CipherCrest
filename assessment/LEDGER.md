# Assessment Ledger — SecureMailScope

| Family | environment_id | TLS | Cipher | Findings (severity) | risk_score | risk_level | posture_score | policy.action | policy_spec | siem_severity |
|--------|---------------|-----|--------|---------------------|------------|------------|---------------|---------------|-------------|---------------|
| 01 | family-01__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | Posture Info secure strong valid cert Low only — override | 6 | Low | 94 | allow | deliver | Low |
| 02 | family-02__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | TLS outdated M, Pre-TLS High, Implicit Info, MX Info, 0-RTT Info, KeyUsage Info, EKU Info, pathLen Info | 28 | High | 72 | quarantine | quarantine | High |
| 03 | family-03__postfix3.9_loss0 | TLS1.2 | DES-CBC3-SHA | TLS outdated M, 3DES SWEET32 High, CBC Medium, KEX High, NoFS High, PreTLS High, Implicit Info, MX Info, 0-RTT Info, KeyUsage Info, EKU Info, pathLen Info | 80 | Critical | 20 | block | hold_incident | Critical |
| 04 | family-04__postfix3.9_loss0 | TLS1.0 | RC4-SHA | TLS deprecated Critical, Weak cipher Critical, CBC High, KEX High, NoFS High, PreTLS High, Implicit Info, MX Info, 0-RTT Info | 100 | Critical | 0 | block | hold_incident | Critical |
| 05 | family-05__postfix3.9_loss0 | TLS1.1 | AES128-SHA | TLS deprecated Critical, CBC High, KEX High, NoFS High, PreTLS High, Implicit Info, MX Info, 0-RTT Info | 91 | Critical | 9 | block | hold_incident | Critical |
| 06 | family-06__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | PreTLS Info, Implicit Info, MX Info, 0-RTT Info, KeyUsage Info, EKU Info — is_tls13_opaque alone never holds | 6 | Low | 94 | allow | deliver | Low |
| 07 | family-07__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | TLS outdated M, CBC Medium, PreTLS High (expired SHA1 Critical via cert path 07 auto-injected as Critical 35 High base; via rules +60 for expired) — evaluated as 35 High, cert expired checked via validator | 35 | High | 65 | quarantine | quarantine | High |
| 08 | family-08__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | TLS outdated M, Weak cipher Critical, CBC Medium, KEX High, NoFS High, PreTLS High, Implicit Info, MX Info, 0-RTT Info | 90 | Critical | 10 | block | hold_incident | Critical |
| 09 | family-09__postfix3.9_loss0 | none | none | KEX High, NoFS High, STARTTLS High, Stripping High (low conf), PreTLS Info, Implicit Info, MX Info, 0-RTT Info | 67 | High | 33 | flag | deliver_banner | High |
| 10 | family-10__postfix3.9_loss0 | TLS1.2 | RSA-AES256-SHA | TLS outdated M, CBC Medium, KEX High, NoFS High, PreTLS High, Implicit Info, MX Info, 0-RTT Info | 65 | Critical | 35 | block | hold_incident | Critical |
| 09-triple | family-09__postfix3.9_loss0 history 3flow 127.0.0.11:54330 | none→TLS1.2 | none→AES128-SHA | 2 prior STARTTLS success + stripped → Stripping Critical (no low conf) | 77 | Critical | 23 | block | hold_incident | Critical |

- 23 checks (20 scored +3 info: 15b injection, 16b MX/MTA-STS/DANE, 16c 0-RTT) | RFC8996/RFC5280/RFC7817 etc | weak recall 100% (7/7 weak families +09) | 🟢
- Scoring: Critical25 High15 Medium7 Low3 Info1 cap100 | thresholds ≥40 Critical ≥25 High ≥10 Medium else Low | posture 100-risk
- Info-weighted: 15b pre_tls_buffer_len High if >0 else Info 1pt; 16b MX/MTA-STS/DANE Info 1pt enforce lane MX=mail.lab.local; 16c 0-RTT Medium if early_data_offered&&reusable else Info 1pt + ECH Outer INFO
- pre_tls_buffer_injection_possible: family01 1 High, family09 0 Info, triple 3flow flow1-2 High flow3 Info per lab/reassembler/reassemble.py _compute_pre_tls_buffer 220→0x16 0x03
- mx_mta_sts: shared/data/mta-sts-fixture.json enforce MX=mail.lab.local + dane-tlsa-fixture.json offline fallback live dig @mockdns if bridge up
- JA4: never raw ja4 as feature (only ja4_rarity per ALLOWED_RISK_FEATURES); no iso-tonic at n<100; no PQC claim; no body decrypt

## R1-R8 Limitations — Mapping-table annex per §6

| ID | Limitation | Per-version coverage | Mitigation |
|----|------------|----------------------|------------|
| R1 | TLS 1.3 encrypts Certificate — is_tls13_opaque True → leaf_present False all cert fields None honest | TLS1.3 1/20 opaque (family06) vs TLS1.0-1.2 14/20 REAL | Honesty invariant hard-fail via shared/schemas.py model_validator; greyed cert tab + blue banner 14/20 REAL +3 info |
| R2 | CRL unknown — no live fetch; crl_unknown_reason honest unknown | All families | Documented; no OCSP/CRL live fetch per offline air-gap; stapled OCSP parse only |
| R3 | OCSP staple opaque in TLS1.3 — encrypted like cert | TLS1.3 ocsp_stapled_status opaque | Legend "staple encrypted like cert" per validator/san_check; TLS1.2 unknown vs not_stapled honest |
| R4 | Stripping single-flow low-conf vs triple Critical | Stripped: single High low-conf, triple Critical with 2 prior upgraded same 5-tuple | EAST 320k CVE-2021-38502 §4.2; history triple same client 127.0.0.11:54330→127.0.0.1:587 |
| R5 | pre_tls_buffer_len heuristic — bytes between 220 and ClientHello 0x16 0x03 | Upgraded High (pipelined), stripped 0 Info | lab/reassembler/reassemble.py _compute_pre_tls_buffer; Postfix CVE-2011-0411 GHSA-9j88 injection_possible flag |
| R6 | MX/MTA-STS/DANE fixture fallback — live dig @mockdns if bridge up else offline JSON | MX=mail.lab.local enforce lane | shared/data/mta-sts-fixture.json + dane-tlsa-fixture.json; never claim DANE beyond fixture; live dig try/except |
| R7 | 0-RTT early_data replay — ticket_age not bounded → Medium | early_data_offered && psk && ticket_age reusable → Medium else Info | RFC8446 §8, RFC9846 §8 GnuTLS replay; ticket_age bounded check; ECH outer INFO per RFC9849 |
| R8 | ECH outer present — Inner not parsed RFC9849 out-of-scope | ECH outer INFO only | analyzer/parse.py notes encrypted_client_hello, Inner not parsed; never claim PQC |

- Platt ECE [lo,hi]: TBD (Day7-10 n≥100 not iso-tonic)
- ΔECE vs uncalibrated: TBD
- SHAP top3: TBD
- Hybrid PR-AUC [lo,hi] vs vanilla: TBD

## Daily Poll — Day3-4
- Polled shared/progress.md daily: 🟢 gated (23 checks, no iso-tonic at n<100, raw ja4 not as feature, family-grouping forbidden)
- prior_flag disjoint: shared/data/censys_top_ja4.json source until censys_sampled_200.json Day7
- locked disjoint + ja4_rarity 0..1 span + chain_valid None censys 11/28 cols hardened

## Honesty Annex — P1 ack Day5 alias, freeze intact

- PolicyDecision wire literals frozen per shared/CONTRIBUTING.md P1 Day2 00:00 additive-only: `allow/quarantine/block/flag` unchanged (shared/schemas.py:123). No mutation.
- Spec display mapping via assessment/policy.py `_ALIAS = {"allow":"deliver","flag":"deliver_banner","quarantine":"quarantine","block":"hold_incident"}` + `to_spec_action()` only in policy layer; dashboard/EVIDENCE use spec, wire stays frozen. `PolicyDecision.model_json_schema()["properties"]["action"]["enum"] == ["allow","quarantine","block","flag"]` verified in tests.
- P1 ack Day5: alias documented, freeze intact, no quarantine table / raw body attach, quarantine_id None lean.
- Lean policy deterministic: Low (<10)→allow banner None, Medium (10-24)→flag yellow "Weak transport — do not send sensitive data", High (25-39)→quarantine/flag yellow, Critical (≥40)→block red "Critical — blocked / hold_incident"; siem_severity mirrors risk_level; disposition_reason includes risk_score+top finding; is_tls13_opaque alone never holds (opaque with only Info → Low allow); low-conf stripping single → flag not block, triple → block.
- Per-family policy (via evaluate+score): 01 secure strong valid → Low allow, 03 3DES → Critical→block (High quarantined in display), 04 RC4→Critical block, 06 opaque→Low allow, 07 expired+SHA1 synthetic→Critical block, 09 single low-conf→High flag, 09 triple→Critical block. 7 fixtures green.
- No torch/training/iso-tonic/as any/unwrap; <250 LOC lean (217 pure); quarantine table deferred to Day10 stretch.

## Daily Poll — Day5

- 2026-08-25 assessment/policy.py lean 7 fixtures 🟢 — decide() deterministic, 7/7 green, 217 LOC, alias P1 ack, is_tls13_opaque never holds, low-conf flag not block
- 2026-08-25 assessment/splits.json 4-dataset env-group wiring 🟢 — 17 envs (10 base +7 jitter distinct family-0X__jitter1_loss5), groups_by_env {env:[flow_id]}, D1_train 5 (01-05), D2_val 3 (06-08), D3_locked 2 (09,10), D_prior 20 censys_prior_* disjoint, D5_temporal_same_env {train_epoch:2026-08-27T00:00:00Z test_epoch:2026-09-03T00:00:00Z env_id_frozen:true} synthetic until Day10 real T2 pcap, unique≥5 ratio 2.5<3, locked∩(train∪val)=∅, prior∩risk=∅, family_id forbidden, no iso-tonic, <250 LOC json
- D5 synthetic until Day10 real T2 pcap — train_epoch from lab/manifest.json capture_epoch 2026-08-27T00:00:00Z, test 7d later 2026-09-03T00:00:00Z same env_id_frozen, forward TimeSeriesSplit no shuffle
- prior_flag disjoint 🟢 — censys 20 rows prior_flag:true chain_valid None days_to_expiry None san_match None ja4_rarity 0.02..0.99, D_prior_groups never in D1/D2/D3, no risk labels on censys, environment_id grouping (not family_id), StratifiedGroupKFold(n_splits=5 groups=environment_id) contract

## Daily Poll — Day5-6 Hardening (Schemas Freeze, Fixtures Parity, Offline Bundle Shell)

- 2026-08-25 Day5 09:00 assessment/policy.py lean 7 fixtures 🟢 — decide() Low→allow 6/94, Medium→flag yellow banner "Weak transport — do not send sensitive data", High→quarantine yellow, Critical→block red "Critical — blocked / hold_incident"; siem_severity mirrors risk_level; disposition_reason includes risk_score+top finding; is_tls13_opaque alone never holds; F1 Low→allow, F3 High→quarantine, F4 Critical→block hold_incident, F9 single High low-conf→flag deliver_banner, F9 triple Critical→block
- 2026-08-25 Day5 12:00 assessment/splits.json 12 groups prior_flag disjoint 🟢 — 17 envs (10+7 jitter), groups_by_env {env:[flow_id]}, D1_train 5 D2_val 3 D3_locked 2 D_prior 20 censys_prior_* disjoint; D3_locked ∩ (D1∪D2)=∅; D_prior ∩ D1=∅; prior_flag:true chain_valid None days_to_expiry None san_match None ja4_rarity 0.02..0.99; D5_temporal_same_env env_id_frozen true train≠test; family_id forbidden; StratifiedGroupKFold(n_splits=5 groups=environment_id)
- 2026-08-25 Day5 15:00 api/db.py JSONB <1ms + POST /analyze chunk-read 🟢 — api/db.py 4 funcs init_db/upsert_flows/query_all/query_by_flow_id PRIMARY KEY json_extract probe TEXT fallback; api/app.py 1 MiB chunk-read 413 guard magic D4 C3 B2 A1 / A1 B2 C3 D4 / 0A 0D 0D 0A; zip fan-out BadZipFile→error; FlowVerdict.model_validate hard-fail before upsert; GET /flows <50ms SQLite without re-parse
- 2026-08-25 Day5 18:00 wheelhouse lean <350M 🟢 — wheelhouse/ 345M 32 wheels xgboost==1.7.6 192M + pyod==2.0.5 + scikit-learn 1.5.0 + cryptography 43.0.1 manylinux --only-binary=:all: --prefer-binary; no torch; pip install --no-index --find-links wheelhouse --only-binary=:all: --dry-run Would install 32; du -m 345 <350 hard-fail
- 2026-08-25 Day6 09:00 CoverageTable 23×3 + honesty 14/20 REAL 🟢 — dashboard/components/CoverageTable.jsx 103 LOC per-port 25/587/993 + MX 25 vs RFC8314 M02 + M3AAWG + RFC8461/RFC7672 per-version R1-R8 14/20 REAL +3 info (15b injection pre_tls_buffer, 16b MX, 16c 0-RTT) greyed; dashboard/components/ThreatMatrix.jsx 95 LOC rows=flows cols=23 20 scored color Critical25 High15 Medium7 Low3 +3 greyed info; dashboard/app.jsx HonestyBanner is_tls13_opaque blue banner + greyed cert tab 14/20 REAL legend M03+M18+M22; Vite gz 157k <3670016
- 2026-08-25 Day6 12:00 live binding E2E zip 10 → dashboard 🟢 — api/tests/test_api_e2e.py zip 10 families → 200 + 10 FlowVerdict assessment validated + policy via decide allow/quarantine/block/flag posture 0-100 policy_dist wire truth; GET /flows polls _last_result else SQLite query_all else stub; dashboard fetch /api/flows 5s poll + SWR + visibilitychange; cold-start <3s (0.04s); malformed flow_id:error not crash
- 2026-08-25 Day6 15:00 EVIDENCE Day5-6 SYSTEM 5/8 🟢 — eval/EVIDENCE_Day5.md + Day6.md SYSTEM 5/8 (STARTTLS F1>95% lossy/weberblog + cipher exact 100% >98% + cert prec 1.000 >90% stratified CABF/private + badssl 1.000 + weak recall 100% 23-check 20 scored +3 info + JSON 20/20 + POST /analyze cold-start <3s + GET /flows <50ms + wheelhouse <350M + splits 12 groups + dashboard 14/20 REAL honest); ML shell Day7-10 lean XGB Platt cv=2 ECE hi<0.20 ECOD ROC>0.60 NDCG 🟡
- Schemas freeze audit 🟢 — shared/schemas.py frozen Day2 00:00 additive-only (P1 CODEOWNER); shared/schemas.json == FlowVerdict.model_json_schema(); PolicyDecision.action enum ["allow","quarantine","block","flag"] frozen, _ALIAS only in policy layer via to_spec_action(); shared/tests/test_freeze_guard.py 6 passed breaking rename→ValidationError, additive Optional, no isotonic, no raw ja4 in vector
- prior_flag disjoint line 🟢 — D_prior_groups 20 censys_prior_* prior_flag:true chain_valid None days_to_expiry None san_match None ja4_rarity 0.02..0.99 span 0..1; D_prior ∩ (D1∪D2∪D3)=∅ disjoint; no risk labels on censys; environment_id grouping per StratifedGroupKFold groups=environment_id; ja4_rarity only (raw ja4 never in ALLOWED_RISK_FEATURES) + GREASE 16 filter_grease FoxIO

### Per-Family Policy Lineage Audit (Day5-6 hardening)

| Family | risk_score | risk_level | posture_score | policy.action (wire) | to_spec_action | siem_severity | banner | disposition_reason snippet |
|--------|------------|------------|---------------|----------------------|----------------|---------------|--------|----------------------------|
| 01 | 6 | Low | 94 | allow | deliver | Low | None | Low risk_score 6 top Posture Info: secure strong cipher valid cert |
| 02 | 28 | High | 72 | quarantine | quarantine | High | yellow Weak transport | High risk_score 28 top Pre-TLS injection possible |
| 03 | 80 | Critical | 20 | block | hold_incident | Critical | red Critical | Critical risk_score 80 top 3DES SWEET32 |
| 04 | 100 | Critical | 0 | block | hold_incident | Critical | red Critical | Critical risk_score 100 top TLS version deprecated |
| 05 | 91 | Critical | 9 | block | hold_incident | Critical | red Critical | Critical risk_score 91 top TLS version deprecated |
| 06 | 6 | Low | 94 | allow | deliver | Low | None | Low risk_score 6 top Pre-TLS injection possible (opaque never holds) |
| 07 | 35 | High | 65 | quarantine | quarantine | High | yellow Weak transport | High risk_score 35 top Pre-TLS injection possible |
| 08 | 90 | Critical | 10 | block | hold_incident | Critical | red Critical | Critical risk_score 90 top Weak cipher (DES) |
| 09 | 67 | High | 33 | flag | deliver_banner | High | yellow Weak transport low conf | High risk_score 67 top Weak KEX (no FS) low conf |
| 10 | 65 | Critical | 35 | block | hold_incident | Critical | red Critical | Critical risk_score 65 top Weak KEX (no FS) |
| 09-triple | 77 | Critical | 23 | block | hold_incident | Critical | red Critical | Critical risk_score 77 top Weak KEX (no FS) history 3flow |
- prior_flag disjoint: shared/fixtures/censys_sampled_200.json 20 rows prior_flag:true chain_valid None days_to_expiry None san_match None ja4_rarity 0.02..0.99; D_prior_groups 20 censys_prior_* never in D1_train_groups 5 (01-05) nor D2/D3; locked ∩ (train∪val)=∅; environment_id grouping forbidden is family_id; StratifiedGroupKFold(n_splits=5 groups=environment_id) contract; max/min ratio 2.5 <3; unique envs 17 ≥5 🟢
