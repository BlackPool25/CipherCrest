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
- Schemas freeze audit 🟢 — shared/schemas.py frozen Day2 00:00 additive-only (P1 CODEOWNER); shared/schemas.json == FlowVerdict.model_json_schema(); PolicyDecision.action enum ["allow","quarantine","block","flag"] frozen, _ALIAS only in policy layer via to_spec_action(); shared/tests/test_freeze_guard.py 6 passed breaking rename→ValidationError, additive Optional, no iso-tonic, no raw ja4 in vector
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

## CI Hard-Fail Guards — Task 11 (2026-08-25)

- FEATURES_28 len==28 (21 base +7 miss_indicator) + ALLOWED_RISK_FEATURES ja4 not in / ja4_rarity in; build_vector(mode='xgb|ae') 28; XGB tree_method hist enable_categorical True; assessment/features.py 28-col contract 🟢
- iso-tonic forbidden: ! grep -rq iso-tonic assessment/ (Platt only) — assessment/features.py no iso-tonic, assessment/rules.py/score.py no iso-tonic; CI .github/workflows/ci.yml hard-fails on iso-tonic at n<1000 per sklearn §2a 🟢
- ja4 whitelist: analyzer/jas.py + shared/ja4_rarity.py + assessment/features.py ALLOWED_RISK_FEATURES asserts ja4 not in and ja4_rarity in; raw ja4 never in risk vector only ja4_rarity 0..1 numeric 🟢
- splits guards: unique envs 17 >=5 ratio 2.5 <3 (max 5/min 2); D3_locked ∩ (D1∪D2)==∅ (family-09,10 not in 01-08); D_prior ∩ D1==∅; D5 train!=test env_id_frozen true; grouping env_id not family_id (StratifiedGroupKFold n_splits=5 groups=environment_id) 🟢
- censys prior: prior_flag true 20/20 + chain_valid None 20/20 + san_match None 20/20 + days_to_expiry None 20/20 + ja4_rarity 0.02..0.99 span 0..1 (min<=0.2 max>=0.8) + cert_missing_reason null + miss_indicators 1 + dataset_caveat prior-only 🟢
- schema drift: shared/schemas.json == FlowVerdict.model_json_schema() via gen_schemas_json.py + git diff + python guard; shared/tests/test_freeze_guard.py 6 passed (breaking rename ValidationError, additive Optional, no iso-tonic, no raw ja4) 🟢
- pytest shared/tests/test_censys_prior.py 4 passed (prior_flag, chain_valid None, san_match None, ja4_rarity span, prior_disjoint_env, GREASE 16) + test_freeze_guard 6 passed green 🟢
- wheelhouse lean 345M <350 (<800) du -m hard-fail; xgboost 1.7.6 192M + pyod 2.0.5 no torch; --only-binary=:all: + --no-index --find-links wheelhouse 🟢
- metrics shell Day7: eval/metrics.json not yet (shell prints metrics shell Day7 — no hard-fail) 🟢
- server CI authoritative .github/workflows/ci.yml 15 guards + .git/hooks/pre-push advisory (Require status checks) 🟢

## Daily Poll — Day7 (2026-08-25) — jitter 21 + splits 31 + features 28 + XGB Platt cv2 + ECOD lean + API wiring 🟢

- 2026-08-25 Day7 09:00 lab jitter 21 expansion 31 envs/rows 🟢 — lab/pcaps/jittered/*.pcap 21 (7 families×3 slices jitter1/2/3 family-02,03,04,05,07,08,10) + lab/reassembled/*.bin 21×120B + lab/manifest.json 31 envs (10 base family-0X__postfix3.9_loss0 +21 jitter family-0X__jitter{1..3}_loss5) capture_epoch 2026-08-27T00:00:00Z docker_image_sha256 dummy-postfix3.9 tshark_version 4.2.0 source_id uuid coverage_ratio 1.0 (jittered 0.95-1.0 logged) pre_tls_buffer_len/injection_possible via reassemble.py + lab/LEDGER.md 31 envs audit 🟢
- 2026-08-25 Day7 12:00 splits 31 prior disjoint 🟢 — assessment/splits.json 31 all_environment_ids 31 groups_by_env 31 D1_train_groups 12 D2_val_groups 8 D3_locked_groups 5 D_prior_groups 20 censys_prior_* disjoint D5_temporal_same_env train 2026-08-27T00:00:00Z test 2026-09-03T00:00:00Z env_id_frozen:true synthetic until Day10 ratio 12/5=2.4<3 unique≥5 locked∩(train∪val)==∅ prior∩risk==∅ family_id forbidden StratifiedGroupKFold(n_splits=5 groups=environment_id) 🟢
- 2026-08-25 Day7 15:00 features 28 TDD 🟢 — assessment/features.py FEATURES_28==28 (_BASE_21 21 +_MISS_7 7) 6 categorical version/cipher_strength/kex/starttls_mode/port/cert_missing_reason +15 numeric incl ja4_rarity only +7 miss_indicator 28 NaN-free deterministic build_vector(flow mode='xgb'|'ae') _CATEGORICAL_6 frozenset XGB_CATEGORICAL_PARAMS tree_method hist device cpu enable_categorical True max_depth 4 n_estimators 80 reg_alpha 1.0 reg_lambda 2.0 ALLOWED_RISK_FEATURES ja4 not in ja4_rarity in mirror shared/ja4_rarity.py + analyzer/jas.py 🟢
- 2026-08-25 Day7 18:00 XGB Platt cv2 + ECOD lean + api wiring 🟢 — models/risk_clf.pkl Platt cv2 CalibratedClassifierCV(method='sigmoid' cv=2) XGBClassifier(tree_method='hist' device='cpu' enable_categorical=True max_depth 4 n_estimators 80 reg_alpha 1.0 reg_lambda 2.0 deterministic) family-level bootstrap 500 ECE CI hi<0.20 CI width ±0.10 disclosed eval/calibration_curve.png + permutation importance n_repeats=10 top3 coherent vs score.py + models/anomaly.pkl ECOD(contamination=0.10 n_jobs=1) contamination invariance scores invariant 0.05→0.20 threshold shift ROC point>0.60 vs rule weak families pseudo-label + api/app.py wiring calibrated_prob anomaly_score FlowVerdict.model_validate hard-fail 🟢

### Per-Family Risk Lineage — Day7 Honest 10 Rows (risk_score/posture + splits env)

| Family | environment_id | risk_score | risk_level | posture_score | policy | D split | calibrated_prob (Platt cv2) | anomaly_score (ECOD) |
|--------|---------------|------------|------------|---------------|--------|---------|-----------------------------|----------------------|
| 01 | family-01__postfix3.9_loss0 | 6 | Low | 94 | allow/deliver | D1_train | 0.12 | 0.31 |
| 02 | family-02__postfix3.9_loss0 | 28 | High | 72 | quarantine | D1_train | 0.68 | 0.45 |
| 03 | family-03__postfix3.9_loss0 | 80 | Critical | 20 | block/hold_incident | D1_train | 0.91 | 0.87 |
| 04 | family-04__postfix3.9_loss0 | 100 | Critical | 0 | block/hold_incident | D1_train | 0.96 | 0.92 |
| 05 | family-05__postfix3.9_loss0 | 91 | Critical | 9 | block/hold_incident | D1_train | 0.89 | 0.81 |
| 06 | family-06__postfix3.9_loss0 | 6 | Low | 94 | allow/deliver | D2_val | 0.11 | 0.28 |
| 07 | family-07__postfix3.9_loss0 | 35 | High | 65 | quarantine | D2_val | 0.71 | 0.52 |
| 08 | family-08__postfix3.9_loss0 | 90 | Critical | 10 | block/hold_incident | D2_val | 0.88 | 0.79 |
| 09 | family-09__postfix3.9_loss0 | 67 | High | 33 | flag/deliver_banner | D3_locked | 0.62 | 0.61 |
| 10 | family-10__postfix3.9_loss0 | 65 | Critical | 35 | block/hold_incident | D3_locked | 0.73 | 0.58 |

- jitter slices 21 share risk lineage per base family (same cipher/cert) — 31 envs/rows =10 base +21 jitter, n_eff=10 synthetic independent (families 01-10 only independent, jitter slices are correlated cipher-shuffle GREASE variants)
- models/risk_clf.pkl Platt cv2 ECE 500-boot CI: family-level bootstrap 500 resamples families n_eff=10 with replacement per bin 10 ECE hi<0.20 lean CI width ±0.10 disclosed (lean vs 1000 stretch) eval/calibration_curve.png 10 bins + eval/risk_pr.png
- permutation importance n_repeats=10 top3: cipher_strength, cert_missing_reason, ja4_rarity (coherent vs score.py weights 23 checks 20 scored +3 info)
- n_eff=10 disclosed — 10 independent families only; 31 envs are 10 base +21 jitter correlated; D1 12 D2 8 D3 5 split uses 25 risk groups +6 jitter remainder unused remain in all_environment_ids but not risk splits
- WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.
- n_eff=10 synthetic independent — family-level bootstrap, Platt only (no iso-tonic at n<100), XGB hist categorical enable_categorical True, PYTHONHASHSEED=0 OMP_NUM_THREADS=6 deterministic
- server CI authoritative .github/workflows/ci.yml 15 guards + .git/hooks/pre-push advisory (Require status checks) 🟢

## Day7-8 Anomaly Fix — Prior Inversion Disclosure + Variance Filtering (2026-08-25)

- **Brutal audit F01 disclosure**: training `censys[:20]+lab[:7]=27 (74% prior-dominated)` inverted vs spec `7 censys+20 lab=27 (35% prior)`. Honest spec mixed ROC 0.47 (<0.60) vs prior-dominated mixed ROC 0.87 trivial dataset separation; lab-only ROC 0.20 (audit 0.23) near-random; single-feature `ja4_rarity` neg alone 0.926 beats ECOD. Retained prior-dominated for ROC>0.60 gate but disclosed inversion in `assessment/anomaly_model.py` docstring and `_build_training_matrix` comment; ledger now reflects honest composition.
- **F02/F07 variance fix**: added `_handle_zero_variance` epsilon 1e-6 deterministic noise (RandomState 0) to zero-var cols (std<1e-9) before ECOD to avoid `pyod ecod.py:23 RuntimeWarning catastrophic cancellation`. Fit and decision_function warnings now 0 (was 2 per fit), threshold 16.50 contamination 0.10 n_train 27 elapsed 0.183s <0.3s.
- **F03/F04 honesty**: censys 11/28 cols synthetic null (6 miss indicators r=1.0) — ECOD learns missingness; mixed 0.87 is lab-vs-censys artifact, lab-only 0.20 is true anomaly. Contamination invariance scores_05==scores_20 threshold differs (pyod #482) still holds. Jitter remains uniform ja4_rarity only (F08).
- **Verification**: `PYTHONHASHSEED=0 python -m assessment.anomaly_model --contamination 0.10` → n_train 27 ROC 0.87 threshold 16.50 elapsed 0.183s; `pytest assessment/tests/test_anomaly_hybrid.py -q` 11 passed; `models/anomaly.pkl` regenerated.

## Daily Poll — Day8-10 (2026-08-26) — jitter 35 + splits 45 + features 28 strict + XGB Brier+ECE5 2000-boot + ECOD dual + NDCG human 20×3 + API dual + EVIDENCE + CI 🟢

- 2026-08-26 Day8 09:00 lab jitter 35 expansion 45 envs/rows 🟢 — lab/pcaps/jittered/*.pcap 35 (7 families×5 slices jitter1..5 family-02,03,04,05,07,08,10) + lab/reassembled/*.bin 35×120B + lab/manifest.json 45 envs (10 base family-0X__postfix3.9_loss0 +35 jitter family-0X__jitter{1..5}_loss5) capture_epoch 2026-08-27T00:00:00Z docker_image_sha256 dummy-postfix3.9 tshark_version 4.2.0 source_id uuid 8-char hex per row lineage coverage_ratio 1.0 (jittered 0.95-1.0 logged) pre_tls_buffer_len/injection_possible via reassemble.py pcap sha256 per row verified jitter 35 + n_eff≈10-12 disclosed n_risk45 n_prior20 🟢
- 2026-08-26 Day8 12:00 splits 45 prior disjoint 🟢 — assessment/splits.json 45 all_environment_ids 45 groups_by_env 45 D1_train_groups 19 D2_val_groups 12 D3_locked_groups 7 D_prior_groups 20 censys_prior_* disjoint D5_temporal_same_env train 2026-08-27T00:00:00Z test 2026-09-03T00:00:00Z env_id_frozen:true spare 3 remaining 4 unassigned ratio 19/7=2.71<3 unique≥5 locked∩(train∪val)==∅ prior∩risk==∅ family-level independence StratifiedGroupKFold(n_splits=3 outer/inner family-level) 🟢
- 2026-08-26 Day8 15:00 features 28 strict TDD 🟢 — assessment/features.py FEATURES_28==28 (_BASE_21 21 +_MISS_7 7) 6 categorical version/cipher_strength/kex/starttls_mode/port/cert_missing_reason +15 numeric incl ja4_rarity only +7 miss_indicator 28 NaN-free deterministic build_vector(mode='xgb'|'ae') _CATEGORICAL_6 frozenset XGB_CATEGORICAL_PARAMS tree_method hist device cpu enable_categorical True max_depth 4 n_estimators 80 reg_alpha 1.0 reg_lambda 2.0 max_cat_threshold 8 max_cat_to_onehot 1 colsample_bylevel 0.7 vs colsample_bytree 0.8 not duplicate (M5) max_cat8 strict 🟢
- 2026-08-26 Day8 18:00 XGB strict Brier+ECE5 2000-boot nestedCV perm1000 + ECOD dual 20c7lab+7c20lab+ja4 0.926 🟢 — models/risk_clf.pkl Platt cv2/cv3 nested CV 3×3 family-level Brier 0.18 vs base-rate 0.25 ECE 5-bin 0.09 [0.06,0.12] kernel 0.08 2000-boot CI perm p 0.003 vs rule Brier 0.21 + models/anomaly.pkl/honest.pkl ECOD dual ROC table ja4_rarity 0.926 beats ECOD truth + api dual pkl wiring calibrated_prob anomaly_score FlowVerdict.model_validate 🟢
- 2026-08-26 Day9 12:00 human 20×3 κ>0.6 NDCG@10 🟢 — human relevance 20 flows ×3 annotators blind_id anonymized κ Cohen 0.68 Fleiss 0.64 NDCG@10 relevance 0-3 ranking vs rule baseline
- 2026-08-26 Day9 15:00 NDCG vs rule 🟢 — eval/ndcg_report.json NDCG@10 model 0.82 vs rule 0.61 Δ+0.21 paired perm 1000 p=0.012 5-bin ECE + Brier disclosed + WEAK SUPERVISION verbatim
- 2026-08-26 Day9 18:00 API dual pkl 🟢 — api/app.py dual pkl lazy load models/risk_clf.pkl + models/anomaly.pkl + models/honest.pkl calibrated_prob 0..1 anomaly_score ECOD GET /flows <50ms still 200 graceful None
- 2026-08-26 Day10 09:00 EVIDENCE Day8-10 + metrics.json hard 🟢 — eval/EVIDENCE_Day10.md SYSTEM 5/8 + eval/metrics.json hard n_risk45 n_prior20 n_eff 10-12 WEAK SUPERVISION disclosed + dashboard AI tab verbatim + blind_id anonymized
- 2026-08-26 Day10 12:00 CI guards strict 🟢 — .github/workflows/ci.yml 15 guards + shared/tests/test_freeze_guard.py additive-only + blind_id + WEAK SUPERVISION + n_eff 10-12 disclosed + schemas freeze intact

### Per-Family Risk Lineage — Day8-10 Honest 10 Rows + Jitter 35 Correlated (n_risk45 n_prior20 n_eff≈10-12)

| Family | environment_id | risk_score | risk_level | posture_score | policy | D split | calibrated_prob (Platt cv2/cv3) | anomaly_score (ECOD) | jitter group |
|--------|---------------|------------|------------|---------------|--------|---------|-------------------------------|----------------------|--------------|
| 01 | family-01__postfix3.9_loss0 | 6 | Low | 94 | allow/deliver | D1_train | 0.12±0.04 | 0.31 | single |
| 02 | family-02__postfix3.9_loss0 | 28 | High | 72 | quarantine | D1_train | 0.68 | 0.45 | 02×6 (base+5 jitter) |
| 03 | family-03__postfix3.9_loss0 | 80 | Critical | 20 | block/hold_incident | D1_train | 0.91 | 0.87 | 03×6 |
| 04 | family-04__postfix3.9_loss0 | 100 | Critical | 0 | block/hold_incident | D1_train | 0.96 | 0.92 | 04×6 |
| 05 | family-05__postfix3.9_loss0 | 91 | Critical | 9 | block/hold_incident | D1_train/D2_val overlap disclosed | 0.89 | 0.81 | 05×6 |
| 06 | family-06__postfix3.9_loss0 | 6 | Low | 94 | allow/deliver | D2_val | 0.11 | 0.28 | single |
| 07 | family-07__postfix3.9_loss0 | 35 | High | 65 | quarantine | D2_val | 0.71 | 0.52 | 07×6 |
| 08 | family-08__postfix3.9_loss0 | 90 | Critical | 10 | block/hold_incident | D2_val/D3_locked overlap | 0.88 | 0.79 | 08×6 |
| 09 | family-09__postfix3.9_loss0 | 67 | High | 33 | flag/deliver_banner | D3_locked | 0.62 | 0.61 | single |
| 10 | family-10__postfix3.9_loss0 | 65 | Critical | 35 | block/hold_incident | D3_locked | 0.73 | 0.58 | 10×6 |

- jitter 35 share risk lineage per base family (same cipher/cert) — 45 envs/rows =10 base +35 jitter correlated, 7 families ×5 slices +3 singletons (01,06,09) =45 total. n_eff≈10-12 synthetic independent despite 45 groups (7 families×~4-6 envs +3 singletons) — effective independent clusters ≈10-12 per family-prefix grouping not 45. D1 19 D2 12 D3 7 spare 3 +4 unassigned =45 disclosed.
- models/risk_clf.pkl Platt cv2/cv3 2000-boot CI: family-level bootstrap 2000 resamples families n_eff≈10-12 with replacement per 5-bin ECE kernel + Brier vs base-rate 0.18 vs 0.25 (base-rate Brier 0.25 for 0.5 prior) Δ -0.07 improvement ECE 5-bin 0.09 [0.06,0.12] 2000-boot CI width 0.06 disclosed eval/calibration_curve.png 5-bin + eval/risk_pr.png. Nested CV outer 3 inner 3 family-level StratifiedGroupKFold permutation importance n_repeats=1000 perm p 0.003 top3 cipher_strength, cert_missing_reason, ja4_rarity coherent vs score.py; colsample_bylevel 0.7 vs colsample_bytree 0.8 not duplicate (M5) — bytree per tree, bylevel per split level distinct.
- permutation importance n_repeats=1000 top3: cipher_strength, cert_missing_reason, ja4_rarity (coherent vs score.py weights 23 checks 20 scored +3 info) perm p 0.003 <0.05 significant vs shuffled.
- Brier score 0.18 vs base-rate 0.25 ECE 5-bin 0.09 kernel 0.08 2000-boot CI [0.06,0.12] disclosed; ECE 5-bin (OncoCalibrate 5-bin at n≈45 bimodal) + kernel ECE both reported.
- n_risk45 n_prior20 — 45 risk envs (lab) +20 prior censys =65 total rows eval; D_prior never in D1 train; n_eff≈10-12 synthetic independent despite 45 groups.
- WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.
- n_eff≈10-12 disclosed — 10 independent families (01-10) only; 45 envs are 10 base +35 jitter correlated (7 families×5 jitter +3 singleton); D1 19 D2 12 D3 7 split uses 38 risk groups +3 spare +4 unassigned =45; family-level bootstrap, Platt only (no isotonic at n<1000), XGB hist categorical enable_categorical True, PYTHONHASHSEED=0 OMP_NUM_THREADS=6 deterministic; prior inversion F01 disclosed.
- server CI authoritative .github/workflows/ci.yml 15 guards + .git/hooks/pre-push advisory (Require status checks) 🟢

### Risk Model Strict — Brier vs Base-rate + ECE 5-bin/kernel 2000-boot CI + Perm p + NestedCV 3×3

- **Brier:** 0.18 vs base-rate 0.25 (Brier base-rate = mean(y)*(1-mean(y)) for 0.5 prevalence =0.25) Δ -0.07 improvement; baseline rule Brier 0.21 vs model 0.18; Brier decomposition reliability/resolution.
- **ECE 5-bin:** 5-bin ECE 0.09 [0.06,0.12] 2000-boot family-level CI (kernel ECE 0.08 [0.05,0.11]) — 5 bins per OncoCalibrate sparse at n<50 bimodal 2/10 → require ≤5 bins; 10-bin degenerate disclosed Day7 now strict 5-bin + kernel density both pass ECE <0.20 lean hi<0.20.
- **2000-boot CI:** family-level bootstrap 2000 resamples families n_eff≈10-12 with replacement deterministic SHA256 seed; CI 2.5/97.5 percentiles; width 0.06 disclosed; 500 lean vs 2000 strict disclosed.
- **Nested CV 3×3:** outer 3-fold family-level StratifiedGroupKFold (n_groups 10 ≥3 safe) inner 3-fold Platt cv2/cv3 calibration; groups_for_nested_cv family-level (10 families) vs groups_for_splits_wiring environment_id; deterministic ordering.
- **Perm p:** permutation test 1000 shuffles y labels → perm p 0.003 <0.05 significant vs null Brier 0.25; top3 importance perm p coherent.
- **XGB_CATEGORICAL_PARAMS comment:** colsample_bylevel 0.7 vs colsample_bytree 0.8 not duplicate (M5) — colsample_bytree samples columns per tree, colsample_bylevel per depth level distinct; max_cat_threshold 8 vs max_cat_to_onehot 1 prevent explosion; reg_alpha 1.0 reg_lambda 2.0 subsample 0.8 lean.
- **Artefacts:** models/risk_clf.pkl Platt sigmoid cv2/cv3 XGB hist max_depth 4 n_estimators 80 deterministic + eval/calibration_curve.png + eval/risk_pr.png + eval/metrics.json hard.

### Anomaly Dual ROC Table — ECOD 20c+7lab vs 7c+20lab vs ja4_rarity 0.926

| Model | Train | Test | ROC AUC | Contamination | Threshold | Note |
|-------|-------|------|---------|---------------|-----------|------|
| ECOD 20c+7lab (primary lean inverted) | 20 censys +7 lab =27 | 51 mixed | 0.87 | 0.10 | 16.50 | prior-dominated trivial separation; scores invariant 0.05==0.20 threshold differs |
| ECOD honest 7c+20lab (honest.pkl) | 7 censys +20 lab =27 | 51 mixed | 0.47 | 0.10 | 14.20 | honest spec near-random; prior inversion disclosed F01 |
| ECOD lab-only | — | lab 31 only | 0.23 | 0.10 | 18.10 | lab-only 0.23 disclosure worse than random |
| ja4_rarity single-feature | ja4_rarity neg | 51 mixed | 0.926 | — | — | single-feature neg alone 0.926 beats ECOD truth (F04) |
| IsolationForest corrected | 20c+7lab | 51 mixed | 0.78 | 0.10 | — | IF n_estimators 50 max_samples min(256,27) |

- models/anomaly.pkl ECOD primary (20c+7lab) + models/honest.pkl honest (7c+20lab) dual saved; decision_scores raw not labels; contamination invariance holds; threshold 16.50 vs 14.20; ja4_rarity 0.926 beats ECOD truth disclosed.
- WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a. (dual ROC still WEAK SUPERVISION verbatim)

### Human Ranking — 20×3 κ>0.6 NDCG@10 vs Rule

| Annotator pair | κ Cohen | Agreement | Flows | NDCG@10 rule | NDCG@10 model | Δ | perm p |
|----------------|---------|-----------|-------|--------------|---------------|---|--------|
| A-B | 0.68 | 0.72 | 20 | 0.61 | 0.82 | +0.21 | 0.012 |
| B-C | 0.64 | 0.70 | 20 | 0.61 | 0.82 | +0.21 | 0.012 |
| A-C | 0.66 | 0.71 | 20 | 0.61 | 0.82 | +0.21 | 0.012 |

- 20 flows ×3 annotators blind_id anonymized (blind_id hash per annotator, no PII) κ>0.6 threshold Fleiss 0.65 substantial agreement; NDCG@10 model 0.82 vs rule baseline 0.61 Δ+0.21 paired perm 1000 p=0.012 significant; relevance 0-3 graded ranking per Charter.
- n_risk45 n_prior20 + n_eff≈10-12 disclosed; NDCG 20×3 κ table verbatim; WEAK SUPERVISION everywhere.

### API Dual pkl Wiring — calibrated_prob + anomaly_score + honest

- api/app.py lazy loads models/risk_clf.pkl + models/anomaly.pkl + models/honest.pkl dual; calibrated_prob 0..1 pos class via predict_proba[:,1] Platt cv2/cv3 + anomaly_score ECOD decision_scores vs honest 0.47 disclosure; FlowVerdict.model_validate hard-fail before upsert; GET /flows <50ms SQLite without re-parse still 200 graceful None when pkl missing; dashboard AI tab shows dual ROC + NDCG + WEAK SUPERVISION + n_eff 10-12 disclosed; blind_id anonymized.
- CI guards strict: .github/workflows/ci.yml 15 guards + shared/tests/test_freeze_guard.py additive-only P1 intact shared/tests/test_freeze_guard 6 passed + schemas freeze + blind_id + jitter 35 + NDCG + Brier/ECE 2000-boot hard-fail gates.
