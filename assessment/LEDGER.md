# Assessment Ledger — SecureMailScope

| Family | environment_id | TLS | Cipher | Findings (severity) | risk_score | risk_level | posture_score |
|--------|---------------|-----|--------|---------------------|------------|------------|---------------|
| 01 | family-01__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | TLS outdated M, Pre-TLS High, Implicit Info, MX Info, 0-RTT Info, KeyUsage Info, EKU Info | 27 | High | 73 |
| 02 | family-02__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | TLS outdated M, Pre-TLS High, Implicit Info, MX Info, 0-RTT Info, KeyUsage Info, EKU Info, pathLen Info | 28 | High | 72 |
| 03 | family-03__postfix3.9_loss0 | TLS1.2 | DES-CBC3-SHA | TLS outdated M, 3DES SWEET32 High, CBC Medium, KEX High, NoFS High, PreTLS High, Implicit Info, MX Info, 0-RTT Info, KeyUsage Info, EKU Info, pathLen Info | 80 | Critical | 20 |
| 04 | family-04__postfix3.9_loss0 | TLS1.0 | RC4-SHA | TLS deprecated Critical, Weak cipher Critical, CBC High, KEX High, NoFS High, PreTLS High, Implicit Info, MX Info, 0-RTT Info | 100 | Critical | 0 |
| 05 | family-05__postfix3.9_loss0 | TLS1.1 | AES128-SHA | TLS deprecated Critical, CBC High, KEX High, NoFS High, PreTLS High, Implicit Info, MX Info, 0-RTT Info | 91 | Critical | 9 |
| 06 | family-06__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | PreTLS Info, Implicit Info, MX Info, 0-RTT Info, KeyUsage Info, EKU Info | 6 | Low | 94 |
| 07 | family-07__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | TLS outdated M, CBC Medium, PreTLS High, Implicit Info, MX Info, 0-RTT Info | 35 | High | 65 |
| 08 | family-08__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | TLS outdated M, Weak cipher Critical, CBC Medium, KEX High, NoFS High, PreTLS High, Implicit Info, MX Info, 0-RTT Info | 90 | Critical | 10 |
| 09 | family-09__postfix3.9_loss0 | none | none | KEX High, NoFS High, STARTTLS High, Stripping High (low-conf), PreTLS Info, Implicit Info, MX Info, 0-RTT Info | 67 | Critical | 33 |
| 10 | family-10__postfix3.9_loss0 | TLS1.2 | RSA-AES256-SHA | TLS outdated M, CBC Medium, KEX High, NoFS High, PreTLS High, Implicit Info, MX Info, 0-RTT Info | 65 | Critical | 35 |

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
