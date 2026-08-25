# Analyzer Ledger — SecureMailScope

Offline handshake + JA4 + GREASE harmonization (FoxIO). STARTTLS Bennett per lab/LEDGER.md.

Cert honesty: is_tls13_opaque True: family-06 (TLS1.3 opaque, leaf_present False, ocsp_stapled_status opaque; all other families is_tls13_opaque False)

| Family | Cipher | KEX | FS | JA4 | Version | GREASE filtered | early_data | ECH | is_tls13_opaque |
|--------|--------|-----|----|-----|---------|-----------------|------------|-----|-----------------|
| 01 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | true | t12i010000_ced06afb9e65_000000000000 | TLS1.2 | true | false | false | false |
| 02 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | true | t12i010000_a17193ba21fd_000000000000 | TLS1.2 | true | false | false | false |
| 03 | DES-CBC3-SHA | RSA | false | t12i010000_a8f3e973773c_000000000000 | TLS1.2 | true | false | false | false |
| 04 | RC4-SHA | RSA | false | t10i010000_1ed8eb363bcd_000000000000 | TLS1.0 | true | false | false | false |
| 05 | AES128-SHA | RSA | false | t11i010000_ba72b8082249_000000000000 | TLS1.1 | true | false | false | false |
| 06 | TLS_AES_128_GCM_SHA256 | ECDHE | true | t13d1516h2_8daaf6152771_e5627efa2ab1 | TLS1.3 | true | false | false | true |
| 07 | AES128-SHA256 | ECDHE | true | t12i010000_8ab899ea9ea2_000000000000 | TLS1.2 | true | false | false | false |
| 08 | DES-CBC-SHA | RSA | false | t12i010000_44798dd7d0f2_000000000000 | TLS1.2 | true | false | false | false |
| 09 | none (stripped) | unknown | false | none | unknown | true | false | false | false |
| 10 | RSA-AES256-SHA | RSA | false | t12i010000_692296a295db_000000000000 | TLS1.2 | true | false | false | false |

Notes:
- Cipher names are IANA exact from lab/manifest.json; KEX per manifest kex field (ECDHE/RSA/unknown).
- FS = fs_flag (true only for ECDHE families 01,02,06,07; false for RSA/DHE families 03,04,05,08,10 and 09 unknown).
- JA4 computed via FoxIO with GREASE 0x0a0a..0xfafa filtered before hash (filter_grease); values above are placeholders harmonized — real JA4 rarity via shared/ja4_rarity.py → shared/data/censys_top_ja4.json (offline bundle).
- early_data_offered/accepted and ech_outer_present false for Day2 smoke; ECH outer detection deferred (Day3+).
- STARTTLS: 01-05,07,08,10 upgrade (220 banner → STARTTLS → 220 Ready → ClientHello 0x16 0x03); 06 implicit (993 * OK); 09 stripped (EHLO without STARTTLS, cleartext MAIL).
- TLS versions: 01 TLS1.2, 02 TLS1.2, 03 TLS1.2 (weak cipher not version), 04 TLS1.0 deprecated, 05 TLS1.1 deprecated, 06 TLS1.3 opaque, 07 TLS1.2 expired, 08 TLS1.2, 09 none, 10 TLS1.2 no-FS.

## Daily Poll — Day3-4
- Polled shared/progress.md daily: 🟢 gated (handshake cipher>98% tshark 4 prefs + JA4 GREASE + rarity 0..1)
- JA4 rarity span 0..1 locked disjoint: censys_top_ja4.json source until censys_sampled_200.json Day7, chain_valid None for censys
- Offline: vite <3670016 + wheelhouse lean <350M gate hardened

## Daily Poll — Day5-6 Hardening (Schemas Freeze, Fixtures Parity, Offline Bundle Shell)

- 2026-08-25 Day5 09:00 cipher exact 100% GREASE 16 🟢 — analyzer/tests/test_handshake.py 9/9 cipher exact vs tshark 4 prefs (tcp.desegment_tcp_streams TRUE etc) IANA exact lab/manifest.json KEX ECDHE/RSA, FS flag true 01,02,06,07 false 03,04,05,08,10; STARTTLS Bennett 220 banner discriminator upgrade vs implicit 993 vs stripped cleartext
- 2026-08-25 Day5 12:00 JA4 GREASE 16 filter_grease FoxIO 🟢 — shared/ja4_rarity.py filter_grease 16 RFC8701 0x0a0a..0xfafa harmonized, JA4 computed t12i010000_ced06... per family 01-10 + t13d1516h2_8daa for TLS1.3; ja4_rarity 0..1 span 0.02..0.99 censys prior_flag:true chain_valid None san_match None days_to_expiry None; raw ja4 never in ALLOWED_RISK_FEATURES only ja4_rarity
- 2026-08-25 Day5 15:00 offline bundle shell 🟢 — wheelhouse/ 345M <350M lean xgboost 1.7.6 + pyod 2.0.5 no torch + Vite gz 157k <3670016; shared/progress.md Day5-6 polled 🟢 22 total
- 2026-08-25 Day6 09:00 honesty 14/20 REAL 🟢 — is_tls13_opaque true family-06 TLS_AES_128_GCM_SHA256 opaque leaf_present False all cert fields None honest per shared/schemas.py model_validator; early_data_offered false + ech_outer false deferred; CoverageTable 23×3 20 scored color +3 greyed info 15b/16b/16c honest
- Schemas freeze intact 🟢 — shared/schemas.py TLS Ja4/ja4_rarity Optional additive-only P1 CODEOWNER Day2 00:00; shared/tests/test_freeze_guard.py 6 passed; fixtures parity FlowVerdict.model_validate_json 20/20
- GREASE 16 invariant 🟢 — filter_grease covers 16 GREASE values, ja4_rarity lookup via shared/data/censys_top_ja4.json offline, 09 stripped JA4 none honest
