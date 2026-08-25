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
