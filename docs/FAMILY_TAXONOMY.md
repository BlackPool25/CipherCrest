# Family Taxonomy — 40 Curated Coherent Families (SIH26159 T4)

> **Purpose:** Curated taxonomy for the 40-family clean laboratory matrix. Replaces the synthetic
> `synth_random` incoherence (legacy TLS with modern ciphers and vice versa) with a coherent,
> IANA-mapped, per-TLS-spec table. Generates 40 distinct pcaps without random incoherence
> (T4 blocks Wave-2 data scaling).

## 1. Scope and Quality Disclosure

- **500-env quality (labs proxy):** 40 curated distinct families × pcap realism (Bennett STARTTLS dialect,
  4-pref reassembler, CER file parity, GREASE-filtered IANA ciphers) are the quality unit, **not** jittered
  duplicates. Jitter slices (`lab/scripts/jitter_slices.py` — shuffle+GREASE+sigalg+expiry+`ja4_rarity` on
  7 jittered families: 02,03,04,05,07,08,10) are explicitly *not* distinct families and MUST NOT be counted
  as families. Distinctness is enforced by the tuple `(TLS version, cipher, KEX, cert, STARTTLS)` — jitter
  preserves all five, taxonomy varies at least one.
- **Coherence invariant:** `TLS version == 0x0304  <=>  cipher ∈ {0x1301, 0x1302, 0x1303}`.
   No legacy-TLS with modern ciphers, no modern-TLS with legacy weak ciphers,
   no unknown cipher fallback. Every cipher maps to an IANA registry hex (Section 3).
- **400 families are NOT from live Internet MX scan** — this spec is docs-only (canon per `lab/manifest.json`
  + `lab/pcaps/*.pcap` + `lab/reassembler`), never a live MX/MTA-STS/DANE fetch.
- **Tracer fidelity:** STARTTLS Bennett dialect per protocol (IMAP `CAPABILITY → STARTTLS → 220 Go ahead`,
  POP3 `CAPA → STLS → +OK`, SMTP `EHLO → STARTTLS → 220`), `pre_tls_buffer_len` injection window,
  MTA-STS/DANE fixtures (offline `shared/data/mta-sts-fixture.json`, `dane-tlsa-fixture.json`), and
  0-RTT/ECH extensions (`0x002a`) are first-class columns.

## 2. Grouping Overview (A–J = 40)

| Group | Label | Rows | Contract / RFC |
|-------|-------|------|----------------|
| **A** | Deprecated version | 3 | TLS1.0 RC4/RC4-MD5, TLS1.1 AES128, TLS1.2 outdated SWEET32 (RFC8996, CVE-2016-2183) |
| **B** | Weak cipher / KEX | 4 | DES (56-bit) rsa1024, 3DES SWEET32 64-bit, RC4-MD5, RSA-no-FS chain-incomplete |
| **C** | Cert weak | 5 | expired SHA1, self-signed, rsa1024, chain-incomplete, MD5/weak sigalg |
| **D** | Stripping (Bennett) | 2 | single-flow High (low-conf) vs history 3-flow 2 prior success→stripped Critical (Bennett et al. §4.2) |
| **E** | Bennett per-protocol | 4 | 143 IMAP STARTTLS, 110 POP3 STLS, 993 IMAPS implicit, 587 Submission (RFC3207, RFC2595) |
| **F** | Pre-TLS injection | 3 | `pre_tls_buffer_len` 0 / 32 / 171 bytes between `220 Ready` and `ClientHello 0x16 0x03` |
| **G** | MTA-STS / DANE | 4 | MTA-STS enforce/testing/none + TLSA `3 1 1` / `2 0 1` (RFC8461, RFC6698) |
| **H** | 0-RTT / ECH | 3 | TLS1.3 `early_data` extension `0x002a` + ECH outer (RFC8446 §8, draft-ietf-tls-esni) |
| **I** | KEX / FS edge | 2 | ECDHE FS=True vs RSA/DHE FS=False (`kex`/`fs_flag` edge, RFC8446) |
| **J** | Reserved / coverage | 10 | Fills 40 distinct tuples; honest-opaque on 993 implicit, extra weak/strong combos; all coherent |

Total: **3+4+5+2+4+3+4+3+2+10 = 40** distinct `(TLS, cipher, KEX, cert, STARTTLS)` tuples.

## 3. IANA Cipher Suite Registry (18 curated, GREASE-filtered)

All taxonomy `Cipher` values appear below. Hex values are IANA-assigned (RFC8446 App B, IANA TLS Parameters).
GREASE values `0x0a0a … 0xfafa` (16 values, RFC8701) are filtered before `JA4`/`hash` (`shared/ja4_rarity.py`).

| Hex | Cipher Name | Min TLS | Notes |
|-----|-------------|---------|-------|
| `0x1301` | TLS_AES_128_GCM_SHA256 | TLS1.3 | AEAD, PFS, strong |
| `0x1302` | TLS_AES_256_GCM_SHA384 | TLS1.3 | AEAD, PFS, strong |
| `0x1303` | TLS_CHACHA20_POLY1305_SHA256 | TLS1.3 | AEAD, PFS, strong |
| `0xC02F` | ECDHE-RSA-AES128-GCM-SHA256 | TLS1.2 | ECDHE, AEAD, strong |
| `0xC030` | ECDHE-RSA-AES256-GCM-SHA384 | TLS1.2 | ECDHE, AEAD, strong |
| `0xC02B` | ECDHE-ECDSA-AES128-GCM-SHA256 | TLS1.2 | ECDHE, AEAD, strong |
| `0xC02C` | ECDHE-ECDSA-AES256-GCM-SHA384 | TLS1.2 | ECDHE, AEAD, strong |
| `0x009C` | RSA-AES128-GCM-SHA256 | TLS1.2 | RSA (no FS), AEAD |
| `0x009D` | RSA-AES256-GCM-SHA384 | TLS1.2 | RSA (no FS), AEAD |
| `0x002F` | AES128-SHA | TLS1.0 | RSA, no AEAD, weak |
| `0x0035` | AES256-SHA | TLS1.0 | RSA, no AEAD, weak |
| `0x000A` | DES-CBC3-SHA | TLS1.0 | 3DES SWEET32 64-bit, weak |
| `0x0005` | RC4-SHA | TLS1.0 | RC4 deprecated, weak |
| `0x0004` | RC4-MD5 | TLS1.0 | RC4-MD5 weak |
| `0x0009` | DES-CBC-SHA | TLS1.0 | single-DES 56-bit, weak |
| `0x003C` | AES128-SHA256 | TLS1.2 | medium (SHA256, no FS if RSA) |
| `0x002C` | ECDHE-ECDSA-AES128-SHA | TLS1.0 | ECDHE, CBC, medium/weak |
| `0x009E` | DHE-RSA-AES128-GCM-SHA256 | TLS1.2 | DHE, AEAD, strong but DHE config-sensitive |
| — | none | none | cleartext / stripped (no handshake) |

> `0xC024`/`0xC028` (ECDHE-ECDSA AES variants) alias to the deprecated CBC class above and map via
> `0x002C` family; no unknown cipher entries remain after this taxonomy.

## 4. 40-Core Table A–J (coherent per Section 1 invariant)

Legend: `TLS` version string, `IANA` hex, `KEX` key-exchange, `Cert` leaf type, `STARTTLS` (`upgrade`/`implicit`/`cleartext`),
`Buf` = `pre_tls_buffer_len` (bytes), `MTA-STS` mode, `TLSA` selector (`usage selector matching`), `Ext` = extensions.

| Family | Group | TLS | Cipher | IANA | KEX | Cert | STARTTLS | Port | Flag | PreTLSBuf | MTA-STS | TLSA | Ext | Description |
|--------|-------|-----|--------|------|-----|------|----------|------|------|-----------|---------|------|-----|-------------|
| family-01 | A | TLS1.0 | RC4-SHA | 0x0005 | RSA | rsa2048 | upgrade | 110 | Critical | 0 | none | — | — | Deprecated TLS1.0 RC4-SHA POP3 Bennett (A1) |
| family-02 | A | TLS1.1 | AES128-SHA | 0x002F | RSA | rsa2048 | upgrade | 587 | High | 0 | none | — | — | Deprecated TLS1.1 AES128-SHA (A2) |
| family-03 | A | TLS1.2 | DES-CBC3-SHA | 0x000A | RSA | rsa2048 | upgrade | 143 | High | 0 | none | — | — | Deprecated TLS1.2 3DES SWEET32 (A3) |
| family-04 | B | TLS1.2 | DES-CBC-SHA | 0x0009 | RSA | rsa1024 | upgrade | 587 | Critical | 0 | none | — | — | B1 DES single 56-bit + rsa1024 |
| family-05 | B | TLS1.2 | DES-CBC3-SHA | 0x000A | ECDHE | rsa2048 | upgrade | 143 | High | 0 | none | — | — | B2 3DES SWEET32 64-bit (CBC) |
| family-06 | B | TLS1.2 | RC4-MD5 | 0x0004 | RSA | rsa2048 | upgrade | 110 | Critical | 0 | none | — | — | B3 RC4-MD5 deprecated |
| family-07 | B | TLS1.2 | AES256-SHA | 0x0035 | RSA | chain-incomplete | upgrade | 587 | High | 0 | none | — | — | B4 RSA-no-FS AES256-SHA chain-incomplete |
| family-08 | C | TLS1.2 | AES128-SHA256 | 0x003C | ECDHE | expired | upgrade | 587 | Critical | 0 | none | — | — | C1 expired SHA1withRSA cert |
| family-09 | C | TLS1.2 | AES128-SHA | 0x002F | RSA | selfsigned | upgrade | 587 | Critical | 0 | none | — | — | C2 self-signed leaf |
| family-10 | C | TLS1.2 | AES128-SHA256 | 0x003C | ECDHE | rsa1024 | upgrade | 25 | Critical | 0 | none | — | — | C3 rsa1024 keysize_weak (25) |
| family-11 | C | TLS1.2 | RSA-AES128-GCM-SHA256 | 0x009C | RSA | chain-incomplete | upgrade | 587 | High | 0 | none | — | — | C4 chain-incomplete intermediate missing |
| family-12 | C | TLS1.2 | RC4-MD5 | 0x0004 | RSA | md5-weak | upgrade | 587 | Critical | 0 | none | — | — | C5 MD5 sigalg weak (md5WithRSA) |
| family-13 | D | none | none | — | unknown | none | cleartext | 587 | High | 0 | none | — | — | D1 single-flow stripped High (low-conf Bennett) |
| family-14 | D | none | none | — | unknown | none | cleartext | 25 | Critical | 0 | enforce | — | — | D2 history 3-flow 2 prior STARTTLS success→stripped Critical (port 25) |
| family-15 | E | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | 0xC02F | ECDHE | rsa2048 | upgrade | 143 | PASS | 0 | none | — | — | E1 Bennett 143 STARTTLS IMAP |
| family-16 | E | TLS1.0 | RC4-SHA | 0x0005 | RSA | selfsigned | upgrade | 110 | Critical | 0 | none | — | — | E2 Bennett 110 POP3 STLS RC4 selfsigned |
| family-17 | E | TLS1.3 | TLS_AES_128_GCM_SHA256 | 0x1301 | ECDHE | p256 | implicit | 993 | PASS | 0 | none | — | — | E3 Bennett 993 IMAPS implicit TLS1.3 |
| family-18 | E | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | 0xC030 | ECDHE | p256 | upgrade | 587 | PASS | 0 | none | — | — | E4 Bennett 587 Submission STARTTLS |
| family-19 | F | TLS1.2 | AES128-SHA256 | 0x003C | ECDHE | rsa2048 | upgrade | 587 | Medium | 0 | none | — | — | F1 pre_tls_buffer_len 0 clean |
| family-20 | F | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | 0xC02F | ECDHE | rsa2048 | upgrade | 587 | Medium | 32 | none | — | — | F2 pre_tls_buffer_len 32 injection probe |
| family-21 | F | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | 0xC030 | ECDHE | rsa2048 | upgrade | 587 | Critical | 171 | none | — | — | F3 pre_tls_buffer_len 171 injection active |
| family-22 | G | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | 0xC02F | ECDHE | p256 | upgrade | 25 | PASS | 0 | enforce | 3 1 1 | — | G1 MTA-STS enforce + TLSA 3 1 1 (DANE-EE SPKI) |
| family-23 | G | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | 0xC030 | ECDHE | p256 | upgrade | 25 | PASS | 0 | testing | 2 0 1 | — | G2 MTA-STS testing + TLSA 2 0 1 DANE-TA |
| family-24 | G | TLS1.2 | AES128-SHA256 | 0x003C | ECDHE | rsa2048 | upgrade | 25 | High | 0 | none | — | — | G3 MTA-STS none (opportunistic) |
| family-25 | G | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | 0xC02B | ECDHE | rsa2048 | upgrade | 25 | High | 0 | enforce | 3 1 1 | — | G4 MTA-STS enforce TLSA 3 1 1 mismatch (chain invalid) |
| family-26 | H | TLS1.3 | TLS_AES_128_GCM_SHA256 | 0x1301 | ECDHE | p256 | upgrade | 587 | Medium | 0 | none | — | early_data 0x002a | H1 0-RTT early_data extension |
| family-27 | H | TLS1.3 | TLS_AES_256_GCM_SHA384 | 0x1302 | ECDHE | p256 | upgrade | 587 | Medium | 0 | none | — | ECH+early_data | H2 ECH outer + 0-RTT |
| family-28 | H | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | 0x1303 | ECDHE | p256 | upgrade | 587 | Medium | 0 | none | — | early_data | H3 CHACHA20 0-RTT |
| family-29 | I | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | 0xC02B | ECDHE | p256 | upgrade | 587 | PASS | 0 | none | — | — | I1 KEX ECDHE FS=True (fs_flag true) p256 |
| family-30 | I | TLS1.2 | RSA-AES128-GCM-SHA256 | 0x009C | RSA | rsa2048 | upgrade | 587 | High | 0 | none | — | — | I2 KEX RSA FS=False (no forward secrecy) |
| family-31 | J | TLS1.3 | TLS_AES_128_GCM_SHA256 | 0x1301 | ECDHE | rsa2048 | implicit | 993 | PASS | 0 | none | — | — | J01 implicit TLS1.3 rsa2048 993 strong |
| family-32 | J | TLS1.3 | TLS_AES_256_GCM_SHA384 | 0x1302 | ECDHE | rsa2048 | implicit | 993 | PASS | 0 | none | — | — | J02 implicit TLS1.3 993 strong |
| family-33 | J | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | 0x1303 | ECDHE | selfsigned | upgrade | 587 | High | 0 | none | — | — | J03 TLS1.3 CHACHA20 self-signed edge |
| family-34 | J | TLS1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 | 0xC02C | ECDHE | p256 | upgrade | 25 | PASS | 0 | none | — | — | J04 ECDSA P-256 strong SMTP 25 |
| family-35 | J | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | 0x009E | DHE | rsa2048 | upgrade | 587 | Medium | 0 | none | — | — | J05 DHE-RSA AEAD medium/strong |
| family-36 | J | TLS1.2 | RSA-AES256-GCM-SHA384 | 0x009D | RSA | rsa2048 | upgrade | 587 | High | 0 | none | — | — | J06 RSA-AES256 noFS medium |
| family-37 | J | TLS1.0 | AES256-SHA | 0x0035 | RSA | expired | upgrade | 587 | Critical | 0 | none | — | — | J07 TLS1.0 AES256 legacy expired |
| family-38 | J | TLS1.1 | ECDHE-ECDSA-AES128-SHA | 0x002C | ECDHE | selfsigned | upgrade | 587 | High | 0 | none | — | — | J08 TLS1.1 ECDHE-ECDSA-AES128-SHA self-signed |
| family-39 | J | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | 0xC02B | ECDHE | p256 | upgrade | 143 | PASS | 0 | none | 3 1 1 | — | J09 ECDSA IMAP STARTTLS Bennett |
| family-40 | J | TLS1.2 | AES128-SHA256 | 0x003C | ECDHE | chain-incomplete | upgrade | 587 | High | 0 | testing | 2 0 1 | — | J10 MTA-STS testing fallback chain-incomplete |

> Coherence proof: validator enforces TLS 1.3 rows (17,26,27,28,31,32,33) use only
> `0x1301`/`0x1302`/`0x1303`; no legacy weak ciphers on modern version.
> Version/cipher coherence is enforced by `lab/scripts/validate_families.py`.

## 5. Validation

```bash
python lab/scripts/validate_families.py --taxonomy docs/FAMILY_TAXONOMY.md
# 40 coherent families validated
python lab/scripts/synth_families.py --count 40 --seed 0 --dry-run 2>&1 | grep "UNKNOWN"  # 0
pytest assessment/tests/test_features.py -q
```

## 6. References

- Bennett et al., STARTTLS stripping (CVE-2011-0411, CVE-2021-38502 §4.2)
- RFC8701 GREASE (16 values), RFC8446 TLS1.3 `0x1301-1303`, RFC8996 deprecates TLS1.0/1.1, RFC8461 MTA-STS, RFC6698 TLSA
- Lab STARTTLS Bennett: `lab/docker-compose.yml` + `lab/scripts/synth_families.py` (`TLSRecord`/`TLSClientHello`)
- Validator: `lab/scripts/validate_families.py` enforces IANA mapping (18 ciphers) + version/cipher coherence + uniqueness

*Generated: 2026-08-27 — Wave1 T4 blocks Wave2 data scaling; live Internet MX MUST NOT be queried for taxonomy creation.*
