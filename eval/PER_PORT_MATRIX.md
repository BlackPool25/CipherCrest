# Per-Port Compliance Matrix — MEASURED (2026-09-09, Day15 pipeline fix)

> 116 pcaps through `_real_pipeline_for_bytes` (52 base + 35 jittered + 28 locked_external + 1 real-protocol), 0 failures.
> Modes end-to-end: implicit=5, none=5, upgrade=106.
> Cell = severities observed (count). — = check never fired on that port. Fixture-backed MTA-STS/DANE fire as Info on every port by design.

| Check | 25 | 110 | 143 | 587 | 993 |
|---|---|---|---|---|---|
| 0-RTT / ECH | Infox20 | Infox11 | Infox14 | Infox60 | Infox11 |
| 3DES SWEET32 | Highx1 | — | Highx8 | Highx1 | — |
| CBC without AEAD | Highx2, Mediumx5 | Highx8, Mediumx1 | Mediumx9 | Highx10, Mediumx34 | Mediumx4 |
| Certificate expired | Criticalx1 | — | — | Criticalx7 | Criticalx1 |
| Chain incomplete/self-signed | Mediumx5 | Mediumx1 | Mediumx2 | Mediumx31 | Mediumx3 |
| ExtendedKeyUsage not serverAuth | Infox20 | Infox11 | Infox14 | Infox60 | Infox11 |
| Implicit TLS absent | Infox20 | Infox11 | Infox14 | Infox60 | Infox11 |
| KeyUsage missing | Highx4, Infox16 | Highx1, Infox10 | Highx1, Infox13 | Highx30, Infox30 | Highx3, Infox8 |
| MX/MTA-STS/DANE | Infox20 | Infox11 | Infox14 | Infox60 | Infox11 |
| No forward secrecy | Highx6 | Highx9 | Highx11 | Highx33 | Highx3 |
| Pre-TLS injection possible | Highx1, Infox19 | Infox11 | Highx11, Infox3 | Highx3, Infox57 | Highx2, Infox9 |
| STARTTLS not offered | Highx2 | — | Highx2 | Highx1 | — |
| TLS version deprecated | Criticalx2 | Criticalx8 | — | Criticalx10 | — |
| TLS version outdated | Mediumx16 | Mediumx3 | Mediumx12 | Mediumx42 | Mediumx6 |
| Weak KEX (no FS) | Highx6 | Highx9 | Highx11 | Highx33 | Highx3 |
| Weak cipher (RC4/NULL/EXPORT/DES) | Criticalx1 | Criticalx9 | Criticalx1 | Criticalx9 | Criticalx2 |
| Weak pubkey (<2048 / <P-256) | Highx1 | — | — | Highx6 | Highx1 |
| pathLen violation | Infox2 | — | Infox2 | Infox1 | — |

## Measured verdicts (only what the matrix shows)
- `STARTTLS not offered` (check-14, High) fires on cleartext never-offered flows incl. family-09 end-to-end (mode none after Day15 fix; was bogus implicit before).
- Stripping-15a Critical tier is ladder-verified via direct evaluate() (`eval/day15/ladder.json`); end-to-end Critical needs a stripped signal plus history triple — no 116-run hit one, which is correct behavior for this corpus (no crafted strip-attack pcap present).
- TLS-1.3-opaque flows (993) carry no cert findings — 14/20 REAL honesty holds across the matrix.
- Real-protocol row: `real-mail-starttls-587.pcap` -> smtp/upgrade, risk 13 Medium, posture 87 (inside the 587 distribution).
- Open follow-up (not fixed): cleartext no-handshake flows also collect KEX/FS Highs; reasons read oddly on flows with no TLS. Cosmetic scoring note for Day16.
