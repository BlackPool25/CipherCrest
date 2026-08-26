# PS Traceability — SecureMailScope NTRO SIH26159

> Mapping PS requirement → family → rule check → evidence 8/8 + pkl + EVIDENCE section. R1 R2 R3 R4 R5 R6 R7 R8 coverage honest 14/20 REAL +3 info per-version. n_risk45 n_prior20 n_eff10 n_families10 disclosed everywhere. WEAK SUPERVISION verbatim preserved. Shared schemas freeze additive-only Day2 00:00 via shared/CONTRIBUTING.md CODEOWNERS P1.

## Traceability Matrix — PS requirement → family → rule check → evidence

| PS Requirement (Problem Statement) | Family (environment_id) | Rule Check (assessment/rules.py 23 =20 scored +3 info) | Evidence 8/8 + pkl + EVIDENCE section | CI Gate |
|---|---|---|---|---|
| STARTTLS stripping (CVE-2011-0411, CVE-2021-38502 §4.2, Bennett) — downgrade opportunistic TLS on 587/25 when MITM suppresses 250-STARTTLS | family-09__postfix3.9_loss0 cleartext stripped + triple history 3flow 127.0.0.11:54330 (2 upgraded → 1 stripped) | R4 (15a stripping) Critical cross-flow ≥3 flows, R5 (15b injection) pre_tls_buffer_len + injection_possible | eval/EVIDENCE_Day12.md gate1 STARTTLS F1>95% lossy/weberblog, lab/LEDGER.md pcap sha256 STARTTLS Bennett + pre_tls_buffer_len/injection_possible, lab/reassembler 4 prefs Bennett 220 vs * OK | 🟢 gated F1>95% |
| TLS version enforcement (RFC8996, RFC8446) — deprecated 1.0/1.1, outdated 1.2, implicit 1.3 opaque | family-04 TLS1.0 RC4, family-05 TLS1.1 selfsigned, family-02 TLS1.2 P-256, family-06 TLS1.3 implicit opaque | R1 TLS1.3 opaque honest (is_tls13_opaque), R2 CRL unknown, check1 TLS deprecated Critical, check2 outdated Medium | eval/EVIDENCE_Day12.md gate2 cipher 100% 9/9 GREASE 16 + gate7 per-port 25/587/993 14/20 REAL +1 opaque, lab/LEDGER.md Cipher (+GREASE sha384) + version, shared/schemas.py is_tls13_opaque invariant | 🟢 gated cipher 100% |
| Weak cipher/KEX downgrade (SWEET32 3DES, RC4, DES, CBC, no-FS) | family-03 DES-CBC3-SHA SWEET32, family-04 RC4-SHA, family-08 DES-CBC-SHA rsa1024, family-10 RSA no-FS chain-incomplete | check3 weak cipher Critical, check4 3DES High, check5 CBC Medium, check6 KEX High, check13 NoFS High | eval/EVIDENCE_Day12.md gate4 weak 100% 23-check, assessment/LEDGER.md Per-Family Policy Lineage, lab/LEDGER.md Cipher (+GREASE sha384) Cert | 🟢 gated weak 100% |
| X.509 chain validation (RFC5280 §6, Store/PolicyBuilder, SAN RFC7817) — expired/self-signed/weak-key/chain-incomplete, OCSP/CRL passive | family-07 expired SHA1, family-05 selfsigned, family-08 rsa1024, family-10 chain-incomplete, family-06 TLS1.3 opaque | R2 CRL unknown, R3 OCSP staple opaque, check9 expired Critical, check11 chain High, check12 SAN High, check7 keysize High | eval/EVIDENCE_Day12.md gate3 cert prec1.000 stratified CABF/private/badssl, validator/LEDGER.md dual-store prec1.000, shared/schemas.py honesty invariant | 🟢 gated prec>90% |
| Injection via pre_tls_buffer_len (Postfix CVE-2011-0411, GHSA-9j88 pipelined EHLO/AUTH before ClientHello 0x16 0x03) | family-01 138/171 High pipelined, family-09 0 Info stripped no 0x16 0x03 | R5 pre_tls_buffer_len heuristic High if >0 else Info 15b, check15b injection | lab/LEDGER.md pre_tls_buffer_len/injection_possible + coverage_ratio 1.0 jittered 0.95-1.0, lab/reassembler/reassemble.py _compute_pre_tls_buffer 220→0x16 0x03, lab/LEDGER.md family-01 138/171 | 🟢 gated coverage 1.0 |
| MX/MTA-STS/DANE filter (RFC8461, RFC7672) — opportunistic vs enforce, DANE TLSA | MX lab.local → mail.lab.local via mockdns | R6 fixture fallback, check16b MX Info enforce lane 16b | shared/data/mta-sts-fixture.json + dane-tlsa-fixture.json, lab/manifest.json MX=mail.lab.local, docs/TSHARK.md 2-lane offline primary | 🟢 gated 15b/16b info-greyed |
| 0-RTT early_data replay, ECH outer (RFC8446 §8, RFC9846 §8, RFC9849) | early_data_offered/psk/ticket_age + ech_outer_present toggles via PcapCustomizer | R7 0-RTT Medium if reusable else Info 16c, R8 ECH INFO only check16c, check16c 0-RTT + ECH INFO | analyzer/parse.py early_data 0x002a + ech_outer_present, assessment/rules.py 16c, dashboard PcapCustomizer toggles, eval/EVIDENCE_Day12.md R1-R8 annex | 🟢 gated 16c info |
| Mail lane hybrid single port 8000 — API enrich + dashboard + offline replay | 45 envs =10 base +35 jitter 7 families×5 slices, n_risk45 n_prior20 n_eff10 n_families10 | All 23 checks posture 0-100 policy decide allow/quarantine/block/flag | eval/EVIDENCE_Day12.md FINAL SYSTEM 8/8 gates 1-8 + eval/metrics.json + eval/LEAKAGE_REPORT.md gap 0.09 + eval/anomaly_baselines.json dual 0.47 vs 0.87 ja4 0.926 + TOP5 LOFAM stump + Platt 2-bin + pkls | 🟢 gated 8/8 |

## Family → Rule → Evidence quick map (10 families)

| Family | Cipher (+GREASE sha384) | Cert | Top rule → risk | Policy | Evidence |
|---|---|---|---|---|---|
| 01 | ECDHE-RSA-AES128-GCM-SHA256 (+GREASE) | rsa2048 | posture 94 Low → allow | Posture Info | gate1 F1>95% + gate5 JSON 20/20 |
| 02 | ECDHE-RSA-AES256-GCM-SHA384 P-256 (+GREASE sha384) | p256 | High quarantine 72 | R5 injection | lab/LEDGER 02×6 jitter |
| 03 | DES-CBC3-SHA (+GREASE sha384) | rsa2048 | Critical block 20 SWEET32 | check4 High | gate3 chain + gate4 weak |
| 04 | RC4-SHA TLS1.0 (+GREASE sha384) | rsa2048 | Critical 0 deprecated | check3 Critical | gate2 cipher 100% |
| 05 | AES128-SHA TLS1.1 (+GREASE sha384) | selfsigned | Critical 9 | check11 High | gate3 prec1.000 |
| 06 | TLS_AES_128_GCM_SHA256 x25519 TLS1.3 opaque (+GREASE) | opaque | Low allow 94 | R1 honest | is_tls13_opaque 14/20 REAL |
| 07 | AES128-SHA256 SHA1 (+GREASE sha384) | expired | High quarantine 65 | check9 Critical | family-07 expired SHA1 |
| 08 | DES-CBC-SHA rsa1024 (+GREASE sha384) | rsa1024 | Critical 10 DES+RSA1024 | check7 Critical | gate3 badssl |
| 09 | none cleartext stripped (+GREASE) | none | High flag 33 single low-conf | R4 single High | triple history 3flow Critical |
| 10 | RSA-AES256-SHA no-FS (+GREASE sha384) | chain-incomplete | Critical 35 | check13 NoFS | family-10 chain-incomplete |

## Evidence 8/8 + pkl + EVIDENCE section

**EVIDENCE 8/8:** `eval/EVIDENCE_Day12.md` FINAL SYSTEM 8/8 green — gate1 STARTTLS F1>95% lossy/weberblog vs tshark 4 prefs, gate2 cipher 100% 9/9 GREASE 16, gate3 cert prec1.000 stratified, gate4 weak 100% 23-check 20+3 info, gate5 JSON 20/20 + POST zip35→200 + GET <50ms + 14/20 REAL +3 info dashboard 23×3 ThreatMatrix, gate6 Brier+ECE 2-bin kernel 2000-boot Brier 0.117 <0.243 ECE 0.21 kernel 0.21 CI [0.18,0.24], gate7 LOFAM 0.58 EnvCV 0.67 gap 0.09 perm p 0.008 dual ECOD honest 0.47 vs inverted 0.87 ja4 0.926, gate8 NDCG tie Δ -0.005 CI [-0.045,0.183] κ 0.81/0.78 trio lineage manifest→reassembled→features vs tshark + per-port 25/587/993 R1-R8 14/20 REAL. Annex: eval/EVIDENCE_Day8.md Day9.md Day10.md kept.

**Models pkl:** `models/risk_clf.pkl` 0.16M Platt cv2 stump LOFAM TOP5 5-col vs 28 fallback, `models/anomaly.pkl` 15K ECOD honest 7c+20lab TOP5 27×5, `models/anomaly_honest.pkl` 15K copy, `models/anomaly_inverted.pkl` ablation 20c+7lab 0.87, `eval/calibration_curve.png` 750×600 2-bin [6,6], `eval/anomaly_baselines.json` 5 rows thresholds_honest 14.974, `eval/LEAKAGE_REPORT.md` gap table Model|p|n_eff|p/n|EnvCV|LOFAM|Gap|Honest? gap>0.10=memorise.

**EVIDENCE section:** Section 0 Gate 8/8, 1 Brier+ECE 2-bin kernel 2000-boot, 2 LOFAM vs EnvCV gap 0.09, 3 perm p 0.008, 4 dual ECOD honest 0.47 + ja4 0.926, 5 NDCG tie, 6 trio lineage 45 envs, 7 per-port R1-R8, 8 verification+history annex per eval/EVIDENCE_Day12.md 8 sections.

**R1-R8 mapping (per-version R1 R2 R3 R4 R5 R6 R7 R8):** R1 TLS1.3 opaque 1/20 vs 14/20 REAL, R2 CRL no fetch, R3 OCSP opaque, R4 stripping single vs triple, R5 pre_tls heuristic, R6 MX fixture, R7 0-RTT replay, R8 ECH outer — all 🟢 per assessment/LEDGER.md R1-R8 limitations annex.

**WEAK SUPERVISION verbatim:** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a. — in EVIDENCE header + dashboard AI footnote + LEDGER + metrics.json. n_risk45 n_prior20 n_eff10 n_families10 everywhere.

**Schemas freeze:** `shared/schemas.py` additive-only Day2 00:00 CODEOWNER P1 only per `shared/CONTRIBUTING.md` CODEOWNERS shared, `shared/tests/test_freeze_guard.py` 6 passed, breaking rename→ValidationError, new Optional only with version bump. `shared/schemas.json` == FlowVerdict.model_json_schema().

## Quick Start hybrid — single port 8000 via api/app.py StaticFiles

```bash
docker pull ghcr.io/ntro/securemailscope:demo
docker run --rm -p 8000:8000 ghcr.io/ntro/securemailscope:demo
# → http://localhost:8000/dashboard
docker compose --profile lab up -d  # mail lane postfix/dovecot/mocksender

bash scripts/turnup.sh --check  # dry-run models 276K wheelhouse 345M vite 157k tshark 4 prefs
WITH_DOCKER=1 bash scripts/turnup.sh  # full hybrid docker lab + API + dashboard
# api/app.py mount: app.mount("/dashboard", StaticFiles(directory=str(_dist), html=True), name="dashboard")
```

Hybrid image: `ghcr.io/ntro/securemailscope:demo` 3-stage Dockerfile (node:20-bookworm-slim → python:3.11-slim-bookworm + tshark) single port 8000 healthcheck `curl /health || /flows`, `.dockerignore` prunes wheelhouse/ .git/ jittered/.

## References

- Plan: `.omo/plans/sih26159-securemailscope-implementation.md` §0.3 quality Gantt + §8 cut order, `.omo/plans/sih26159-day10-day12-closure-audit-ux.md` 13 todos Wave1-4
- Ledgers: `lab/LEDGER.md` 45 rows pcap sha256 STARTTLS Bennett Cipher (+GREASE sha384) Cert tshark parity PASS coverage_ratio 1.0 jittered 0.95-1.0 pre_tls_buffer_len/injection_possible source_id n_eff 1, `assessment/LEDGER.md` TOP5 LOFAM stump honest + LEAKAGE_REPORT gap 0.09 + Platt 2-bin + dual ECOD honest 0.47 + ja4 0.926 + WEAK SUPERVISION verbatim, `shared/progress.md` Wave1-4 daily poll Clock|Agent|Milestone|Artifact|CI gate|Blocked on 🟢 gated
- Evidence: `eval/EVIDENCE_Day12.md` FINAL 8/8 + `eval/metrics.json` hard-fail via `shared/schemas_eval.py` n_risk45 n_prior20 n_eff10 + `eval/LEAKAGE_REPORT.md` + `eval/anomaly_baselines.json` + `eval/human_grades.csv` 20×3 κ0.81/0.78
- Docs: `lab/reassembler/README.md` 4-prefs, `docs/TSHARK.md` 2-lane offline primary vs oracle parity 4 prefs, `docs/LARGE_FILES.md` Releases 2GB/asset strategy
- Code: `api/app.py` mount `/dashboard` StaticFiles, `scripts/turnup.sh` WITH_DOCKER=1 hybrid, `shared/CONTRIBUTING.md` CODEOWNERS shared, `shared/schemas.py` freeze additive-only Day2 00:00
