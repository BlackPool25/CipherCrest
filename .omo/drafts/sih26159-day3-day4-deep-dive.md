---
slug: sih26159-day3-day4-deep-dive
status: awaiting-approval
intent: clear
review_required: false
pending-action: write .omo/plans/sih26159-day3-day4-deep-dive.md
approach: Day3 lab parity hardening (lossy/weberblog, pre_tls_buffer, coverage) → Day3 analyzer scapy+tshark oracle with GREASE+JA4 rarity+early_data/ECH+opaque flag → Day4 validator Store/PolicyBuilder dual-store+SAN+weak+stapled OCSP+honesty → Day4 rules 23 (20+3 info-weighted) + score → banner 14/20. Conditional USE_STUB flip on ledger 🟢.
---

# Draft: sih26159-day3-day4-deep-dive

## Components (topology ledger)
<!-- Lock the SHAPE before depth. One row per top-level component that can succeed or fail independently. -->
<!-- id | outcome (one line) | status: active|deferred | evidence path -->

## Open assumptions (announced defaults)
<!-- Record any default you adopt instead of asking, so the user can veto it at the gate. -->
<!-- assumption | adopted default | rationale | reversible? -->


## Findings (cited - path:lines)
- lab/reassembler/reassemble.py:1-290 — 5-tuple seq buffering, reassemble_out_of_order True sorts by seq, overlap first-seen, gap flag, coverage_ratio, banner 220/* OK/+OK, STARTTLS Bennett keyword+220 Ready/OK Begin TLS, pre_tls_buffer via 220→0x16 0x03, per_flow aggregation. Clean 10 families all coverage 1.0 gap False overlap False (lab/LEDGER.md).
- lab/LEDGER.md — 10 families sha256 pinned, gaps: lossy/weberblog parity deferred to Day2+, jittered.pcap coverage 0.897 logged, pre_tls_buffer_len 138/171 for family-01.
- lab/manifest.json — family→cipher/kex/starttls ground truth, 10 ciphers distinct (family-01 ECDHE-RSA-AES128-GCM-SHA256 not reused).
- lab/reassembler/tests/test_reassembly.py — F1>95% vs tshark both prefs TRUE, banner discriminator 220/* OK, coverage_clean, jitter not yet lossy.
- analyzer/ — EMPTY except LEDGER.md+__init__.py; parse.py missing → Day3 create.
- validator/ — EMPTY except __init__.py; chain.py missing → Day4 create.
- assessment/ — EMPTY except LEDGER.md; rules.py missing → Day4 create.
- shared/schemas.py:1-120 — Pydantic v2 strict extra=forbid, TLS/Cert/Assessment/FlowVerdict, honesty invariant is_tls13_opaque→leaf_present False + 15 fields None + ocsp=opaque hard-fail via model_validator. FlowVerdict uses Literal smtp/imap/pop3 + upgrade/implicit/none/stripped (differs from plan's SMTP/IMAP/POP3+implicit/starttls-upgrade — additive freeze risk).
- shared/schemas.json — generated title FlowVerdict, $defs TLS/Cert/Finding/Assessment/PolicyDecision, must equal live model_json_schema.
- shared/ja4_rarity.py — GREASE_VALUES 0x0a0a..0xfafa, filter_grease(), get_ja4_rarity() offline censys_top_ja4.json, 1-percentile, no live fetch.
- shared/data/censys_top_ja4.json — exists (few MB top 1000), offline rarity source.
- shared/tests/test_schema.py — fixtures via model_validate_json, opaque invariant tamper raises ValidationError, schemas.json drift check.
- shared/progress.md — Day2 gated (reassembler coverage, manifest, mockdns, CoverageTable), Day2→Day3 handoff USE_STUB=True → conditional flip when reassembled/*.bin 🟢.
- searxng: scapy layers tls handshake supports TLS13ClientHello/TLSClientHello, supported_versions 0x2b, extensions 0x002a early_data (RFC8446 §8), GREASE harmonization needed; cryptography.io Store/PolicyBuilder Rust-backed, PolicyBuilder time+max_depth+store, ServerVerifier DNSName/IPAddress, VerificationError.

## Decisions (with rationale)
- D1 Exit gate B Core+Honest Banner (MCQ): delivers deterministic chain + is_tls13_opaque banner 14/20 triple citation M03+M18+M22 + lineage manifest→reassembled→features vs tshark + per-version coverage table R1-R8. Policy prelude deferred to stretch per cut-order 0.
- D2 Parser A tshark-oracle+scapy fallback: tshark -T json -o tcp.desegment_tcp_streams:TRUE -o tcp.reassemble_out_of_order:TRUE -o tls.desegment_ssl_records:TRUE -o tls.desegment_ssl_application_data:TRUE as harness; scapy TLSClientHello/TLSServerHello + extensions for importable pipeline; dpkt rejected (fork maintenance). Offline bundle keeps tshark optional but CI requires it else skip.
- D3 Validator B Strict+Stapled OCSP Parse: Store/PolicyBuilder dual-store (trust /etc/ssl/certs/ca-certificates.crt + privateCA.pem), BasicConstraints/KeyUsage/ExtKeyUsage/pathLen, SAN RFC7817 dNSName vs mail.lab.local CN fallback Medium, 1.3 honesty hard-fail, plus stapled OCSP parse ClientHello status_request 0x0005 + CertificateStatus type 22 via cryptography.x509.ocsp.load_der_ocsp_response → ocsp_stapled_status good/revoked/unknown/not-stapled/opaque. No fetch.
- D4 Rule A Info-weighted 1pt: 15b pre_tls_buffer_len>0→High else Info, 16b MX/MTA-STS/DANE via mockdns offline fixture → Info, 16c early_data replayable→Medium else Info. Critical25 High15 Medium7 Low3 Info1 → risk_score cap100 thresholds ≥40 Critical ≥25 High ≥10 Medium. Dashboard 23 cols 20 scored (color) +3 greyed info.
- D5 Parity A Strict F1>95% lossy+weberblog: tc netem 2% + jittered.pcap (0.897) + weberblog 20 flows full + stripping-history 3flow, both tshark prefs TRUE, hard-fail not annex. Anti-tautology: every gate proves lossy/weberblog+limbo not fixtures alone.
- D6 JA4+flip A Shared rarity+conditional flip: GREASE filter via shared/ja4_rarity.filter_grease → FoxIO ja4 python canonical hash → ja4_rarity via censys lookup 1-percentile; lab jitter_slices.py samples rarity 0..1 variance; USE_STUB=False only when shared/progress.md 🟢 + reassembled/*.bin + coverage_ratio + pre_tls_buffer logged.
- D7 Schema mismatch risk: shared/schemas.py uses Literal weak/medium/strong+ upgrade/implicit/none/stripped vs plan spec weak/acceptable/strong+ implicit/starttls-upgrade/cleartext/failed-upgrade. Decision: freeze as-is Day3 (additive-only per CODEOWNER), map in rules via alias table, document drift in LEDGER, fix via Additive Optional fields if needed Day5 — no breaking rename Day3-4.

## Scope IN
- Day3: lab jitter lossy pcaps + tshark parity F1>95% lossy/weberblog + pre_tls_buffer_injection_possible + stripping 3flow history + analyzer parse.py complete + JA4 rarity + fixtures 7 new family json.
- Day4: validator chain.py+san_check.py dual-store + SAN + weak checks + stapled OCSP + limbo/badssl prec>90% stratified + rules.py 23 checks spec-cited + score.py + dashboard honesty banner + CoverageTable per-port 23×3.

## Scope OUT (Must NOT have)
- No ML training (ECOD/XGB/Platt/calibration) — Day7-10 lean.
- No quarantine.py/siem.py/arf.py/QuarantineConsole/milter mockdns live beyond fixture read (cut-order 0 stretch).
- No live OCSP/CRL fetch, no PQC/DANE claim, no mail body decrypt, no mock 1.3 cert.
- No schema breaking rename of TLS.cipher_strength / FlowVerdict.starttls_mode literals.
- No B1-B5 per-split annex tables (Day10).

## Open questions
- None — all 6 MCQ forks answered (A/B/A/A/A/A). Proceed to approval.

## Approval gate
status: awaiting-approval
approver: user
next-action: on explicit 'approve' → node scaffold-plan.mjs sih26159-day3-day4-deep-dive --clear (without --draft-only) → write .omo/plans/sih26159-day3-day4-deep-dive.md with full Todos + Final verification wave
