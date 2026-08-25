# EVIDENCE — SecureMailScope (aggregator)

> See Day snapshots: `eval/EVIDENCE_Day2.md` (Day2 handoff), `eval/EVIDENCE_Day3.md` (lab parity lossy/weberblog F1>95% + jittered <1.0 + pre_tls_buffer + triple), `eval/EVIDENCE_Day4.md` (cipher>98% + JA4 GREASE + limbo/badssl prec>90% stratified + 23 weak 100% + 14/20 REAL + 23×3).

## Linear lineage

| Day | Snapshot | Gate |
|-----|----------|------|
| Day2 | eval/EVIDENCE_Day2.md | scaffold + fixtures 10 families + vite 156k |
| Day3 | eval/EVIDENCE_Day3.md | STARTTLS F1>95% lossy/weberblog + jittered 0.897 logged + pre_tls 171 + triple same 5-tuple 127.0.0.11:54330 |
| Day4 | eval/EVIDENCE_Day4.md | cipher>98% 9/9 + JA4 GREASE 16 + limbo 1.000 CABF/private + badssl 1.000 + 23 weak 100% + 14/20 REAL + 23×3 CoverageTable 20 scored+3 info-greyed |

Harness: `pytest shared/tests/test_schema.py lab/reassembler/tests/test_reassembly.py lab/reassembler/tests/test_coverage_ratio.py lab/reassembler/tests/test_history_triple.py analyzer/tests/test_handshake.py analyzer/tests/test_ja4.py shared/tests/test_ja4_grease.py shared/tests/test_ja4_rarity.py validator/tests/test_chain_limbo.py validator/tests/test_badssl.py assessment/tests/test_rules.py api/tests/test_api.py -q` → 91 passed 1 skipped.

Triple citation M03+M18+M22 + R1-R8 per-version in Day3 §4 / Day4 §7.
