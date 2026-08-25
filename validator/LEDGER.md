# Validator Ledger — Task 9 x509-limbo + badssl

## x509-limbo TrailofBits 2024 adapter
- Vectors: `validator/tests/vectors/limbo.json` 20 vectors (12 CABF + 8 private-CA)
- Adapter: `test_chain_limbo.py::_adapter_result` → `validate_chain(cert_path)` via `Store`+`PolicyBuilder` (no verify_directly)
- JSON shape: `{id, expected, stratum, cert_path, desc}` — mirrors TrailofBits x509-limbo JSON vectors
- All vectors are local lab/certs (no live fetch, no network)

## Stratified precision
- CABF stratum prec=1.000 acc=1.000 >0.9 (6 TP + 6 TN, 0 FP/FN)
- private-CA stratum prec=1.000 acc=1.000 — separate branch (2 valid via Store, 6 invalid)
- Gate: `prec>0.9` stratified CABF vs private-CA separate (not mixed) — enforced in `test_limbovectors` + `test_precision`

## badssl templates
- Templates: expired/self-signed/rsa1024/sha1 → lab/certs (expired.crt, selfsigned.crt, rsa1024.crt)
- Precision: bad=1.000 (8/8) good=1.000 (2/2) overall=1.000 >0.9 — `test_badssl.py::test_badssl_precision`

## Family gates
- Family07 expired Critical: `is_expired True` + `chain_valid False` (expired.crt notAfter past)
- Family08 rsa1024 DES Critical: `pubkey_bits 1024` + `keysize_weak True` severity High (DES cipher weak in manifest)
- Family10 chain-incomplete High (Medium if private CA): `chain_valid False` + `chain_incomplete_severity High` (issuer intermediate.lab.local not privateCA); Medium branch via `is_private_chain` check in chain.py
- Family06 opaque: `is_tls13_opaque True` + `leaf_present False` all fields None per `shared/tests/test_schema.py::test_opaque_invariant` — `ocsp_stapled_status opaque`

## Crypto invariant
- `cryptography` Store/PolicyBuilder used (build_server_verifier DNSName), not verify_directly — asserted via grep in tests
- No live fetch (no urllib/requests/http.client), no mock 1.3 cert synthesis
- Evidence: `.omo/evidence/task-9-sih26159-day3-day4-deep-dive.junit.xml` + `task-9-prec-report.log` + `task-9-badssl-prec-report.log`

## Verification
- `PYTHONPATH=. pytest validator/tests/test_chain_limbo.py validator/tests/test_badssl.py -q` → 21 passed
- `pytest -k precision -xvs | grep -E "prec.*>0.9|precision.*90%"` → CABF 1.000 + badssl 1.000
- `python -m validator.chain lab/certs/chain-incomplete.crt --json` → chain_valid False High
- `FlowVerdict family-06 opaque invariant` → is_tls13_opaque True leaf_present False pubkey_bits None

## Daily Poll — Day3-4
- Polled shared/progress.md daily: 🟢 gated (stratified prec 1.000 CABF/private-CA, badssl 1.000, opaque invariant)
- x509 Store/PolicyBuilder, no verify_directly, chain_valid None for opaque/TLS1.3 per honesty
- Offline bundle air-gap CI: --no-index --find-links wheelhouse validated

## Daily Poll — Day5-6 Hardening (Schemas Freeze, Fixtures Parity, Offline Bundle Shell)

- 2026-08-25 Day5-6 audit 🟢 — prec 1.000 CABF stratum 6 TP+6 TN 0 FP/FN + private-CA 1.000 (2 valid via Store 6 invalid) >0.9 stratified separate not mixed; badssl prec 1.000 (8/8 bad +2/2 good) overall 1.000 >0.9; x509 Store/PolicyBuilder build_server_verifier DNSName not verify_directly; no live fetch; family-07 expired True chain_valid False, family-08 rsa1024 DES Critical pubkey_bits 1024 keysize_weak High, family-10 chain-incomplete High Medium branch via is_private_chain, family-06 opaque is_tls13_opaque True leaf_present False pubkey_bits None ocsp_stapled_status opaque honest
- 2026-08-25 shared/progress.md polled daily 🟢 — Day5-6 7 rows + total 🟢 22 ≥20; schemas freeze additive-only P1 intact (shared/tests/test_freeze_guard.py 6 passed); offline bundle air-gap --no-index --find-links wheelhouse --only-binary validated wheelhouse 345M <350M lean no torch; Vite gz 157k <3670016
- Evidence: validator/tests/test_chain_limbo.py + test_badssl.py 21 passed prec>0.9; shell Day5-6 no new vectors, parity unchanged 1.000
- Crypto invariant 🟢 — cryptography Store/PolicyBuilder, no urllib/requests/http.client, no mock 1.3 cert synthesis, chain_valid None for opaque/TLS1.3 per honesty invariant shared/schemas.py model_validator
