## 2026-08-25 Task 1 decisions

- Chose secure_strong override for family-01 Low: reason — lean gateway must not quarantine known-good strong TLS1.2 valid cert; keeps F1 Low allow per happy scenario while preserving deterministic thresholds for others. Alternative was hard-coding flow_id, rejected for domain reasoning.
- Chose to downgrade Critical→High when low-conf evidence present: reason — single-flow stripped lacks history triple per R4, must be flag not block; matches spec "single High low-conf → flag/banner not block".
- Chose is_tls13_opaque alone never holds via has_high check: reason — opaque with only Info findings stays Low allow, per R1 honesty invariant; prevents holding on encrypted cert alone.
- Chose banner yellow for Medium/High, red for Critical, None for Low: reason — spec says yellow Medium / red Critical, High shares yellow.
- Chose to keep quarantine_id None lean: reason — no quarantine table per Must NOT have, deferred to Day10 stretch.

