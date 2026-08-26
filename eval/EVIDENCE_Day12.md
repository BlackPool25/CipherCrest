# EVIDENCE Day12 — LOFAM stump honest

WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

See LEAKAGE_REPORT.md for leakage gap analysis. Calibration 2-bin n_val=12 counts [6, 6] caveat Platt unpowered at n_cal<20. LOFAM 0.58 EnvCV 0.67 gap 0.09 PASS-bounded Brier 0.117 < base 0.243 CI [0.088,0.146] non-overlap 2000-boot family-level. WEAK SUPERVISION verbatim + p/n 0.5 disclosed.
