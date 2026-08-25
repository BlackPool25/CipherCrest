"""assessment/score.py — deterministic posture scoring.

Weights: Critical=25, High=15, Medium=7, Low=3, Info=1 → sum cap 100
Risk level: ≥40 Critical, ≥25 High, ≥10 Medium, else Low
Posture score: 100 - risk_score (gauge)

Severity-agnostic: Info-weighted 1pt for 15b/16b/16c unless
High/Medium-triggered is handled in rules.py (score just sums).
No ML probability here — calibrated_prob lives in risk_model.py.

Spec: plan §4 (score.py), 23 checks (20 scored +3 info-weighted).
"""

from __future__ import annotations

from shared.schemas import Finding

# ── weights (must match plan §4 — do not invent) ──
SEVERITY_WEIGHTS: dict[str, int] = {
    "Critical": 25,
    "High": 15,
    "Medium": 7,
    "Low": 3,
    "Info": 1,
}

# thresholds for risk_level (inclusive lower bounds)
_RISK_THRESHOLDS: list[tuple[int, str]] = [
    (40, "Critical"),
    (25, "High"),
    (10, "Medium"),
    (0, "Low"),
]

# Remediation text per severity tier — exported for rules.py / policy.py
REMEDIATION_BY_SEVERITY: dict[str, str] = {
    "Critical": "Immediate action required: upgrade to TLS 1.3 with ECDHE AES128-GCM, rotate to RSA-2048/SHA-256, provision missing intermediate, and fix STARTTLS stripping (RFC8996 §4, RFC5280 §6).",
    "High": "High-priority fix: replace weak cipher/KEX (RC4/DES/3DES/RSA-no-FS), fix SAN mismatch, complete chain, add keyUsage/serverAuth, enforce MTA-STS/DANE where applicable.",
    "Medium": "Medium-priority hardening: renew cert expiring <30d, disable TLS 1.0/1.1, bound 0-RTT ticket_age / add anti-replay, align with Mozilla intermediate profile.",
    "Low": "Low-priority hygiene: align cipher suite order and sigalgs with Mozilla intermediate, verify posture_score gauge, schedule next scan.",
    "Info": "Informational: no direct risk weight (1pt posture). Track for coverage — e.g. pre-TLS buffer absent, MX/MTA-STS/DANE present, ECH outer noted. No remediation required unless escalated by rules.py.",
}

# Backwards-compat alias used by older callers / tests
REMEDIATION_TEXT = REMEDIATION_BY_SEVERITY

__all__ = ["REMEDIATION_BY_SEVERITY", "REMEDIATION_TEXT", "SEVERITY_WEIGHTS", "score"]


def _risk_level(risk_score: int) -> str:
    """Map risk_score 0..100 to risk_level via plan thresholds."""
    for threshold, level in _RISK_THRESHOLDS:
        if risk_score >= threshold:
            return level
    return "Low"  # unreachable (0 covers)


def score(findings: list[Finding]) -> tuple[int, str, int]:
    """Deterministic posture scoring.

    Args:
        findings: list of Finding (severity determines weight).

    Returns:
        (risk_score 0..100, risk_level str, posture_score 0..100)

    - Severity weights: Critical25 High15 Medium7 Low3 Info1 sum cap 100.
    - risk_level: ≥40 Critical, ≥25 High, ≥10 Medium, else Low.
    - posture_score = 100 - risk_score.
    - Empty list → 0 Low 100.
    - Severity-agnostic: caller (rules.py) decides Info vs High for 15b/16b/16c.
    """
    total = 0
    for f in findings:
        # Finding.severity is Literal validated by pydantic; fallback 0 for safety
        total += SEVERITY_WEIGHTS.get(f.severity, 0)
    risk_score = min(total, 100)
    risk_level = _risk_level(risk_score)
    posture_score = 100 - risk_score
    return risk_score, risk_level, posture_score
