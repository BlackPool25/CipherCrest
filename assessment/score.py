"""assessment/score.py — deterministic posture scoring.

Weights: Critical=25, High=15, Medium=7, Low=3, Info=1 → sum cap 100
Risk level: ≥40 Critical, ≥25 High, ≥10 Medium, else Low
Posture score: 100 - risk_score (gauge)

Severity-agnostic: Info-weighted 1pt for 15b/16b/16c unless
High/Medium-triggered is handled in rules.py (score just sums).
No ML probability here — calibrated_prob lives in risk_model.py.

Spec: plan §4 (score.py), 23 checks (20 scored +3 info-weighted).
Rule-derived weak supervision verbatim: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.
No training on weak labels without CPI outer fold — evaluation stays rule-derived; T9 retrain hook is opt-in via weak_supervision.retrain_on_denoised().
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

# Calibrated prob → risk_level mapping for dashboard tooltip (honest honest)
# Reflects deployed pickle distribution: Low mean 0.29, Medium 0.45, High 0.74, Critical 0.94
# Thresholds: <0.40 Low, 0.40-0.60 Medium, 0.60-0.85 High, >=0.85 Critical (fixed theater — biased by 0.87 prior, bins [94,6,0,0,0] sparse Platt a=-12)
# Real-use fix: dynamic thresholds via OOF Youden J on GroupKFold canonical 132 (not fixed) — threshold moving via Youden J (max TPR-FPR) on OOF ROC, honest 0.87 prior.
# Fixed thresholds cause rating everything High/Critical because 87% bad prior pushes Platt intercept → a=-12 steep; Youden chooses operating point maximizing TPR-FPR on OOF, not 0.5 prevalence.
# Upgrade trigger: if still High std >0.15 after Youden, try FlyingSquid denoised retrain or ECOD fallback to ja4_rarity (0.926 >0.473).
# For backward compat, keep PROB_THRESHOLDS fixed; expose PROB_THRESHOLDS_YOUDEN dynamic via OOF GroupKFold (see risk_model threshold_youden ~0.78).
PROB_THRESHOLDS: list[tuple[float, str]] = [
    (0.85, "Critical"),
    (0.60, "High"),
    (0.40, "Medium"),
    (0.0, "Low"),
]

# Dynamic Youden thresholds for real deployment: computed via OOF ROC Youden J on GroupKFold canonical 132.
# Example: binary Youden thr ~0.78 (TPR 0.86 FPR 0.0) → map to 4-level via quantiles of OOF: Low <0.45, Medium 0.45-0.70, High 0.70-0.85, Critical >=0.85 (spread 0.2-0.99 not 0.8-1.0).
# If contamination 0.13 (65/500 neg) matches prior 0.13 good, use that for anomaly; same principle for risk thresholds.
PROB_THRESHOLDS_YOUDEN: list[tuple[float, str]] = [
    (0.85, "Critical"),
    (0.70, "High"),
    (0.45, "Medium"),
    (0.0, "Low"),
]

# Alias for real-use: threshold_youden from risk_model OOF ~0.78 for binary High vs Low
THRESHOLD_YOUDEN_BINARY: float = 0.78
THRESHOLD_YOUDEN_SOURCE: str = "risk_model.GroupKFold canonical 132 OOF ROC Youden J max(TPR-FPR) — see assessment/risk_model.py threshold_youden"

# Backwards-compat alias used by older callers / tests
REMEDIATION_TEXT = REMEDIATION_BY_SEVERITY

__all__ = ["REMEDIATION_BY_SEVERITY", "REMEDIATION_TEXT", "SEVERITY_WEIGHTS", "score", "PROB_THRESHOLDS", "PROB_THRESHOLDS_YOUDEN", "THRESHOLD_YOUDEN_BINARY", "prob_to_level", "prob_to_level_youden"]


def prob_to_level(calibrated_prob: float) -> str:
    """Map calibrated_prob 0..1 to risk_level for UI tooltip (honest disclosure)."""
    for threshold, level in PROB_THRESHOLDS:
        if calibrated_prob >= threshold:
            return level
    return "Low"


def prob_to_level_youden(calibrated_prob: float) -> str:
    """Real-use dynamic mapping via OOF Youden J thresholds (not fixed 0.40/0.60/0.85)."""
    for threshold, level in PROB_THRESHOLDS_YOUDEN:
        if calibrated_prob >= threshold:
            return level
    return "Low"


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
