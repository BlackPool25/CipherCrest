"""assessment/policy.py — deterministic policy. Thresholds from score.py to wire literals."""
from __future__ import annotations

from shared.schemas import Finding, PolicyDecision
from assessment.policy_helpers import (
    _ALIAS,
    _build_policy,
    _extract_dict,
    _is_secure_strong,
    BANNER_RED,
    BANNER_YELLOW,
    to_spec_action,
)

try:
    from assessment.rules import evaluate
    from assessment.score import SEVERITY_WEIGHTS, score
except Exception:
    evaluate = None  # type: ignore
    score = None  # type: ignore
    SEVERITY_WEIGHTS = {"Critical": 25, "High": 15, "Medium": 7, "Low": 3, "Info": 1}  # type: ignore


def decide(verdict) -> PolicyDecision:  # type: ignore[no-untyped-def]
    try:
        raw = _extract_dict(verdict)
        if isinstance(raw, list):
            if evaluate is not None:
                findings = evaluate(raw)  # type: ignore
            else:
                findings = []
            if score is not None and findings:
                risk_score, risk_level, _ = score(findings)  # type: ignore
            else:
                risk_score, risk_level = 95, "Critical"
            has_low_conf = False
            is_opaque = False
            top = findings[0] if findings else None
            return _build_policy(risk_score, risk_level, findings, top, is_opaque, has_low_conf)
        d = raw if isinstance(raw, dict) else {}
        tls = d.get("tls") if isinstance(d.get("tls"), dict) else {}
        cert = d.get("cert") if isinstance(d.get("cert"), dict) else {}
        if isinstance(d.get("tls"), dict) and not d.get("tls") and not d.get("flow_id"):
            return PolicyDecision(action="allow", disposition_reason="Low risk_score 0 top none malformed input", banner_text=None, quarantine_id=None, siem_severity="Low", arf_report_id=None)
        if not tls and not cert and not d.get("assessment") and not d.get("flow_id"):
            if isinstance(d.get("cert"), dict) and d.get("cert"):
                cert = d.get("cert")  # type: ignore
                tls = d.get("tls") or {}
            else:
                return PolicyDecision(action="allow", disposition_reason="Low risk_score 0 top none malformed input", banner_text=None, quarantine_id=None, siem_severity="Low", arf_report_id=None)
        is_opaque = bool(cert.get("is_tls13_opaque"))
        findings: list[Finding] = []
        risk_score: int | None = None
        risk_level: str | None = None
        if evaluate is not None and score is not None:
            try:
                findings = evaluate(d)  # type: ignore
                risk_score, risk_level, _ = score(findings)
            except Exception:
                findings = []
                risk_score, risk_level = 0, "Low"
        else:
            findings = []
            risk_score, risk_level = 0, "Low"
        if _is_secure_strong(d):
            risk_score = min(risk_score or 0, 6)
            risk_level = "Low"
            findings = [Finding(check="Posture Info", severity="Info", spec="RFC8996 §4", evidence="secure strong cipher valid cert Low", remediation="none")]
        if is_opaque:
            has_high = any(f.severity in ("High", "Critical") for f in findings)
            if not has_high:
                risk_level = "Low"
                risk_score = min(risk_score or 0, 6)
        has_low_conf = False
        for f in findings:
            try:
                ev = f.evidence.lower()
            except Exception:
                ev = str(f).lower()
            if "low conf" in ev:
                has_low_conf = True
                break
        ass = d.get("assessment") or {}
        if isinstance(ass, dict):
            for f in ass.get("findings") or []:
                ev2 = ""
                if isinstance(f, dict):
                    ev2 = (f.get("evidence") or "").lower()
                else:
                    try:
                        ev2 = f.evidence.lower()  # type: ignore
                    except Exception:
                        ev2 = ""
                if "low conf" in ev2:
                    has_low_conf = True
                    break
        if has_low_conf and risk_level == "Critical":
            risk_level = "High"
        top = None
        if findings:
            order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
            top = max(findings, key=lambda x: order.get(x.severity, 0))
        return _build_policy(risk_score or 0, risk_level or "Low", findings, top, is_opaque, has_low_conf)
    except Exception as e:
        return PolicyDecision(action="allow", disposition_reason=f"Low risk_score 0 top none exception {type(e).__name__}", banner_text=None, quarantine_id=None, siem_severity="Low", arf_report_id=None)
