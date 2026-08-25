from __future__ import annotations

from typing import Literal

from shared.schemas import Finding, PolicyDecision

_ALIAS: dict[str, str] = {
    "allow": "deliver",
    "flag": "deliver_banner",
    "quarantine": "quarantine",
    "block": "hold_incident",
}

_RISK_THRESHOLDS: list[tuple[int, str]] = [
    (40, "Critical"),
    (25, "High"),
    (10, "Medium"),
    (0, "Low"),
]

BANNER_YELLOW = "Weak transport — do not send sensitive data"
BANNER_RED = "Critical — blocked / hold_incident"


def to_spec_action(action: Literal["allow", "quarantine", "block", "flag"]) -> str:
    return _ALIAS[action]


def _risk_level_from_score(risk_score: int) -> str:
    for thr, lvl in _RISK_THRESHOLDS:
        if risk_score >= thr:
            return lvl
    return "Low"


def _extract_dict(verdict) -> dict | list:
    if isinstance(verdict, list):
        return verdict
    if isinstance(verdict, dict):
        return verdict
    try:
        return verdict.model_dump()  # type: ignore
    except Exception:
        try:
            return dict(verdict)  # type: ignore
        except Exception:
            return {}


def _is_secure_strong(verdict_dict: dict) -> bool:
    tls = verdict_dict.get("tls") or {}
    cert = verdict_dict.get("cert") or {}
    return (
        tls.get("cipher_strength") == "strong"
        and tls.get("is_deprecated") is False
        and tls.get("fs_flag") is True
        and cert.get("leaf_present") is True
        and cert.get("chain_valid") is True
        and cert.get("san_match") is True
        and cert.get("is_expired") is False
        and not cert.get("sigalg_weak")
        and not cert.get("keysize_weak")
        and (cert.get("pubkey_bits") or 2048) >= 2048
        and not cert.get("is_tls13_opaque")
    )


def _build_policy(
    risk_score: int,
    risk_level: str,
    findings: list[Finding],
    top: Finding | None,
    is_opaque: bool,
    has_low_conf: bool,
) -> PolicyDecision:
    if risk_level not in ("Critical", "High", "Medium", "Low"):
        risk_level = _risk_level_from_score(risk_score)
    if risk_level == "Low":
        action: Literal["allow", "quarantine", "block", "flag"] = "allow"
        banner = None
    elif risk_level == "Medium":
        action = "flag"
        banner = BANNER_YELLOW
    elif risk_level == "High":
        if has_low_conf:
            action = "flag"
            banner = BANNER_YELLOW
        else:
            action = "quarantine"
            banner = BANNER_YELLOW
    else:
        action = "block"
        banner = BANNER_RED
    if is_opaque and risk_level == "Low":
        action = "allow"
        banner = None
    siem = risk_level
    if top is not None:
        disp = f"{risk_level} risk_score {risk_score} top {top.check}: {top.evidence}"
    else:
        disp = f"{risk_level} risk_score {risk_score} top none"
    if has_low_conf:
        disp += " low conf"
    return PolicyDecision(
        action=action,
        disposition_reason=disp,
        banner_text=banner,
        quarantine_id=None,
        siem_severity=siem,
        arf_report_id=None,
    )
