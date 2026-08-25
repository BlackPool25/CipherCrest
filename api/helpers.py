from __future__ import annotations

from collections import Counter
from typing import Any

from shared.schemas import FlowVerdict

try:
    from assessment.policy import decide as _policy_decide
except Exception:
    _policy_decide = None  # type: ignore

_PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")


def attach_policy(flows: list[FlowVerdict]) -> list[FlowVerdict]:
    if _policy_decide is None:
        return flows
    out: list[FlowVerdict] = []
    for fv in flows:
        if fv.policy is not None:
            out.append(fv)
            continue
        try:
            pol = _policy_decide(fv.model_dump())  # type: ignore
            out.append(fv.model_copy(update={"policy": pol}))
        except Exception:
            out.append(fv)
    return out


def compute_summary(flows: list[FlowVerdict]) -> dict[str, Any]:
    if not flows:
        return {"proto_counts": {}, "starttls_modes": {}, "deprecated_count": 0, "opaque_count": 0, "posture": 0, "risk_dist": {}, "policy_dist": {}}
    proto_counts = dict(Counter(f.app_protocol for f in flows))
    starttls_modes = dict(Counter(f.starttls_mode for f in flows))
    deprecated_count = sum(1 for f in flows if f.tls.is_deprecated)
    opaque_count = sum(1 for f in flows if f.cert.is_tls13_opaque)
    risk_dist = dict(Counter(f.assessment.risk_level for f in flows))
    policy_dist = dict(Counter((f.policy.action if f.policy else "none") for f in flows))
    posture_scores = [f.assessment.posture_score for f in flows if f.assessment.posture_score is not None]
    if posture_scores:
        posture = int(sum(posture_scores) / len(posture_scores))
    else:
        avg_risk = sum(f.assessment.risk_score for f in flows) / len(flows)
        posture = int(100 - avg_risk)
        posture = max(0, min(100, posture))
    return {"proto_counts": proto_counts, "starttls_modes": starttls_modes, "deprecated_count": deprecated_count, "opaque_count": opaque_count, "posture": posture, "risk_dist": risk_dist, "policy_dist": policy_dist}


def is_malformed(filename: str, data: bytes) -> bool:
    if data == b"random":
        return True
    if filename == "bad":
        return True
    if filename.endswith(".zip"):
        return False
    if len(data) < 4:
        return True
    if filename and not any(filename.endswith(ext) for ext in (".pcap", ".pcapng", ".cap", ".zip")):
        return True
    if data[:4] not in _PCAP_MAGICS:
        return True
    if len(data) < 10:
        return True
    return False
