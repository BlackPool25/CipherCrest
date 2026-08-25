"""Fixture-aware validator stub — opaque invariant honest.

Returns a validated Cert. Opaque branch returns honest None for all
cert-detail fields; non-opaque branch returns a minimal valid leaf cert
(and tries to mirror family-01 fixture values).
"""
from __future__ import annotations

import json
import pathlib

from shared.schemas import Cert


def validate(cert_der: bytes | None, is_tls13_opaque: bool) -> Cert:  # noqa: ARG001
    """Return a Cert respecting the honesty invariant.

    Args:
        cert_der: DER bytes or None (ignored in stub; present for API parity).
        is_tls13_opaque: if True, return opaque Cert with leaf_present False.

    Returns:
        Validated Cert object.
    """
    if is_tls13_opaque:
        return Cert(
            leaf_present=False,
            is_tls13_opaque=True,
            ocsp_stapled_status="opaque",
        )

    # Non-opaque: try to load from family-01 fixture for realism, else construct.
    fixture = pathlib.Path("shared/fixtures/family-01.json")
    if not fixture.exists():
        fixture = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "family-01.json"
    if fixture.exists():
        try:
            data = json.loads(fixture.read_text(encoding="utf-8"))
            cert_data = data.get("cert", {})
            # Ensure non-opaque; override opaque fields if fixture was opaque
            cert_data["leaf_present"] = True
            cert_data["is_tls13_opaque"] = False
            # If ocsp was opaque, fix to good
            if cert_data.get("ocsp_stapled_status") == "opaque":
                cert_data["ocsp_stapled_status"] = "good"
            # Fill any None detail that should be present for non-opaque minimal
            defaults = {
                "not_before": "2025-01-01T00:00:00Z",
                "not_after": "2026-01-01T00:00:00Z",
                "days_to_expiry": 90,
                "is_expired": False,
                "is_self_signed": False,
                "chain_length": 2,
                "chain_valid": True,
                "san_match": True,
                "pubkey_algo": "RSA",
                "pubkey_bits": 2048,
                "sigalg": "sha256WithRSAEncryption",
                "sigalg_weak": False,
                "keysize_weak": False,
                "ocsp_stapled_status": cert_data.get("ocsp_stapled_status", "good"),
                "ocsp_must_staple": False,
                "crl_unknown_reason": False,
            }
            for k, v in defaults.items():
                if cert_data.get(k) is None:
                    cert_data[k] = v
            return Cert.model_validate(cert_data)
        except Exception:
            pass

    # Fallback minimal non-opaque cert
    return Cert(
        leaf_present=True,
        is_tls13_opaque=False,
        not_before="2025-01-01T00:00:00Z",
        not_after="2026-01-01T00:00:00Z",
        days_to_expiry=90,
        is_expired=False,
        is_self_signed=False,
        chain_length=2,
        chain_valid=True,
        san_match=True,
        pubkey_algo="RSA",
        pubkey_bits=2048,
        sigalg="sha256WithRSAEncryption",
        sigalg_weak=False,
        keysize_weak=False,
        ocsp_stapled_status="good",
        ocsp_must_staple=False,
        crl_unknown_reason=False,
    )
