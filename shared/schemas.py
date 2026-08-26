from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class TLS(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

    version: Literal["TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3", "unknown"]
    is_deprecated: bool
    cipher_suite: str
    cipher_strength: Literal["strong", "medium", "weak", "unknown"]
    is_aead: bool
    kex: Literal["ECDHE", "RSA", "DHE", "unknown"]
    fs_flag: bool
    ja4: str | None = Field(default=None)
    ja4_rarity: float | None = Field(default=None, ge=0, le=1, description="Population rarity 0..1 from offline shared/data/censys_top_ja4.json")
    ja4s: str | None = Field(default=None)
    early_data_offered: bool = Field(default=False)
    early_data_accepted: bool = Field(default=False)
    psk_offered: bool = Field(default=False)
    ticket_age: int | None = Field(default=None)
    ech_outer_present: bool = Field(default=False)
    handshake_success: bool
    alert_after_starttls: bool


class Cert(BaseModel):
    """Certificate honesty invariant.

    Invariant: if is_tls13_opaque == True → leaf_present == False and
    all cert-detail fields (not_before, not_after, days_to_expiry,
    is_expired, is_self_signed, chain_length, chain_valid, san_match,
    pubkey_algo, pubkey_bits, sigalg, sigalg_weak, keysize_weak,
    ocsp_must_staple, crl_unknown_reason) must be None (or remain at
    default None). Only ocsp_stapled_status may be 'opaque' in the
    opaque branch; all other cert fields are honest None to avoid
    fabricating X.509 data when TLS 1.3 encrypts the Certificate
    message.
    """

    model_config = ConfigDict(extra='forbid', strict=True)

    leaf_present: bool
    is_tls13_opaque: bool
    not_before: str | None = Field(default=None)
    not_after: str | None = Field(default=None)
    days_to_expiry: int | None = Field(default=None)
    is_expired: bool | None = Field(default=None)
    is_self_signed: bool | None = Field(default=None)
    chain_length: int | None = Field(default=None)
    chain_valid: bool | None = Field(default=None)
    san_match: bool | None = Field(default=None)
    pubkey_algo: str | None = Field(default=None)
    pubkey_bits: int | None = Field(default=None)
    sigalg: str | None = Field(default=None)
    sigalg_weak: bool | None = Field(default=None)
    keysize_weak: bool | None = Field(default=None)
    ocsp_stapled_status: Literal["good", "revoked", "unknown", "opaque", "not_stapled"]
    ocsp_must_staple: bool | None = Field(default=None)
    crl_unknown_reason: bool | None = Field(default=None)

    @model_validator(mode="after")
    def _check_honesty_invariant(self) -> Cert:
        if self.is_tls13_opaque and self.leaf_present:
            raise ValueError("honesty invariant violated: is_tls13_opaque==True requires leaf_present==False")
        if self.is_tls13_opaque:
            # In opaque branch, cert detail fields must be None (honest).
            # Enforce at least pubkey_bits and san_match are None; extend to
            # all detail fields for strict honesty per docstring.
            opaque_forbidden = {
                "not_before": self.not_before,
                "not_after": self.not_after,
                "days_to_expiry": self.days_to_expiry,
                "is_expired": self.is_expired,
                "is_self_signed": self.is_self_signed,
                "chain_length": self.chain_length,
                "chain_valid": self.chain_valid,
                "san_match": self.san_match,
                "pubkey_algo": self.pubkey_algo,
                "pubkey_bits": self.pubkey_bits,
                "sigalg": self.sigalg,
                "sigalg_weak": self.sigalg_weak,
                "keysize_weak": self.keysize_weak,
                "ocsp_must_staple": self.ocsp_must_staple,
                "crl_unknown_reason": self.crl_unknown_reason,
            }
            non_none = [k for k, v in opaque_forbidden.items() if v is not None]
            if non_none:
                raise ValueError(
                    f"honesty invariant violated: is_tls13_opaque==True requires cert fields None, "
                    f"but got non-None for {', '.join(non_none)}"
                )
        return self


class Finding(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

    check: str
    severity: Literal["Critical", "High", "Medium", "Low", "Info"]
    spec: str
    evidence: str
    remediation: str


class Assessment(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

    findings: list[Finding]
    risk_level: Literal["Critical", "High", "Medium", "Low"]
    risk_score: int = Field(ge=0, le=100)
    anomaly_score: float | None = Field(default=None)
    anomaly_honest_score: float | None = Field(default=None)
    posture_score: int | None = Field(default=None, ge=0, le=100)
    calibrated_prob: float | None = Field(default=None, ge=0, le=1)


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

    action: Literal["allow", "quarantine", "block", "flag"]
    disposition_reason: str
    banner_text: str | None = Field(default=None)
    quarantine_id: str | None = Field(default=None)
    siem_severity: str | None = Field(default=None)
    arf_report_id: str | None = Field(default=None)


class FlowVerdict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

    flow_id: str
    environment_id: str | None = Field(default=None)
    capture_epoch: str | None = Field(default=None)
    source_id: str | None = Field(default=None)
    # lineage coverage — additive Optional per R1-R8, keeps extra='forbid' honest
    coverage_ratio: float | None = Field(default=None, ge=0, le=1)
    pre_tls_buffer_len: int | None = Field(default=None, ge=0)
    pre_tls_buffer_injection_possible: bool | None = Field(default=None)
    app_protocol: Literal["smtp", "imap", "pop3"]
    starttls_mode: Literal["upgrade", "implicit", "none", "stripped"]
    tls: TLS
    cert: Cert
    assessment: Assessment
    policy: PolicyDecision | None = Field(default=None)
