"""Placeholder db — Day1 returns stub flows; later assessment.db."""
from __future__ import annotations

from shared.mocks.reassembler_stub import reassemble
from shared.schemas import FlowVerdict


def get_flows() -> list[FlowVerdict]:
    """Return stub flows (fallback: all family fixtures)."""
    return reassemble("fallback")
