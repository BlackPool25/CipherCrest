"""Fixture-passthrough reassembler stub — Day1-2.

Returns validated FlowVerdict objects from shared/fixtures/*.json
without invoking real reassembly. Family-filtered by pcap_path substring;
fallback returns all fixtures if no family matches.
"""
from __future__ import annotations

import glob
import pathlib

from shared.schemas import FlowVerdict


def _load_fixture(path: str) -> FlowVerdict:
    return FlowVerdict.model_validate_json(pathlib.Path(path).read_text(encoding="utf-8"))


def reassemble(pcap_path: str) -> list[FlowVerdict]:
    """Return fixture FlowVerdicts matching pcap_path family or all if unknown.

    Family matching is substring-based: if "family-01" in pcap_path, return
    only family-01.json, etc. Fallback (unknown path) returns all
    shared/fixtures/family-*.json fixtures (3 on Day1, 10+ after Day2).

    Always returns validated FlowVerdict objects via model_validate_json,
    never raw dicts. If fixtures are missing, returns [].
    """
    # Collect all fixture paths
    fixture_paths = sorted(glob.glob("shared/fixtures/family-*.json"))
    if not fixture_paths:
        # Fallback: try absolute relative to project root
        proj_fixtures = pathlib.Path(__file__).resolve().parents[1] / "fixtures"
        fixture_paths = sorted(str(p) for p in proj_fixtures.glob("family-*.json"))
    if not fixture_paths:
        return []

    # Family-filter: check known families in pcap_path
    for fp in fixture_paths:
        stem = pathlib.Path(fp).stem  # e.g. family-01
        if stem in pcap_path:
            try:
                return [_load_fixture(fp)]
            except Exception:
                return []

    # Fallback: return all fixtures
    results: list[FlowVerdict] = []
    for fp in fixture_paths:
        try:
            results.append(_load_fixture(fp))
        except Exception:
            continue
    return results
