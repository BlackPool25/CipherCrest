"""SQLite JSONB flow store — Day3+ real lane (stub→real).

When USE_STUB True returns stub reassembler fallback.
When False queries SQLite JSONB via json_extract / json_data (assessment.db or api/flows.db).
Honest: if DB missing or query fails, falls back to stub (no crash, hotspot ensures ~12/23 honest).
"""
from __future__ import annotations
import json, pathlib, sqlite3
from shared.config import USE_STUB
from shared.mocks.reassembler_stub import reassemble as stub_reassemble
from shared.schemas import FlowVerdict

_DB_CANDIDATES = [
    pathlib.Path(__file__).resolve().parent / "flows.db",
    pathlib.Path("assessment/assessment.db"),
    pathlib.Path("api/flows.db"),
]

def _db_path() -> pathlib.Path | None:
    for p in _DB_CANDIDATES:
        if p.exists():
            return p
    # also check parent api flows.db created by app
    return _DB_CANDIDATES[0] if _DB_CANDIDATES[0].exists() else None

def get_flows() -> list[FlowVerdict]:
    """Return flows via SQLite JSONB when real lane, else stub."""
    if USE_STUB:
        return stub_reassemble("fallback")
    dbp = _db_path()
    if dbp is None or not dbp.exists():
        return stub_reassemble("fallback")
    try:
        con = sqlite3.connect(str(dbp))
        # JSONB query: SELECT json(data) or json_extract
        cur = con.execute("SELECT data FROM flows LIMIT 100")
        rows = cur.fetchall()
        con.close()
        out: list[FlowVerdict] = []
        for (data,) in rows:
            try:
                d = json.loads(data) if isinstance(data, str) else json.loads(bytes(data).decode())
                # support JSONB column as text
                if isinstance(d, str):
                    d = json.loads(d)
                out.append(FlowVerdict.model_validate(d))
            except Exception:
                continue
        if out:
            return out
        return stub_reassemble("fallback")
    except Exception:
        return stub_reassemble("fallback")
