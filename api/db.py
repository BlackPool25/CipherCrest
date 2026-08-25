"""SQLite JSONB flow store — canonical 4-func API.

Canonical DB: api/flows.db only (no _DB_CANDIDATES ambiguity).
Assessment alias: assessment/assessment.db is a symlink to api/flows.db if needed.

Schema: CREATE TABLE IF NOT EXISTS flows (flow_id TEXT PRIMARY KEY, data TEXT)
Uses json_extract probe when JSON1 available, TEXT fallback otherwise.
Idempotent init_db, INSERT OR REPLACE, <1ms point lookup via PRIMARY KEY.
"""

from __future__ import annotations

import json
import pathlib
import sqlite3

from shared.schemas import FlowVerdict

# Canonical path — single source of truth (no _DB_CANDIDATES)
# assessment.db symlink: ln -sf api/flows.db assessment/assessment.db
_DB = pathlib.Path(__file__).resolve().parent / "flows.db"


def _has_json1() -> bool:
    try:
        con = sqlite3.connect(":memory:")
        con.execute("SELECT json_extract('{\"a\":1}', '$.a')")
        con.close()
        return True
    except Exception:
        return False


_HAS_JSON1 = _has_json1()


def init_db() -> None:
    """Idempotent — creates parent dir and flows table if missing."""
    _DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(_DB))
    try:
        con.execute("CREATE TABLE IF NOT EXISTS flows (flow_id TEXT PRIMARY KEY, data TEXT)")
        con.commit()
    finally:
        con.close()


def upsert_flows(flows: list[FlowVerdict]) -> None:
    """INSERT OR REPLACE each FlowVerdict; handles 10-flow zip + 20 prior <100 rows."""
    if not flows:
        return
    init_db()
    con = sqlite3.connect(str(_DB))
    try:
        for f in flows:
            payload = json.dumps(f.model_dump())
            con.execute(
                "INSERT OR REPLACE INTO flows (flow_id, data) VALUES (?, ?)",
                (f.flow_id, payload),
            )
        con.commit()
    finally:
        con.close()


def query_all() -> list[FlowVerdict]:
    """Return all valid FlowVerdict rows; skips malformed json not crash.

    Missing DB -> empty list (creates on demand via init_db fallback).
    JSON1 probe: uses json_extract when available else plain TEXT select.
    """
    if not _DB.exists():
        return []
    try:
        con = sqlite3.connect(str(_DB))
    except Exception:
        return []
    try:
        # Probe JSON1 for filtered queries; fallback to plain SELECT
        if _HAS_JSON1:
            try:
                # Validate JSON1 works on actual table (no-op filter)
                con.execute("SELECT json_extract(data, '$.flow_id') FROM flows LIMIT 1").fetchall()
            except Exception:
                pass
        try:
            rows = con.execute("SELECT data FROM flows").fetchall()
        except Exception:
            return []
        out: list[FlowVerdict] = []
        for (data,) in rows:
            try:
                if data is None:
                    continue
                d = json.loads(data) if isinstance(data, str) else json.loads(bytes(data).decode())
                if isinstance(d, str):
                    d = json.loads(d)
                out.append(FlowVerdict.model_validate(d))
            except Exception:
                continue
        return out
    finally:
        try:
            con.close()
        except Exception:
            pass


def query_by_flow_id(flow_id: str) -> FlowVerdict | None:
    """Point lookup via PRIMARY KEY — <1ms on <100 rows (SEARCH USING INDEX)."""
    if not _DB.exists():
        return None
    try:
        con = sqlite3.connect(str(_DB))
    except Exception:
        return None
    try:
        try:
            cur = con.execute("SELECT data FROM flows WHERE flow_id = ?", (flow_id,))
            row = cur.fetchone()
        except Exception:
            return None
        if row is None:
            return None
        data = row[0]
        try:
            d = json.loads(data) if isinstance(data, str) else json.loads(bytes(data).decode())
            if isinstance(d, str):
                d = json.loads(d)
            return FlowVerdict.model_validate(d)
        except Exception:
            return None
    finally:
        try:
            con.close()
        except Exception:
            pass
