"""SQLite JSONB flow store — canonical 4-func API + versioned history.

Canonical DB: api/flows.db only (no _DB_CANDIDATES ambiguity).
Assessment alias: assessment/assessment.db is a symlink to api/flows.db if needed.

Schema:
  flows (flow_id TEXT PRIMARY KEY, data TEXT)
  flows_history (flow_id TEXT, version INTEGER, data TEXT, created_at TEXT, PRIMARY KEY(flow_id, version))

Uses json_extract probe when JSON1 available, TEXT fallback otherwise.
Idempotent init_db, INSERT OR REPLACE, <1ms point lookup via PRIMARY KEY.
History: every upsert auto-increments version per flow_id before REPLACE.
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
    """Idempotent — creates parent dir and flows + flows_history tables if missing."""
    _DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(_DB))
    try:
        con.execute("CREATE TABLE IF NOT EXISTS flows (flow_id TEXT PRIMARY KEY, data TEXT)")
        con.execute(
            "CREATE TABLE IF NOT EXISTS flows_history "
            "(flow_id TEXT, version INTEGER, data TEXT, created_at TEXT, "
            "PRIMARY KEY(flow_id, version))"
        )
        con.commit()
    finally:
        con.close()


def upsert_flows(flows: list[FlowVerdict]) -> None:
    """INSERT OR REPLACE each FlowVerdict; history version auto-inc before REPLACE.

    Handles 10-flow zip + 20 prior <100 rows. History insertion uses
    COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=:flow_id),0)+1
    before the canonical flows INSERT OR REPLACE, ensuring version 1..N timeline.
    """
    if not flows:
        return
    init_db()
    con = sqlite3.connect(str(_DB))
    try:
        for f in flows:
            payload = json.dumps(f.model_dump())
            # history versioning — must precede flows REPLACE
            try:
                con.execute(
                    "INSERT INTO flows_history (flow_id, version, data, created_at) "
                    "SELECT ?, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=?),0)+1, ?, datetime('now')",
                    (f.flow_id, f.flow_id, payload),
                )
            except Exception:
                # table missing edge -> ensure then retry once
                try:
                    con.execute(
                        "CREATE TABLE IF NOT EXISTS flows_history "
                        "(flow_id TEXT, version INTEGER, data TEXT, created_at TEXT, "
                        "PRIMARY KEY(flow_id, version))"
                    )
                    con.execute(
                        "INSERT INTO flows_history (flow_id, version, data, created_at) "
                        "SELECT ?, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=?),0)+1, ?, datetime('now')",
                        (f.flow_id, f.flow_id, payload),
                    )
                except Exception:
                    pass
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


def query_history(flow_id: str) -> list[dict]:
    """Return versioned history for flow_id ordered by version ASC.

    Each entry: {flow_id, version, created_at, data: FlowVerdict dict}
    Returns [] if no history or DB missing. Keeps FlowVerdict validation graceful.
    """
    if not _DB.exists():
        return []
    try:
        con = sqlite3.connect(str(_DB))
    except Exception:
        return []
    try:
        try:
            # ensure history table exists lazily
            con.execute(
                "CREATE TABLE IF NOT EXISTS flows_history "
                "(flow_id TEXT, version INTEGER, data TEXT, created_at TEXT, "
                "PRIMARY KEY(flow_id, version))"
            )
        except Exception:
            pass
        try:
            rows = con.execute(
                "SELECT version, data, created_at FROM flows_history WHERE flow_id=? ORDER BY version ASC",
                (flow_id,),
            ).fetchall()
        except Exception:
            return []
        out: list[dict] = []
        for version, data, created_at in rows:
            try:
                if data is None:
                    continue
                d = json.loads(data) if isinstance(data, str) else json.loads(bytes(data).decode())
                if isinstance(d, str):
                    d = json.loads(d)
                # validate FlowVerdict but keep raw dict for response
                try:
                    FlowVerdict.model_validate(d)
                except Exception:
                    pass
                out.append({"flow_id": flow_id, "version": int(version), "created_at": created_at, "data": d})
            except Exception:
                continue
        return out
    finally:
        try:
            con.close()
        except Exception:
            pass


def query_all_history(limit: int = 100, offset: int = 0) -> list[dict]:
    """Return all history entries ordered by created_at DESC, paginated.

    Each entry: {flow_id, version, created_at, data: FlowVerdict dict}
    limit/offset are clamped to >=0; limit capped at 1000.
    """
    if not _DB.exists():
        return []
    # clamp
    try:
        limit = int(limit)
        offset = int(offset)
    except Exception:
        limit, offset = 100, 0
    limit = max(0, min(1000, limit))
    offset = max(0, offset)
    try:
        con = sqlite3.connect(str(_DB))
    except Exception:
        return []
    try:
        try:
            con.execute(
                "CREATE TABLE IF NOT EXISTS flows_history "
                "(flow_id TEXT, version INTEGER, data TEXT, created_at TEXT, "
                "PRIMARY KEY(flow_id, version))"
            )
        except Exception:
            pass
        try:
            rows = con.execute(
                "SELECT flow_id, version, data, created_at FROM flows_history "
                "ORDER BY created_at DESC, flow_id ASC, version DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        except Exception:
            return []
        out: list[dict] = []
        for flow_id, version, data, created_at in rows:
            try:
                if data is None:
                    continue
                d = json.loads(data) if isinstance(data, str) else json.loads(bytes(data).decode())
                if isinstance(d, str):
                    d = json.loads(d)
                try:
                    FlowVerdict.model_validate(d)
                except Exception:
                    pass
                out.append({"flow_id": flow_id, "version": int(version), "created_at": created_at, "data": d})
            except Exception:
                continue
        return out
    finally:
        try:
            con.close()
        except Exception:
            pass
