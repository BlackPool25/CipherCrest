from __future__ import annotations

import json
import pathlib
import sqlite3
import time

import pytest

from shared.schemas import FlowVerdict

DB_PATH = pathlib.Path("api/flows.db")


def _load_fixtures(n: int = 10) -> list[FlowVerdict]:
    out: list[FlowVerdict] = []
    for i in range(1, n + 1):
        p = pathlib.Path(f"shared/fixtures/family-0{i}.json") if i < 10 else pathlib.Path("shared/fixtures/family-10.json")
        # handle 10
        if i == 10:
            p = pathlib.Path("shared/fixtures/family-10.json")
        else:
            p = pathlib.Path(f"shared/fixtures/family-0{i}.json")
        d = json.loads(p.read_text())
        out.append(FlowVerdict.model_validate(d))
    return out


def test_init_db_creates_table():
    from api.db import init_db

    init_db()
    assert DB_PATH.exists()
    con = sqlite3.connect(str(DB_PATH))
    sql = con.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='flows'").fetchone()
    con.close()
    assert sql is not None
    assert "flow_id TEXT PRIMARY KEY" in sql[0]
    assert "data TEXT" in sql[0]


def test_upsert_query():
    from api.db import init_db, query_all, upsert_flows

    # clean slate for this test — repopulate then assert 10
    init_db()
    flows = _load_fixtures(10)
    upsert_flows(flows)
    got = query_all()
    assert len(got) >= 10
    # each returned must be valid FlowVerdict
    for f in got:
        FlowVerdict.model_validate(f.model_dump())
    # ensure our 10 ids present
    ids = {f.flow_id for f in got}
    for f in flows:
        assert f.flow_id in ids
    # EXPLAIN QUERY PLAN point lookup uses index
    con = sqlite3.connect(str(DB_PATH))
    plan = con.execute("EXPLAIN QUERY PLAN SELECT data FROM flows WHERE flow_id='family-01'").fetchone()
    con.close()
    assert plan is not None
    detail = " ".join(str(x) for x in plan)
    assert "SEARCH" in detail or "USING" in detail or "PRIMARY" in detail or "INDEX" in detail


def test_point_lookup_latency():
    from api.db import init_db, query_by_flow_id, upsert_flows

    init_db()
    flows = _load_fixtures(10)
    upsert_flows(flows)
    from api.db import query_by_flow_id as q

    # warm
    assert q("family-01") is not None
    t0 = time.perf_counter()
    for _ in range(100):
        q("family-01")
    dt = (time.perf_counter() - t0) / 100
    assert dt < 0.001, f"point lookup {dt*1000:.3f}ms >=1ms"
    # also query_all <50ms avg
    from api.db import query_all

    t0 = time.perf_counter()
    for _ in range(100):
        query_all()
    dt2 = (time.perf_counter() - t0) / 100
    assert dt2 < 0.05, f"query_all {dt2*1000:.1f}ms >=50ms"


def test_malformed_json_skipped():
    from api.db import init_db, query_all

    init_db()
    # inject malformed row
    con = sqlite3.connect(str(DB_PATH))
    con.execute("INSERT OR REPLACE INTO flows (flow_id, data) VALUES (?, ?)", ("bad-json-row", "NOT_JSON{{{"))
    con.commit()
    con.close()
    # query_all should skip without crash and still return valid rows
    result = query_all()
    assert isinstance(result, list)
    assert all(isinstance(f, FlowVerdict) for f in result)
    assert not any(f.flow_id == "bad-json-row" for f in result)
    # cleanup
    con = sqlite3.connect(str(DB_PATH))
    con.execute("DELETE FROM flows WHERE flow_id='bad-json-row'")
    con.commit()
    con.close()


def test_missing_db_fallback():
    import shutil
    import tempfile

    # backup current db
    backup = None
    if DB_PATH.exists():
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        tmp.close()
        backup = pathlib.Path(tmp.name)
        shutil.copy(str(DB_PATH), str(backup))
        DB_PATH.unlink()
    try:
        # reload module to ensure fresh _DB check? query_all handles missing
        from api.db import query_all, query_by_flow_id

        assert query_all() == []
        assert query_by_flow_id("family-01") is None
        # creating on demand
        from api.db import init_db

        init_db()
        assert DB_PATH.exists()
    finally:
        if backup is not None and backup.exists():
            shutil.copy(str(backup), str(DB_PATH))
            backup.unlink()
            # re-upsert original fixtures to restore 10 rows for next checks
            from api.db import upsert_flows

            flows = _load_fixtures(10)
            upsert_flows(flows)


def test_query_by_flow_id_missing_returns_none():
    from api.db import query_by_flow_id

    assert query_by_flow_id("nonexistent-flow-xyz") is None


def test_upsert_idempotent():
    from api.db import query_all, query_by_flow_id, upsert_flows

    flows = _load_fixtures(3)
    upsert_flows(flows)
    upsert_flows(flows)
    got = query_all()
    ids = [f.flow_id for f in got]
    # no duplicates
    assert len(ids) == len(set(ids))
    for f in flows:
        found = query_by_flow_id(f.flow_id)
        assert found is not None
        assert found.flow_id == f.flow_id
