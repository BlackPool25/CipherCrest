"""Task 8: history for all runs partitioned + lab/live/model history — version increments and concurrent distinct versions."""
from __future__ import annotations
import asyncio
import json
import os
import pathlib
import pytest

# ensure Test DSN points to seeded postgres (ciphercrest-postgres-1)
TEST_DSN_CANDIDATES = [
    "postgresql://app:app_dev_only@172.30.0.3:5432/ciphcrest",
    "postgresql://app:app_dev_only@localhost:5434/ciphcrest",
    "postgresql://app:app_dev_only@localhost:5432/ciphcrest",
]
for _dsn in TEST_DSN_CANDIDATES:
    # try quick connect at import time via env; final choice set below
    pass
os.environ["POSTGRES_DSN"] = TEST_DSN_CANDIDATES[0]
os.environ.setdefault("POSTGRES_PASSWORD", "app_dev_only")

from shared.schemas import FlowVerdict


def _load_flow(fid: str = "family-02") -> FlowVerdict:
    p = pathlib.Path("shared/fixtures/family-02.json")
    if not p.exists():
        p = pathlib.Path("shared/fixtures/family-01.json")
    d = json.loads(p.read_text())
    # override flow_id to fid for controlled test
    d["flow_id"] = fid
    # ensure flow_id matches family for has_run logic if needed
    return FlowVerdict.model_validate(d)


def _can_connect() -> bool:
    try:
        import psycopg  # type: ignore
        # try each DSN quickly
        for dsn in TEST_DSN_CANDIDATES:
            try:
                with psycopg.connect(dsn, connect_timeout=2) as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT 1 FROM information_schema.tables WHERE table_name='flows_history'")
                        if cur.fetchone() is None:
                            schema_path = pathlib.Path("init-db/01_schema.sql")
                            if schema_path.exists():
                                try:
                                    cur.execute(schema_path.read_text())
                                    conn.commit()
                                except Exception:
                                    try:
                                        conn.rollback()
                                    except Exception:
                                        pass
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


CAN_PG = _can_connect()

# pick working DSN for the session
WORKING_DSN = None
if CAN_PG:
    import psycopg  # type: ignore
    for dsn in TEST_DSN_CANDIDATES:
        try:
            with psycopg.connect(dsn, connect_timeout=2) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
            WORKING_DSN = dsn
            os.environ["POSTGRES_DSN"] = dsn
            break
        except Exception:
            continue


def test_reruns_increment_version():
    """2 reruns produce version 1->2->3; verify via query_history."""
    if not CAN_PG or WORKING_DSN is None:
        pytest.skip("postgres not available — skipping pg version test")

    async def _inner():
        from api.db_pg import query_history, upsert_flows, _get_pool

        fid = "family-test-history-8"
        # clean prior history for this fid to make test deterministic
        pool = await _get_pool()
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                try:
                    await cur.execute("DELETE FROM flows_history WHERE flow_id=%s", (fid,))
                    await cur.execute("DELETE FROM flows WHERE flow_id=%s", (fid,))
                    await conn.commit()
                except Exception:
                    try:
                        await conn.rollback()
                    except Exception:
                        pass

        flow = _load_flow(fid)
        # first insert -> version 1
        await upsert_flows([flow], source="synthetic")
        h1 = await query_history(fid, limit=10, offset=0)
        assert len(h1) >= 1
        assert max(r["version"] for r in h1) == 1

        # second rerun with lab source -> version 2
        await upsert_flows([flow], source="lab")
        h2 = await query_history(fid, limit=10, offset=0)
        assert len(h2) >= 2
        versions = sorted(r["version"] for r in h2)
        assert versions == list(range(1, len(versions) + 1))
        assert max(versions) == 2
        # check source differentiation exists (at least one lab)
        # query raw pg for source column
        pool = await _get_pool()
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT source FROM flows_history WHERE flow_id=%s ORDER BY version", (fid,))
                rows = await cur.fetchall()
                sources = [r[0] if isinstance(r, (list, tuple)) else r.get("source") for r in rows]
                assert "lab" in sources

        # third rerun -> version 3
        await upsert_flows([flow], source="live")
        h3 = await query_history(fid, limit=10, offset=0)
        versions3 = sorted(r["version"] for r in h3)
        assert max(versions3) == 3
        assert versions3 == [1, 2, 3]

        # cleanup
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                try:
                    await cur.execute("DELETE FROM flows_history WHERE flow_id=%s", (fid,))
                    await cur.execute("DELETE FROM flows WHERE flow_id=%s", (fid,))
                    await conn.commit()
                except Exception:
                    pass

    asyncio.run(_inner())


def test_concurrent_5x_distinct_versions():
    """concurrent 5x same family produce distinct versions 1..5 with FOR UPDATE no collision."""
    if not CAN_PG or WORKING_DSN is None:
        pytest.skip("postgres not available")

    async def _inner():
        from api.db_pg import query_history, upsert_flows, _get_pool

        fid = "family-concurrent-8"
        pool = await _get_pool()
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                try:
                    await cur.execute("DELETE FROM flows_history WHERE flow_id=%s", (fid,))
                    await cur.execute("DELETE FROM flows WHERE flow_id=%s", (fid,))
                    await conn.commit()
                except Exception:
                    try:
                        await conn.rollback()
                    except Exception:
                        pass

        flow = _load_flow(fid)

        # run 5 concurrent upserts
        await asyncio.gather(*[upsert_flows([flow], source="synthetic") for _ in range(5)])
        hist = await query_history(fid, limit=10, offset=0)
        assert len(hist) == 5, f"expected 5 history rows, got {len(hist)}"
        versions = sorted(r["version"] for r in hist)
        assert versions == [1, 2, 3, 4, 5], f"versions not distinct 1..5: {versions}"
        # no gaps, no duplicates
        assert len(set(versions)) == 5

        # cleanup
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                try:
                    await cur.execute("DELETE FROM flows_history WHERE flow_id=%s", (fid,))
                    await cur.execute("DELETE FROM flows WHERE flow_id=%s", (fid,))
                    await conn.commit()
                except Exception:
                    pass

    asyncio.run(_inner())


def test_source_column_and_indexes_exist():
    """Check schema: flows_history has source column with CHECK and indexes."""
    src = pathlib.Path("init-db/01_schema.sql").read_text()
    assert "source TEXT" in src
    assert "CHECK (source IN" in src
    assert "flows_history_source" in src or "idx_flows_history_source" in src

    # also verify live postgres column if available
    if not CAN_PG or WORKING_DSN is None:
        pytest.skip("postgres not available for live column check")
    import psycopg  # type: ignore
    with psycopg.connect(WORKING_DSN) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='flows_history' AND column_name='source'")
            row = cur.fetchone()
            assert row is not None, "flows_history.source column missing in live DB"
            cur.execute("SELECT indexname FROM pg_indexes WHERE tablename='flows_history' AND indexname LIKE '%source%'")
            rows = cur.fetchall()
            assert len(rows) >= 1, "source index missing"


def test_analyze_source_differentiation():
    """POST /api/analyze with ?source=lab vs live appends history with correct source."""
    # Check app.py source extraction and upsert_flows source param
    src = pathlib.Path("api/app.py").read_text()
    assert "_extract_source" in src
    assert "source" in src.lower()
    assert "upsert_flows" in src
    # must pass source to upsert_flows
    assert "upsert_flows(flows, source=src)" in src or "upsert_flows(validated_single, source=src)" in src
    # db_pg must handle source column
    dbsrc = pathlib.Path("api/db_pg.py").read_text()
    assert "FOR UPDATE" in dbsrc
    assert "INSERT INTO flows_history" in dbsrc
    assert "source" in dbsrc
    # schema index
    assert "source" in pathlib.Path("init-db/01_schema.sql").read_text()

    # live integration via TestClient if pg available
    if not CAN_PG or WORKING_DSN is None:
        pytest.skip("postgres not available for live api test")
    os.environ["POSTGRES_DSN"] = WORKING_DSN
    from fastapi.testclient import TestClient
    from api.app import app
    import pathlib as pl

    client = TestClient(app)
    p = pl.Path("lab/pcaps/family-02.pcap")
    assert p.exists()
    # clean history for family-02 to isolate source test? don't clean all — just check incremental
    # get baseline count
    import psycopg  # type: ignore
    with psycopg.connect(WORKING_DSN) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM flows_history WHERE flow_id='family-02'")
            before = cur.fetchone()[0]

    with open(p, "rb") as f:
        r = client.post("/api/analyze?source=lab", files={"pcap": ("family-02.pcap", f, "application/vnd.tcpdump.pcap")})
    assert r.status_code == 200
    with psycopg.connect(WORKING_DSN) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM flows_history WHERE flow_id='family-02'")
            after = cur.fetchone()[0]
            assert after == before + 1, f"version not bumped: before {before} after {after}"
            cur.execute("SELECT source FROM flows_history WHERE flow_id='family-02' ORDER BY version DESC LIMIT 1")
            row = cur.fetchone()
            assert row is not None and row[0] == "lab", f"last source not lab: {row}"

    # live source
    with open(p, "rb") as f:
        r2 = client.post("/api/analyze?source=live", files={"pcap": ("family-02.pcap", f, "application/vnd.tcpdump.pcap")})
    assert r2.status_code == 200
    with psycopg.connect(WORKING_DSN) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT source FROM flows_history WHERE flow_id='family-02' ORDER BY version DESC LIMIT 1")
            row = cur.fetchone()
            assert row[0] == "live"
            # also show live_captures_history or flows_history with source=live exists
            cur.execute("SELECT count(*) FROM flows_history WHERE source='live'")
            live_cnt = cur.fetchone()[0]
            assert live_cnt >= 1


def test_history_never_pruned_and_append_only():
    """Ensure history is append-only: no DELETE without INSERT pattern in code."""
    dbsrc = pathlib.Path("api/db_pg.py").read_text()
    # should not contain DELETE FROM flows_history except in tests
    # main code only INSERTs
    assert "DELETE FROM flows_history" not in dbsrc
    assert "INSERT INTO flows_history" in dbsrc
    # FOR UPDATE must be present for version collision handling
    assert "FOR UPDATE" in dbsrc
    assert "SELECT MAX(version) FROM flows_history WHERE flow_id=$1 FOR UPDATE" in dbsrc or "SELECT MAX(version) FROM flows_history" in dbsrc
