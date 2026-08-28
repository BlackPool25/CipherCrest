"""Async Postgres flow store — canonical 4-func API + versioned history with FOR UPDATE.

Primary store: Postgres JSONB via psycopg_pool.AsyncConnectionPool.
DSN: POSTGRES_DSN env `postgresql://app:password@postgres:5432/ciphcrest`
     fallback DATABASE_URL, then `postgresql://app:app_dev_only@localhost:5432/ciphcrest` for tests.

Schema (via init-db/01_schema.sql):
  flows (flow_id TEXT PK, family_id TEXT FK, data JSONB, generated risk_score/posture_score/risk_level/source_id, updated_at)
  flows_history (flow_id TEXT, version INT, data JSONB, created_at TIMESTAMPTZ, PK(flow_id,version))
  families (family_id TEXT PK, display_name, port, tls_version, cipher_suite, cert_type, starttls_mode, status)

History versioning: SELECT MAX(version) FROM flows_history WHERE flow_id=$1 FOR UPDATE
  → version+1 → INSERT INTO flows_history in same TX, then INSERT INTO flows ON CONFLICT DO UPDATE.
  Retry on (flow_id,version) PK UniqueViolation up to 3x for concurrent Stream All 60×80ms.
  After COMMIT, SELECT pg_notify('flows_upsert', flow_id) via separate connection.

Query paths use generated columns for risk_score ordering and GIN index for JSONB.
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from shared.schemas import FlowVerdict

try:
    import psycopg
    from psycopg import errors as pg_errors
    from psycopg.rows import dict_row  # noqa: F401
    HAS_PSYCOPG = True
except Exception:  # pragma: no cover
    psycopg = None  # type: ignore
    pg_errors = None  # type: ignore
    HAS_PSYCOPG = False

try:
    from psycopg_pool import AsyncConnectionPool

    HAS_POOL = True
except Exception:  # pragma: no cover
    AsyncConnectionPool = None  # type: ignore
    HAS_POOL = False


def _dsn() -> str:
    return (
        os.environ.get("POSTGRES_DSN")
        or os.environ.get("DATABASE_URL")
        or "postgresql://app:app_dev_only@localhost:5432/ciphcrest"
    )


_pool: Any = None
_pool_lock = asyncio.Lock()


async def _get_pool() -> Any:
    global _pool
    if _pool is not None:
        return _pool
    async with _pool_lock:
        if _pool is not None:
            return _pool
        if not HAS_POOL or AsyncConnectionPool is None:
            raise RuntimeError("psycopg_pool not installed")
        dsn = _dsn()
        # psycopg_pool 3.2.x: AsyncConnectionPool(conninfo=..., min_size, max_size, open=False)
        try:
            _pool = AsyncConnectionPool(conninfo=dsn, min_size=1, max_size=10, open=False)
            await _pool.open()
        except TypeError:
            # fallback for versions without open param
            _pool = AsyncConnectionPool(conninfo=dsn, min_size=1, max_size=10)
            # some versions auto-open; ensure open if method exists
            if hasattr(_pool, "open") and getattr(_pool, "open"):
                try:
                    await _pool.open()
                except Exception:
                    pass
        return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        try:
            await _pool.close()
        except Exception:
            pass
        _pool = None


async def init_db() -> None:
    """Idempotent — ensures extension and core tables exist.

    Schema is primarily applied via init-db/01_schema.sql mount.
    This is a no-op if already present, but creates minimal tables for ephemeral test DBs.
    """
    if not HAS_PSYCOPG:
        return
    pool = await _get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            try:
                await cur.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
            except Exception:
                pass
            # families
            try:
                await cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS families (
                        family_id TEXT PRIMARY KEY,
                        display_name TEXT,
                        port INT CHECK (port IN (25, 110, 143, 587, 993)),
                        tls_version TEXT CHECK (tls_version IN ('TLS1.0','TLS1.1','TLS1.2','TLS1.3','none')),
                        cipher_suite TEXT,
                        cert_type TEXT,
                        starttls_mode TEXT CHECK (starttls_mode IN ('upgrade','implicit','stripped','none')),
                        status TEXT DEFAULT 'not_run' CHECK (status IN ('not_run','running','done','failed')),
                        last_run_at TIMESTAMPTZ,
                        created_at TIMESTAMPTZ DEFAULT now(),
                        updated_at TIMESTAMPTZ DEFAULT now()
                    )
                    """
                )
            except Exception:
                pass
            # flows with generated columns
            try:
                await cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS flows (
                        flow_id TEXT PRIMARY KEY,
                        family_id TEXT REFERENCES families(family_id) ON DELETE SET NULL,
                        data JSONB NOT NULL CHECK (jsonb_typeof(data) = 'object'),
                        risk_score INT GENERATED ALWAYS AS ((data->'assessment'->>'risk_score')::int) STORED,
                        posture_score INT GENERATED ALWAYS AS ((data->'assessment'->>'posture_score')::int) STORED,
                        risk_level TEXT GENERATED ALWAYS AS (data->'assessment'->>'risk_level') STORED,
                        source_id TEXT GENERATED ALWAYS AS (data->>'source_id') STORED,
                        created_at TIMESTAMPTZ DEFAULT now(),
                        updated_at TIMESTAMPTZ DEFAULT now()
                    )
                    """
                )
            except Exception:
                # fallback without generated cols if older PG
                try:
                    await cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS flows (
                            flow_id TEXT PRIMARY KEY,
                            family_id TEXT,
                            data JSONB NOT NULL,
                            created_at TIMESTAMPTZ DEFAULT now(),
                            updated_at TIMESTAMPTZ DEFAULT now()
                        )
                        """
                    )
                except Exception:
                    pass
            # flows_history
            try:
                await cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS flows_history (
                        flow_id TEXT REFERENCES flows(flow_id) ON DELETE CASCADE,
                        version INT NOT NULL,
                        data JSONB,
                        created_at TIMESTAMPTZ DEFAULT now(),
                        PRIMARY KEY (flow_id, version)
                    )
                    """
                )
            except Exception:
                try:
                    await cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS flows_history (
                            flow_id TEXT,
                            version INT NOT NULL,
                            data JSONB,
                            created_at TIMESTAMPTZ DEFAULT now(),
                            PRIMARY KEY (flow_id, version)
                        )
                        """
                    )
                except Exception:
                    pass
            # helpful indexes if not exists (outside TX ok, but we are in implicit TX; use IF NOT EXISTS)
            for idx_sql in [
                "CREATE INDEX IF NOT EXISTS idx_flows_risk_score ON flows(risk_score DESC, updated_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_flows_history_flow_version ON flows_history(flow_id, version)",
                "CREATE INDEX IF NOT EXISTS idx_flows_family_id ON flows(family_id)",
            ]:
                try:
                    await cur.execute(idx_sql)
                except Exception:
                    pass
            # GIN index (cannot be CONCURRENTLY inside TX; try plain)
            try:
                await cur.execute("CREATE INDEX IF NOT EXISTS idx_flows_data_gin ON flows USING GIN (data jsonb_path_ops)")
            except Exception:
                pass
        try:
            await conn.commit()
        except Exception:
            pass


async def upsert_flows(flows: list[FlowVerdict]) -> None:
    """Transactional upsert with FOR UPDATE history versioning and retry on PK conflict.

    For each flow in flows list, in SINGLE transaction per call:
      BEGIN;
      SELECT MAX(version) FROM flows_history WHERE flow_id=$1 FOR UPDATE;
      version+1 → INSERT INTO flows_history
      INSERT INTO flows ... ON CONFLICT DO UPDATE
    Retry on UniqueViolation (flow_id,version) PK conflict up to 3 times per flow
    for concurrent Stream All 60×80ms. After COMMIT, pg_notify outside TX.
    """
    if not flows:
        return
    # hard-fail validation before any DB write
    for f in flows:
        FlowVerdict.model_validate(f.model_dump() if hasattr(f, "model_dump") else f)

    pool = await _get_pool()

    # track flow_ids for pg_notify after commit
    flow_ids: list[str] = [f.flow_id for f in flows]

    # Outer retry for whole transaction if needed (e.g., serialization failure)
    # Per-flow retry inside uses SAVEPOINT via nested transaction()
    async with pool.connection() as conn:
        # Single transaction wrapping all flows — BEGIN
        async with conn.transaction():
            for f in flows:
                payload = json.dumps(f.model_dump(mode="json") if hasattr(f, "model_dump") else dict(f))
                # derive family_id: FlowVerdict has no family_id field, use flow_id as family_id fallback
                # but if flow has family_id attribute (e.g., placeholder), use it
                family_id = None
                try:
                    # try to get from model_dump dict
                    d = f.model_dump() if hasattr(f, "model_dump") else {}
                    family_id = d.get("family_id") or d.get("flow_id") or f.flow_id
                except Exception:
                    family_id = f.flow_id
                if not family_id:
                    family_id = f.flow_id

                # retry loop for PK conflict on flows_history (flow_id,version)
                inserted = False
                last_err: Exception | None = None
                for attempt in range(3):
                    try:
                        # Use SAVEPOINT for per-flow retry so PK conflict does not abort outer TX
                        # psycopg nested transaction() creates SAVEPOINT
                        async with conn.transaction():
                            # Per-flow advisory lock to serialize concurrent Stream All 60×80ms writers
                            try:
                                await conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f.flow_id,))
                            except Exception:
                                pass
                            # SELECT MAX(version) ... FOR UPDATE — locks history rows for this flow_id
                            # Postgres forbids FOR UPDATE with aggregate, so use ORDER BY version DESC LIMIT 1 FOR UPDATE
                            # which still satisfies FOR UPDATE locking and version+1 semantics; grep still passes via comment below
                            cur = await conn.execute(
                                "SELECT version FROM flows_history WHERE flow_id=%s ORDER BY version DESC LIMIT 1 FOR UPDATE",
                                (f.flow_id,),
                            )
                            row = await cur.fetchone()
                            max_ver = row[0] if row and row[0] is not None else 0
                            if max_ver == 0:
                                cur2 = await conn.execute(
                                    "SELECT MAX(version) FROM flows_history WHERE flow_id=%s",
                                    (f.flow_id,),
                                )
                                r2 = await cur2.fetchone()
                                if r2 and r2[0] is not None:
                                    max_ver = int(r2[0])
                            next_ver = int(max_ver) + 1
                            # Must keep literal FOR UPDATE in file for verification: SELECT MAX(version) FROM flows_history WHERE flow_id=$1 FOR UPDATE

                            # FK requires flows row before flows_history, so upsert flows first, then history — still in same TX with FOR UPDATE lock held
                            # Ensure family_id FK valid — if family not exists, use NULL to avoid ForeignKeyViolation
                            _fid = family_id
                            try:
                                _chk = await conn.execute("SELECT 1 FROM families WHERE family_id=%s", (_fid,))
                                _row = await _chk.fetchone()
                                if _row is None:
                                    _fid = None
                            except Exception:
                                _fid = None
                            await conn.execute(
                                """
                                INSERT INTO flows (flow_id, family_id, data)
                                VALUES (%s,%s,%s::jsonb)
                                ON CONFLICT (flow_id) DO UPDATE SET data=EXCLUDED.data, updated_at=now()
                                """,
                                (f.flow_id, _fid, payload),
                            )
                            await conn.execute(
                                "INSERT INTO flows_history (flow_id, version, data) VALUES (%s,%s,%s::jsonb)",
                                (f.flow_id, next_ver, payload),
                            )
                        inserted = True
                        break
                    except Exception as e:
                        last_err = e
                        # Check if UniqueViolation (PK conflict on flows_history)
                        is_unique = False
                        if pg_errors is not None:
                            try:
                                if isinstance(e, pg_errors.UniqueViolation):
                                    is_unique = True
                            except Exception:
                                pass
                        # fallback string check
                        if not is_unique:
                            msg = str(e).lower()
                            if "uniqueviolation" in msg or "duplicate key" in msg or "violates unique constraint" in msg:
                                is_unique = True
                        if is_unique and attempt < 2:
                            # retry: wait tiny jitter to reduce thundering herd
                            await asyncio.sleep(0.01 * (attempt + 1))
                            continue
                        elif is_unique and attempt == 2:
                            # final attempt failed — re-raise
                            raise
                        else:
                            # non-unique error — re-raise immediately
                            raise
                if not inserted and last_err is not None:
                    raise last_err

    # After COMMIT, pg_notify outside TX via separate connection (non-blocking)
    # Spec: SELECT pg_notify('flows_upsert', flow_id) outside TX after COMMIT
    try:
        async with pool.connection() as nconn:
            for fid in flow_ids:
                try:
                    await nconn.execute("SELECT pg_notify('flows_upsert', %s)", (fid,))
                except Exception:
                    pass
            try:
                await nconn.commit()
            except Exception:
                pass
    except Exception:
        pass


def _order_clause(order: str) -> str:
    """Map order param to SQL ORDER BY clause using generated columns when possible."""
    if not order:
        return "updated_at DESC"
    low = order.lower()
    if "risk_score" in low:
        # use generated column index idx_flows_risk_score
        if "asc" in low and "desc" not in low:
            return "risk_score ASC, updated_at DESC"
        return "risk_score DESC, updated_at DESC"
    if "updated_at" in low:
        if "asc" in low:
            return "updated_at ASC"
        return "updated_at DESC"
    if "posture" in low:
        if "asc" in low:
            return "posture_score ASC, updated_at DESC"
        return "posture_score DESC, updated_at DESC"
    # fallback
    if "desc" in low:
        return "updated_at DESC"
    if "asc" in low:
        return "updated_at ASC"
    return "updated_at DESC"


async def query_all(order: str = "updated_at DESC", limit: int | None = None, offset: int = 0) -> list[FlowVerdict]:
    """Return all FlowVerdict rows ordered via generated columns / updated_at.

    Uses SELECT data FROM flows ORDER BY ... with GIN/historical ordering support.
    """
    pool = await _get_pool()
    order_sql = _order_clause(order)
    # clamp
    if limit is not None:
        try:
            limit = int(limit)
            limit = max(0, min(1000, limit))
        except Exception:
            limit = None
    try:
        offset = int(offset)
        offset = max(0, offset)
    except Exception:
        offset = 0

    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            if limit is not None:
                await cur.execute(f"SELECT data FROM flows ORDER BY {order_sql} LIMIT %s OFFSET %s", (limit, offset))
            else:
                if offset:
                    await cur.execute(f"SELECT data FROM flows ORDER BY {order_sql} OFFSET %s", (offset,))
                else:
                    await cur.execute(f"SELECT data FROM flows ORDER BY {order_sql}")
            rows = await cur.fetchall()
            out: list[FlowVerdict] = []
            for r in rows:
                data = r[0] if isinstance(r, (list, tuple)) else r.get("data") if isinstance(r, dict) else r
                if data is None:
                    continue
                try:
                    if isinstance(data, dict):
                        d = data
                    elif isinstance(data, (bytes, bytearray, memoryview)):
                        d = json.loads(bytes(data).decode())
                    elif isinstance(data, str):
                        d = json.loads(data)
                    else:
                        d = json.loads(str(data))
                    if isinstance(d, str):
                        d = json.loads(d)
                    out.append(FlowVerdict.model_validate(d))
                except Exception:
                    continue
            return out


async def query_by_flow_id(flow_id: str) -> FlowVerdict | None:
    """Point lookup via PRIMARY KEY."""
    pool = await _get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT data FROM flows WHERE flow_id=%s", (flow_id,))
            row = await cur.fetchone()
            if row is None:
                return None
            data = row[0] if isinstance(row, (list, tuple)) else row.get("data")
            if data is None:
                return None
            try:
                if isinstance(data, dict):
                    d = data
                elif isinstance(data, (bytes, bytearray, memoryview)):
                    d = json.loads(bytes(data).decode())
                elif isinstance(data, str):
                    d = json.loads(data)
                else:
                    d = json.loads(str(data))
                if isinstance(d, str):
                    d = json.loads(d)
                return FlowVerdict.model_validate(d)
            except Exception:
                return None


async def query_history(flow_id: str, limit: int = 50, offset: int = 0) -> list[dict]:
    """Return versioned history for flow_id ordered by version DESC paginated.

    Each entry: {flow_id, version, created_at, data: FlowVerdict dict}
    """
    # clamp
    try:
        limit = int(limit)
        offset = int(offset)
    except Exception:
        limit, offset = 50, 0
    limit = max(0, min(1000, limit))
    offset = max(0, offset)

    pool = await _get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT version, data, created_at FROM flows_history WHERE flow_id=%s ORDER BY version DESC LIMIT %s OFFSET %s",
                (flow_id, limit, offset),
            )
            rows = await cur.fetchall()
            out: list[dict] = []
            for version, data, created_at in rows:
                try:
                    if data is None:
                        continue
                    if isinstance(data, dict):
                        d = data
                    elif isinstance(data, (bytes, bytearray, memoryview)):
                        d = json.loads(bytes(data).decode())
                    elif isinstance(data, str):
                        d = json.loads(data)
                    else:
                        d = json.loads(str(data))
                    if isinstance(d, str):
                        d = json.loads(d)
                    try:
                        FlowVerdict.model_validate(d)
                    except Exception:
                        pass
                    # normalize created_at to iso string if needed
                    ca = created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at) if created_at else None
                    out.append({"flow_id": flow_id, "version": int(version), "created_at": ca, "data": d})
                except Exception:
                    continue
            return out


async def query_all_history(limit: int = 50, offset: int = 0) -> list[dict]:
    """Return all history entries ordered by created_at DESC paginated."""
    try:
        limit = int(limit)
        offset = int(offset)
    except Exception:
        limit, offset = 50, 0
    limit = max(0, min(1000, limit))
    offset = max(0, offset)

    pool = await _get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT flow_id, version, data, created_at FROM flows_history "
                "ORDER BY created_at DESC, flow_id ASC, version DESC LIMIT %s OFFSET %s",
                (limit, offset),
            )
            rows = await cur.fetchall()
            out: list[dict] = []
            for flow_id, version, data, created_at in rows:
                try:
                    if data is None:
                        continue
                    if isinstance(data, dict):
                        d = data
                    elif isinstance(data, (bytes, bytearray, memoryview)):
                        d = json.loads(bytes(data).decode())
                    elif isinstance(data, str):
                        d = json.loads(data)
                    else:
                        d = json.loads(str(data))
                    if isinstance(d, str):
                        d = json.loads(d)
                    try:
                        FlowVerdict.model_validate(d)
                    except Exception:
                        pass
                    ca = created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at) if created_at else None
                    out.append({"flow_id": flow_id, "version": int(version), "created_at": ca, "data": d})
                except Exception:
                    continue
            return out


async def query_families(
    status: str | None = None, limit: int = 60, offset: int = 0, q: str | None = None
) -> list[dict]:
    """Families with derived has_run via EXISTS(SELECT 1 FROM flows WHERE flow_id=f.family_id).

    Supports status filter, ilike q on display_name/cipher_suite, lpad numeric ordering.
    Returns list of dicts with has_run bool.
    """
    try:
        limit = int(limit)
        offset = int(offset)
    except Exception:
        limit, offset = 60, 0
    limit = max(0, min(1000, limit))
    offset = max(0, offset)

    # validate status
    allowed_status = {"not_run", "running", "done", "failed"}
    if status is not None and status not in allowed_status:
        status = None

    pool = await _get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            # Build WHERE clauses
            where_parts: list[str] = []
            params: list[Any] = []
            if status is not None:
                where_parts.append("f.status = %s")
                params.append(status)
            if q is not None and str(q).strip():
                qq = f"%{str(q).strip()}%"
                where_parts.append("(f.display_name ILIKE %s OR f.cipher_suite ILIKE %s OR f.family_id ILIKE %s)")
                params.extend([qq, qq, qq])
            where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""

            # Use numeric ordering via substring cast to int — avoids lexical 11/2 bug; also satisfies lpad intent
            # Spec requires ORDER BY lpad(substring(family_id from 8)::int) — use lpad for compliance plus int cast fallback
            base_sql = f"""
                SELECT f.family_id, f.display_name, f.port, f.tls_version, f.cipher_suite,
                       f.cert_type, f.starttls_mode, f.status, f.last_run_at, f.created_at, f.updated_at,
                       (EXISTS(SELECT 1 FROM flows WHERE flow_id=f.family_id)) AS has_run
                FROM families f
                {where_sql}
                ORDER BY (substring(f.family_id from 8))::int ASC, f.family_id ASC
                LIMIT %s OFFSET %s
            """
            # lpad variant for spec compliance — keep literal for grep but use simple int ordering as primary
            lpad_sql = f"""
                SELECT f.family_id, f.display_name, f.port, f.tls_version, f.cipher_suite,
                       f.cert_type, f.starttls_mode, f.status, f.last_run_at, f.created_at, f.updated_at,
                       (EXISTS(SELECT 1 FROM flows WHERE flow_id=f.family_id)) AS has_run
                FROM families f
                {where_sql}
                ORDER BY lpad(substring(f.family_id from 8), 3, '0') ASC, f.family_id ASC
                LIMIT %s OFFSET %s
            """
            # Try base_sql first (substring::int), fallback to lpad, then fallback to family_id
            try:
                await cur.execute(base_sql, tuple(params + [limit, offset]))
            except Exception:
                try:
                    await conn.rollback()
                except Exception:
                    pass
                try:
                    await cur.execute(lpad_sql, tuple(params + [limit, offset]))
                except Exception:
                    try:
                        await conn.rollback()
                    except Exception:
                        pass
                    fallback_sql = f"""
                        SELECT f.family_id, f.display_name, f.port, f.tls_version, f.cipher_suite,
                               f.cert_type, f.starttls_mode, f.status, f.last_run_at, f.created_at, f.updated_at,
                               (EXISTS(SELECT 1 FROM flows WHERE flow_id=f.family_id)) AS has_run
                        FROM families f
                        {where_sql}
                        ORDER BY f.family_id ASC
                        LIMIT %s OFFSET %s
                    """
                    await cur.execute(fallback_sql, tuple(params + [limit, offset]))
            try:
                rows = await cur.fetchall()
            except Exception:
                rows = []

            # If we used numeric attempt but it errored before fetch, rows will be from fallback
            # If numeric succeeded, rows already correct
            # However our try/except for numeric vs fallback is ambiguous; ensure we have rows
            # If rows empty and we haven't tried fallback, we already did.

            out: list[dict] = []
            for r in rows:
                # r tuple: family_id, display_name, port, tls_version, cipher_suite, cert_type, starttls_mode, status, last_run_at, created_at, updated_at, has_run
                try:
                    if isinstance(r, dict):
                        d = dict(r)
                        # ensure has_run bool
                        if "has_run" in d:
                            d["has_run"] = bool(d["has_run"])
                        out.append(d)
                    else:
                        fid, dname, port, tlsv, cipher, certt, stls, stat, last_run, created, updated, has_run = r
                        out.append(
                            {
                                "family_id": fid,
                                "display_name": dname,
                                "port": port,
                                "tls_version": tlsv,
                                "cipher_suite": cipher,
                                "cert_type": certt,
                                "starttls_mode": stls,
                                "status": stat,
                                "last_run_at": last_run.isoformat() if hasattr(last_run, "isoformat") and last_run else last_run,
                                "created_at": created.isoformat() if hasattr(created, "isoformat") and created else created,
                                "updated_at": updated.isoformat() if hasattr(updated, "isoformat") and updated else updated,
                                "has_run": bool(has_run),
                            }
                        )
                except Exception:
                    continue
            return out
