"""
api/seed.py — startup-idempotent deterministic seed + run-dashboard 10

Usage:
  python -m api.seed --dry-run               # prints 60 families ordered lpad numeric without DB
  python -m api.seed                          # seeds 60 families + pcap_files + flows in single BEGIN
  python -m api.seed --run-dashboard          # also replays lab/pcaps/family-01..10 → reassemble → FlowVerdict → upsert + NOTIFY
  python -m api.seed --upsert-families        # seed all canonical families (61+ without down -v)
  python -m api.seed --dsn postgresql://...  # override POSTGRES_DSN
  python -m api.seed --help                   # shows --run-dashboard, --dry-run, --upsert-families

Idempotency:
  families:  INSERT ... ON CONFLICT (family_id) DO UPDATE SET ... WHERE IS DISTINCT FROM (avoid WAL when unchanged)
  pcap_files: INSERT ... ON CONFLICT (family_id,sha256) DO UPDATE SET data=... WHERE IS DISTINCT FROM
  flows:     INSERT ... ON CONFLICT (flow_id) DO UPDATE SET data=... WHERE IS DISTINCT FROM
  Deterministic source_id = hashlib.sha256((family_id + str(seed)).encode()).hexdigest()  # never uuid4
  Ordering: ORDER BY lpad(substring(family_id from 8)::int) numeric — python mimics via int(split("-")[1])
  Transaction: single BEGIN wrapping 60 families — never per-family commit
  BYTEA: looped psycopg.Binary for <50MB (total ~50KB); COPY BINARY alternative documented but not needed

Do NOT use docker-entrypoint-initdb.d/02_seed.sql — only 01_schema.sql is entrypoint.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import pathlib
import re
import sys
import time

# Prefer psycopg[binary] 3.2.5
try:
    import psycopg
    from psycopg import AsyncConnection, Connection
    HAS_PSYCOPG = True
except Exception:
    psycopg = None  # type: ignore
    AsyncConnection = None  # type: ignore
    Connection = None  # type: ignore
    HAS_PSYCOPG = False

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "lab/manifest.json"
PCAP_DIR = ROOT / "lab/pcaps"
DEFAULT_DSN = os.environ.get("POSTGRES_DSN", "postgresql://app:app_dev_only@localhost:5432/ciphcrest")

SEED = 0  # deterministic seed for source_id

CANON_RE = re.compile(r"^family-\d{2}$")


def deterministic_source_id(family_id: str, seed: int = SEED) -> str:
    """Deterministic source_id — never uuid4."""
    return hashlib.sha256((family_id + str(seed)).encode()).hexdigest()


def _sorted_family_keys(manifest_data: dict, upsert_families: bool = False) -> list[str]:
    """Return canonical family keys sorted numeric via lpad(substring(... )::int)."""
    canon = [k for k in manifest_data.keys() if CANON_RE.match(k)]
    # numeric ordering avoids lexical 11/100/2 bug: ORDER BY lpad(substring(family_id from 8)::int)
    canon_sorted = sorted(canon, key=lambda x: int(x.split("-")[1]))
    if not upsert_families:
        # default 60 families 01-60
        # filter to <=60 if more exist (e.g. 99 synthetic)
        filtered = [k for k in canon_sorted if int(k.split("-")[1]) <= 60]
        # if manifest has exactly 60, filtered == canon_sorted[:60]
        # if manifest has 50 pcaps, still return 60 families (01-60) even if pcap missing
        if len(filtered) >= 60:
            return filtered[:60]
        # fallback: take first 60 sorted
        return canon_sorted[:60]
    return canon_sorted


def _get_manifest_families(upsert_families: bool = False) -> list[tuple[str, dict]]:
    if not MANIFEST.exists():
        return []
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    keys = _sorted_family_keys(data, upsert_families=upsert_families)
    return [(k, data[k]) for k in keys]


async def _wait_for_pg(dsn: str, retries: int = 5, base_delay: float = 0.5) -> None:
    """Wait for pg_isready with exponential backoff 0.5s,1s,2s,4s,8s — logs retries."""
    # try async path if psycopg available
    for attempt in range(retries):
        delay = base_delay * (2 ** attempt)
        try:
            if HAS_PSYCOPG and AsyncConnection is not None:
                conn = await AsyncConnection.connect(dsn, connect_timeout=2)
                await conn.close()
                if attempt > 0:
                    print(f"[seed] pg_isready retry {attempt}/{retries} succeeded after {delay/2:.1f}s backoff")
                return
            else:
                # sync fallback probe
                import psycopg as _pg  # type: ignore
                c = _pg.connect(dsn, connect_timeout=2)
                c.close()
                return
        except Exception as e:
            print(f"[seed] pg_isready attempt {attempt+1}/{retries} failed: {e} — retry in {delay:.1f}s (exponential)")
            if attempt == retries - 1:
                # last attempt failed
                raise RuntimeError(f"pg_isready failed after {retries} retries: {e}") from e
            try:
                await asyncio.sleep(delay)
            except Exception:
                time.sleep(delay)
    # fallback sync sleep if async not available
    for attempt in range(retries):
        delay = base_delay * (2 ** attempt)
        try:
            if HAS_PSYCOPG:
                import psycopg as _pg2
                c = _pg2.connect(dsn, connect_timeout=2)
                c.close()
                return
        except Exception as e2:
            print(f"[seed] pg_isready sync attempt {attempt+1}/{retries} failed: {e2}")
            if attempt == retries - 1:
                raise
            time.sleep(delay)


def _sync_wait_for_pg(dsn: str, retries: int = 5, base_delay: float = 0.5) -> None:
    for attempt in range(retries):
        delay = base_delay * (2 ** attempt)
        try:
            if HAS_PSYCOPG:
                import psycopg as _pg
                c = _pg.connect(dsn, connect_timeout=2)
                c.close()
                if attempt > 0:
                    print(f"[seed] pg_isready sync retry {attempt}/{retries} succeeded")
                return
            else:
                # if psycopg not installed, assume ready (for dry-run tests)
                return
        except Exception as e:
            print(f"[seed] pg_isready sync attempt {attempt+1}/{retries} failed: {e} — retry in {delay:.1f}s")
            if attempt == retries - 1:
                raise RuntimeError(f"pg_isready sync failed after {retries}: {e}") from e
            time.sleep(delay)


def _families_upsert_sql() -> str:
    # avoid WAL blow on unchanged — IS DISTINCT FROM
    return """
    INSERT INTO families (family_id, display_name, port, tls_version, cipher_suite, cert_type, starttls_mode, status)
    VALUES (%s, %s, %s, %s, %s, %s, %s, 'not_run')
    ON CONFLICT (family_id) DO UPDATE SET
        display_name = EXCLUDED.display_name,
        port = EXCLUDED.port,
        tls_version = EXCLUDED.tls_version,
        cipher_suite = EXCLUDED.cipher_suite,
        cert_type = EXCLUDED.cert_type,
        starttls_mode = EXCLUDED.starttls_mode,
        updated_at = now()
    WHERE families.display_name IS DISTINCT FROM EXCLUDED.display_name
       OR families.port IS DISTINCT FROM EXCLUDED.port
       OR families.tls_version IS DISTINCT FROM EXCLUDED.tls_version
       OR families.cipher_suite IS DISTINCT FROM EXCLUDED.cipher_suite
       OR families.cert_type IS DISTINCT FROM EXCLUDED.cert_type
       OR families.starttls_mode IS DISTINCT FROM EXCLUDED.starttls_mode
    """


def _pcap_files_upsert_sql() -> str:
    # UNIQUE (family_id, sha256) — avoid WAL when sha unchanged
    return """
    INSERT INTO pcap_files (family_id, data, sha256, byte_length)
    VALUES (%s, %s, %s, %s)
    ON CONFLICT (family_id, sha256) DO UPDATE SET
        data = EXCLUDED.data,
        byte_length = EXCLUDED.byte_length
    WHERE pcap_files.sha256 IS DISTINCT FROM EXCLUDED.sha256
       OR pcap_files.data IS DISTINCT FROM EXCLUDED.data
    """


def _flows_upsert_sql() -> str:
    return """
    INSERT INTO flows (flow_id, family_id, data)
    VALUES (%s, %s, %s::jsonb)
    ON CONFLICT (flow_id) DO UPDATE SET
        data = EXCLUDED.data,
        updated_at = now()
    WHERE flows.data IS DISTINCT FROM EXCLUDED.data
    """


def _make_placeholder_flow(family_id: str, entry: dict, seed: int = SEED) -> dict:
    """Minimal valid FlowVerdict-like JSON for placeholder flows — deterministic source_id."""
    port = int(entry.get("port", 587) or 587)
    tls_raw = entry.get("tls") or entry.get("tls_version") or "TLS1.2"
    if tls_raw == "none":
        tls_raw = "unknown"
    if tls_raw not in ("TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3", "unknown"):
        tls_raw = "unknown"
    cipher = entry.get("cipher") or entry.get("cipher_suite") or "ECDHE-RSA-AES128-GCM-SHA256"
    cert_type = entry.get("cert") or entry.get("cert_type") or "rsa2048"
    starttls = entry.get("starttls") or entry.get("starttls_mode") or "upgrade"
    if starttls == "cleartext":
        starttls = "stripped"
    if starttls not in ("upgrade", "implicit", "none", "stripped"):
        starttls = "upgrade"
    if port == 993 and starttls == "upgrade":
        starttls = "implicit"
    app_proto = "smtp" if port in (25, 587) else ("imap" if port in (143, 993) else "pop3")
    source_id = deterministic_source_id(family_id, seed)
    env_id = entry.get("environment_id") or f"{family_id}__postfix3.9_loss0"
    capture_epoch = entry.get("capture_epoch") or "2026-08-27T00:00:00Z"
    return {
        "flow_id": family_id,
        "family_id": family_id,
        "source_id": source_id,
        "environment_id": env_id,
        "capture_epoch": capture_epoch,
        "app_protocol": app_proto,
        "starttls_mode": starttls,
        "tls": {
            "version": tls_raw,
            "is_deprecated": tls_raw in ("TLS1.0", "TLS1.1"),
            "cipher_suite": cipher,
            "cipher_strength": "unknown",
            "is_aead": False,
            "kex": entry.get("kex", "unknown") if entry.get("kex") in ("ECDHE", "RSA", "DHE", "unknown") else "unknown",
            "fs_flag": False,
            "handshake_success": tls_raw != "unknown",
            "alert_after_starttls": False,
        },
        "cert": {
            "leaf_present": False,
            "is_tls13_opaque": False,
            "ocsp_stapled_status": "unknown",
        },
        "assessment": {"findings": [], "risk_level": "Low", "risk_score": 10, "posture_score": 90},
        "policy": None,
        "coverage_ratio": 1.0,
        "pre_tls_buffer_len": 0,
        "pre_tls_buffer_injection_possible": False,
    }


async def seed_all(dsn: str | None = None, with_dashboard_run: bool = False, upsert_families: bool = False) -> dict:
    """
    Startup-idempotent deterministic seed.

    - Waits for pg_isready retry 5×500ms exponential (0.5,1,2,4,8s)
    - In single transaction order families→pcap_files→flows (BEGIN wrapping 60 families)
    - Bulk BYTEA via looped psycopg.Binary (<50MB) — COPY BINARY documented as alternative for >50MB

    Returns dict with counts diffs.
    """
    dsn = dsn or DEFAULT_DSN
    # pg_isready exponential backoff
    try:
        await _wait_for_pg(dsn, retries=5, base_delay=0.5)
    except Exception:
        # fallback sync wait
        try:
            _sync_wait_for_pg(dsn, retries=5, base_delay=0.5)
        except Exception as e:
            print(f"[seed] pg_isready final failure: {e}")
            raise

    families = _get_manifest_families(upsert_families=upsert_families)
    print(f"[seed] seeding {len(families)} families ordered lpad(substring(family_id from 8)::int) — {[f[0] for f in families[:3]]} ... {[f[0] for f in families[-2:]]}")

    # Try async path first
    use_async = HAS_PSYCOPG and AsyncConnection is not None
    counts_before = {}
    counts_after = {}
    try:
        if use_async:
            return await _seed_all_async(dsn, families, with_dashboard_run)
        else:
            return _seed_all_sync(dsn, families, with_dashboard_run)
    except Exception as e:
        # fallback sync if async failed for driver reason
        if use_async:
            print(f"[seed] async seed failed ({e}), falling back to sync")
            return _seed_all_sync(dsn, families, with_dashboard_run)
        raise


async def _seed_all_async(dsn: str, families: list[tuple[str, dict]], with_dashboard_run: bool) -> dict:
    conn = await AsyncConnection.connect(dsn)
    try:
        # counts before
        counts_before = {}
        for tbl in ("families", "pcap_files", "flows"):
            try:
                cur = await conn.execute(f"SELECT count(*) FROM {tbl}")
                row = await cur.fetchone()
                counts_before[tbl] = int(row[0]) if row else 0
            except Exception:
                counts_before[tbl] = 0

        # Single transaction wrapping 60 families — BEGIN
        async with conn.transaction():
            for family_id, entry in families:
                # families
                display_name = entry.get("description") or entry.get("display_name") or family_id
                port = int(entry.get("port", 587) or 587)
                tls_version = entry.get("tls") or entry.get("tls_version") or "TLS1.2"
                if tls_version == "none":
                    tls_version = "none"
                # normalize tls_version to allowed set
                if tls_version not in ("TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3", "none", "unknown"):
                    tls_version = "unknown"
                # for DB check, families allows none but flows tls only unknown — keep DB as is
                if tls_version == "unknown":
                    tls_version = "none"
                cipher_suite = entry.get("cipher") or entry.get("cipher_suite") or "ECDHE-RSA-AES128-GCM-SHA256"
                cert_type = entry.get("cert") or entry.get("cert_type") or "rsa2048"
                starttls_mode = entry.get("starttls") or entry.get("starttls_mode") or "upgrade"
                if starttls_mode == "cleartext":
                    starttls_mode = "stripped"
                if starttls_mode not in ("upgrade", "implicit", "stripped", "none"):
                    starttls_mode = "upgrade"
                await conn.execute(_families_upsert_sql(), (family_id, display_name, port, tls_version, cipher_suite, cert_type, starttls_mode))

                # pcap_files — read bytes via psycopg.Binary streaming
                pcap_path = PCAP_DIR / f"{family_id}.pcap"
                # fallback: manifest pcap field
                if not pcap_path.exists() and entry.get("pcap"):
                    alt = ROOT / entry["pcap"]
                    if alt.exists():
                        pcap_path = alt
                if pcap_path.exists():
                    data = pcap_path.read_bytes()
                    # guard 100MB (seed pcaps are 1KB safe)
                    if len(data) >= 100 * 1024 * 1024:
                        print(f"[seed] skip {family_id} pcap too large {len(data)}")
                    else:
                        sha256 = hashlib.sha256(data).hexdigest()
                        byte_length = len(data)
                        # Bulk BYTEA: looped Binary for <50MB — COPY BINARY alternative for larger would be:
                        # await conn.execute("COPY pcap_files (family_id, data, sha256, byte_length) FROM STDIN WITH (FORMAT BINARY)")
                        # but loop is fine for <50MB
                        await conn.execute(_pcap_files_upsert_sql(), (family_id, psycopg.Binary(data), sha256, byte_length))

                # flows placeholder — deterministic source_id
                flow_data = _make_placeholder_flow(family_id, entry, seed=SEED)
                flow_json = json.dumps(flow_data)
                await conn.execute(_flows_upsert_sql(), (family_id, family_id, flow_json))
                # history versioning — SELECT FOR UPDATE pattern via INSERT with version auto-inc
                # insert into flows_history (flow_id, version, data) with COALESCE MAX+1
                try:
                    await conn.execute(
                        "INSERT INTO flows_history (flow_id, version, data) "
                        "SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb "
                        "ON CONFLICT (flow_id, version) DO NOTHING",
                        (family_id, family_id, flow_json),
                    )
                except Exception:
                    # flows_history may not exist yet if schema not applied — ignore
                    pass

        # counts after
        counts_after = {}
        for tbl in ("families", "pcap_files", "flows"):
            try:
                cur = await conn.execute(f"SELECT count(*) FROM {tbl}")
                row = await cur.fetchone()
                counts_after[tbl] = int(row[0]) if row else 0
            except Exception:
                counts_after[tbl] = 0

        for tbl in ("families", "pcap_files", "flows"):
            before = counts_before.get(tbl, 0)
            after = counts_after.get(tbl, 0)
            diff = after - before
            inserted = diff if diff > 0 else 0
            # need to compute actually inserted vs updated diff via ROW_COUNT? psycopg rowcount for last execute not per table
            # we log diff
            print(f"[seed] {tbl}: before={before} after={after} diff={after - before} (0 diff means idempotent)")

        # Dashboard 10 — iterate families 01-10 through pipeline
        if with_dashboard_run:
            await _run_dashboard_10_async(conn, families)

        await conn.commit()
        return {"before": counts_before, "after": counts_after}
    finally:
        await conn.close()


def _seed_all_sync(dsn: str, families: list[tuple[str, dict]], with_dashboard_run: bool) -> dict:
    if not HAS_PSYCOPG:
        # no postgres driver — simulate counts for dry-run environments
        print("[seed] psycopg not available — skipping DB seed (dry-run mode)")
        return {"before": {}, "after": {}}
    import psycopg as _pg
    conn = _pg.connect(dsn)
    try:
        counts_before = {}
        for tbl in ("families", "pcap_files", "flows"):
            try:
                with conn.cursor() as cur:
                    cur.execute(f"SELECT count(*) FROM {tbl}")
                    row = cur.fetchone()
                    counts_before[tbl] = int(row[0]) if row else 0
            except Exception:
                counts_before[tbl] = 0

        # Single transaction wrapping 60 families
        with conn.transaction():
            for family_id, entry in families:
                display_name = entry.get("description") or entry.get("display_name") or family_id
                port = int(entry.get("port", 587) or 587)
                tls_version = entry.get("tls") or entry.get("tls_version") or "TLS1.2"
                if tls_version not in ("TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3", "none", "unknown"):
                    tls_version = "unknown"
                if tls_version == "unknown":
                    tls_version = "none"
                cipher_suite = entry.get("cipher") or entry.get("cipher_suite") or "ECDHE-RSA-AES128-GCM-SHA256"
                cert_type = entry.get("cert") or entry.get("cert_type") or "rsa2048"
                starttls_mode = entry.get("starttls") or entry.get("starttls_mode") or "upgrade"
                if starttls_mode == "cleartext":
                    starttls_mode = "stripped"
                if starttls_mode not in ("upgrade", "implicit", "stripped", "none"):
                    starttls_mode = "upgrade"
                with conn.cursor() as cur:
                    cur.execute(_families_upsert_sql(), (family_id, display_name, port, tls_version, cipher_suite, cert_type, starttls_mode))

                pcap_path = PCAP_DIR / f"{family_id}.pcap"
                if not pcap_path.exists() and entry.get("pcap"):
                    alt = ROOT / entry["pcap"]
                    if alt.exists():
                        pcap_path = alt
                if pcap_path.exists():
                    data = pcap_path.read_bytes()
                    if len(data) < 100 * 1024 * 1024:
                        sha256 = hashlib.sha256(data).hexdigest()
                        byte_length = len(data)
                        with conn.cursor() as cur2:
                            cur2.execute(_pcap_files_upsert_sql(), (family_id, _pg.Binary(data), sha256, byte_length))

                flow_data = _make_placeholder_flow(family_id, entry, seed=SEED)
                flow_json = json.dumps(flow_data)
                with conn.cursor() as cur3:
                    cur3.execute(_flows_upsert_sql(), (family_id, family_id, flow_json))
                    try:
                        cur3.execute(
                            "INSERT INTO flows_history (flow_id, version, data) "
                            "SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb "
                            "ON CONFLICT (flow_id, version) DO NOTHING",
                            (family_id, family_id, flow_json),
                        )
                    except Exception:
                        pass

        counts_after = {}
        for tbl in ("families", "pcap_files", "flows"):
            try:
                with conn.cursor() as cur:
                    cur.execute(f"SELECT count(*) FROM {tbl}")
                    row = cur.fetchone()
                    counts_after[tbl] = int(row[0]) if row else 0
            except Exception:
                counts_after[tbl] = 0

        for tbl in ("families", "pcap_files", "flows"):
            before = counts_before.get(tbl, 0)
            after = counts_after.get(tbl, 0)
            print(f"[seed] {tbl}: before={before} after={after} diff={after - before} (0 diff means idempotent)")

        if with_dashboard_run:
            _run_dashboard_10_sync(conn, families)

        conn.commit()
        return {"before": counts_before, "after": counts_after}
    finally:
        conn.close()


async def _run_dashboard_10_async(conn, families: list[tuple[str, dict]]) -> None:
    """Iterate families 01-10 reading lab/pcaps/family-*.pcap bytes → pipeline → FlowVerdict → upsert + NOTIFY."""
    # filter 01-10 numeric
    dash_families = [fid for fid, _ in families if 1 <= int(fid.split("-")[1]) <= 10]
    dash_families = sorted(dash_families, key=lambda x: int(x.split("-")[1]))
    print(f"[seed] --run-dashboard processing {len(dash_families)} families 01-10")
    # try import pipeline
    try:
        from api.pipeline import _real_pipeline_for_bytes as _pipeline
        has_pipeline = True
    except Exception:
        _pipeline = None  # type: ignore
        has_pipeline = False
    try:
        from shared.schemas import FlowVerdict as _FV
    except Exception:
        _FV = None  # type: ignore

    for fid in dash_families:
        pcap_path = PCAP_DIR / f"{fid}.pcap"
        if not pcap_path.exists():
            print(f"[seed] dashboard skip {fid} no pcap")
            continue
        data = pcap_path.read_bytes()
        if len(data) >= 100 * 1024 * 1024:
            print(f"[seed] dashboard skip {fid} pcap too large")
            continue
        flows = []
        try:
            if has_pipeline and _pipeline is not None:
                flows = _pipeline(data, f"{fid}.pcap")
            else:
                # fallback to lab/reassembler
                from lab.reassembler.reassemble import reassemble as _reassemble
                import tempfile, pathlib
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tf:
                    tf.write(data); tf.flush(); tmp = tf.name
                try:
                    _reassemble(tmp)
                finally:
                    pathlib.Path(tmp).unlink(missing_ok=True)
                print(f"[seed] fallback reassemble for {fid}")
                flows = []
        except Exception as e:
            print(f"[seed] pipeline error {fid}: {e}")
            continue
        for fv in flows:
            try:
                if _FV is not None:
                    validated = _FV.model_validate(fv.model_dump() if hasattr(fv, "model_dump") else fv)
                    payload = json.dumps(validated.model_dump())
                    flow_id = validated.flow_id
                    family_id = getattr(validated, "family_id", fid) or fid
                else:
                    payload = json.dumps(fv.model_dump() if hasattr(fv, "model_dump") else fv)
                    flow_id = fv.flow_id if hasattr(fv, "flow_id") else fid
                    family_id = fid
                # upsert via transactional path + NOTIFY flows_upsert
                await conn.execute(_flows_upsert_sql(), (flow_id, family_id, payload))
                try:
                    await conn.execute(
                        "INSERT INTO flows_history (flow_id, version, data) "
                        "SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb "
                        "ON CONFLICT (flow_id, version) DO NOTHING",
                        (flow_id, flow_id, payload),
                    )
                except Exception:
                    pass
                try:
                    await conn.execute("SELECT pg_notify('flows_upsert', %s)", (flow_id,))
                except Exception:
                    pass
                print(f"[seed] dashboard upsert flow_id={flow_id} family={family_id}")
            except Exception as e:
                print(f"[seed] dashboard validate/upsert error {fid}: {e}")


def _run_dashboard_10_sync(conn, families: list[tuple[str, dict]]) -> None:
    dash_families = [fid for fid, _ in families if 1 <= int(fid.split("-")[1]) <= 10]
    dash_families = sorted(dash_families, key=lambda x: int(x.split("-")[1]))
    print(f"[seed] --run-dashboard sync processing {len(dash_families)} families 01-10")
    try:
        from api.pipeline import _real_pipeline_for_bytes as _pipeline
        has_pipeline = True
    except Exception:
        _pipeline = None  # type: ignore
        has_pipeline = False
    try:
        from shared.schemas import FlowVerdict as _FV
    except Exception:
        _FV = None  # type: ignore

    for fid in dash_families:
        pcap_path = PCAP_DIR / f"{fid}.pcap"
        if not pcap_path.exists():
            continue
        data = pcap_path.read_bytes()
        if len(data) >= 100 * 1024 * 1024:
            continue
        flows = []
        try:
            if has_pipeline and _pipeline is not None:
                flows = _pipeline(data, f"{fid}.pcap")
        except Exception as e:
            print(f"[seed] pipeline error {fid}: {e}")
            continue
        for fv in flows:
            try:
                if _FV is not None:
                    validated = _FV.model_validate(fv.model_dump() if hasattr(fv, "model_dump") else fv)
                    payload = json.dumps(validated.model_dump())
                    flow_id = validated.flow_id
                    family_id = getattr(validated, "family_id", fid) or fid
                else:
                    payload = json.dumps(fv.model_dump() if hasattr(fv, "model_dump") else fv)
                    flow_id = fv.flow_id if hasattr(fv, "flow_id") else fid
                    family_id = fid
                with conn.cursor() as cur:
                    cur.execute(_flows_upsert_sql(), (flow_id, family_id, payload))
                    try:
                        cur.execute(
                            "INSERT INTO flows_history (flow_id, version, data) "
                            "SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb "
                            "ON CONFLICT (flow_id, version) DO NOTHING",
                            (flow_id, flow_id, payload),
                        )
                    except Exception:
                        pass
                    try:
                        cur.execute("SELECT pg_notify('flows_upsert', %s)", (flow_id,))
                    except Exception:
                        pass
                print(f"[seed] dashboard upsert flow_id={flow_id}")
            except Exception as e:
                print(f"[seed] dashboard error {fid}: {e}")


def _dry_run(upsert_families: bool = False) -> None:
    families = _get_manifest_families(upsert_families=upsert_families)
    print(f"60 families" if len(families) == 60 else f"{len(families)} families")
    # numeric order proof: list in lpad order
    for fid, entry in families:
        print(f"  {fid} port={entry.get('port')} tls={entry.get('tls')} cipher={entry.get('cipher')} cert={entry.get('cert')} starttls={entry.get('starttls')} source_id={deterministic_source_id(fid)[:8]}")
    # show ordering avoids lexical bug: family-02 before family-11
    if families:
        order = [fid for fid, _ in families]
        # verify numeric vs lexical
        lexical = sorted([fid for fid, _ in families])
        if order != lexical:
            print(f"[dry-run] numeric order verified: {order[:5]} ... lexical would be {lexical[:5]} (avoids 11/100/2 bug)")
        # lpad sql example
        print("ORDER BY lpad(substring(family_id from 8)::int) — numeric order applied")


def main() -> None:
    parser = argparse.ArgumentParser(description="CipherCrest seed — startup-idempotent deterministic seed + run-dashboard 10")
    parser.add_argument("--dsn", type=str, default=os.environ.get("POSTGRES_DSN", DEFAULT_DSN), help="Postgres DSN (default POSTGRES_DSN env)")
    parser.add_argument("--dry-run", action="store_true", help="print 60 families ordered lpad without DB")
    parser.add_argument("--run-dashboard", action="store_true", help="iterate families 01-10 through pipeline → FlowVerdict → upsert + NOTIFY flows_upsert")
    parser.add_argument("--upsert-families", action="store_true", help="allow adding family-61+ without docker compose down -v (seeds all canonical families)")
    # alias per spec: --upsert-families
    parser.add_argument("--with-dashboard", dest="run_dashboard_alias", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    with_dashboard = bool(args.run_dashboard or args.run_dashboard_alias)

    if args.dry_run:
        _dry_run(upsert_families=bool(args.upsert_families))
        return

    # Not dry-run: run seed_all sync wrapper for CLI
    async def _amain():
        try:
            await seed_all(dsn=args.dsn, with_dashboard_run=with_dashboard, upsert_families=bool(args.upsert_families))
        except Exception as e:
            # if async fails due to no async driver, fallback to sync
            print(f"[seed] async error: {e}")
            try:
                _sync_wait_for_pg(args.dsn)
                fam = _get_manifest_families(upsert_families=bool(args.upsert_families))
                _seed_all_sync(args.dsn, fam, with_dashboard)
            except Exception as e2:
                print(f"[seed] sync fallback error: {e2}", file=sys.stderr)
                sys.exit(1)

    # detect if we are in async context or need asyncio.run
    try:
        asyncio.run(_amain())
    except RuntimeError as re:
        # already in event loop (e.g. pytest)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(_amain())


if __name__ == "__main__":
    main()
