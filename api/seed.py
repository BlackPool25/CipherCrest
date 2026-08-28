"""
api/seed.py — startup-idempotent deterministic seed + run-dashboard 10 + comprehensive ingest

Usage:
  python -m api.seed --dry-run               # prints all actual families (680) ordered lpad numeric without DB, excludes jitter
  python -m api.seed --dry-run --full        # prints all actual families (680) ordered lpad, excludes jitter (alias for default, includes sqlite/fixtures/model_runs)
  python -m api.seed                          # seeds all actual families (680) + pcap_files (excl jitter) + flows in single BEGIN
  python -m api.seed --full                   # alias: seeds all actual families (680) + all pcaps excluding jitter + sqlite + fixtures + model_runs
  python -m api.seed --run-dashboard          # also replays lab/pcaps/family-01..10 → reassemble → FlowVerdict → upsert + NOTIFY
  python -m api.seed --upsert-families        # alias for --full (seeds all actual families without down -v, excludes jitter)
  python -m api.seed --dsn postgresql://...  # override POSTGRES_DSN
  python -m api.seed --help                   # shows --run-dashboard, --dry-run, --upsert-families, --full

Idempotency:
  families:  INSERT ... ON CONFLICT (family_id) DO UPDATE SET ... WHERE IS DISTINCT FROM (avoid WAL when unchanged)
  pcap_files: INSERT ... ON CONFLICT (family_id,sha256) DO UPDATE SET data=... WHERE IS DISTINCT FROM
  flows:     INSERT ... ON CONFLICT (flow_id) DO UPDATE SET data=... WHERE IS DISTINCT FROM
  model_runs: INSERT ... ON CONFLICT (model_name) DO UPDATE SET ... WHERE IS DISTINCT FROM
  Deterministic source_id = hashlib.sha256((family_id + str(seed)).encode()).hexdigest()  # never uuid4
  Ordering: ORDER BY lpad(substring(family_id from 8)::int) numeric — python mimics via _family_sort_key
  Transaction: single BEGIN wrapping families (chunked 50 at a time for 680) — never per-family commit
  BYTEA: looped psycopg.Binary for <50MB (total pcaps ~115KB); COPY BINARY alternative documented but not needed
  Jitter: excluded per user — any family_id containing 'jitter' is skipped (families + pcaps)

Do NOT use docker-entrypoint-initdb.d/02_seed.sql — only 01_schema.sql is entrypoint.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import pathlib
import pickle
import re
import sqlite3
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
SQLITE_DB = ROOT / "api/flows.db"
FIXTURES_DIR = ROOT / "shared/fixtures"
LOCKED_DIR = FIXTURES_DIR / "locked_external"
MODELS_DIR = ROOT / "models"
EVAL_METRICS = ROOT / "eval/metrics.json"

SEED = 0  # deterministic seed for source_id

CANON_RE = re.compile(r"^family-\d+$")


def deterministic_source_id(family_id: str, seed: int = SEED) -> str:
    """Deterministic source_id — never uuid4."""
    return hashlib.sha256((family_id + str(seed)).encode()).hexdigest()


def _family_sort_key(fid: str) -> tuple[int, int, str]:
    """Numeric lpad ordering for actual families (jitter excluded).

    family-02          -> (2, -1, '')
    family-100         -> (100, -1, '')
    family-locked-01   -> (9999, 01, 'locked') sorts after numeric families
    (jitter variants would have been excluded before sorting)
    """
    if fid.startswith("family-locked-"):
        try:
            n = int(fid.split("-")[-1])
        except Exception:
            n = 9999
        return (9999, n, fid)
    if "jitter" in fid:
        # jitter families should have been filtered out, but keep stable sort if encountered
        base, js = fid.split("-jitter-", 1) if "-jitter-" in fid else (fid, "0")
        try:
            base_num = int(base.split("-")[1])
        except Exception:
            base_num = 9999
        try:
            jit_num = int(js)
        except Exception:
            jit_num = 0
        return (base_num, jit_num, fid)
    # canonical family-XX or family-XXX
    try:
        num = int(fid.split("-")[1])
        return (num, -1, fid)
    except Exception:
        return (9999, -1, fid)


def _sorted_family_keys(manifest_data: dict, upsert_families: bool = False, full: bool = False) -> list[str]:
    """Return family keys sorted numeric via lpad(substring(... )::int).

    Always excludes jitter variants (any key containing 'jitter').
    - default and full/upsert: all actual families matching ^family-\\d+$ (680), sorted numeric.
    Locked families are handled separately via _get_locked_families when full=True.
    """
    # exclude jitter variants
    actual_keys = [k for k in manifest_data.keys() if CANON_RE.match(k) and "jitter" not in k.lower()]
    # also explicitly skip any jitter substring even if regex matched (defensive)
    actual_keys = [k for k in actual_keys if "jitter" not in k]
    return sorted(actual_keys, key=_family_sort_key)


def _get_manifest_families(upsert_families: bool = False, full: bool = False) -> list[tuple[str, dict]]:
    if not MANIFEST.exists():
        return []
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    keys = _sorted_family_keys(data, upsert_families=upsert_families, full=full)
    return [(k, data[k]) for k in keys]


def _discover_pcap_paths() -> list[tuple[str, pathlib.Path]]:
    """Discover every pcap present on filesystem to ingest as BYTEA, excluding jitter.

    Returns list of (family_id, Path) sorted via _family_sort_key.
    Covers: lab/pcaps/*.pcap (50 base, jitter excluded), shared/fixtures/locked_external/*.pcap (30),
    plus lab/pcaps/coherent/* if exists. Jittered pcaps (lab/pcaps/jittered/*) are excluded per user.
    """
    found: list[tuple[str, pathlib.Path]] = []
    # base pcaps (exclude jitter)
    for p in sorted(PCAP_DIR.glob("*.pcap")):
        if p.name == "jittered.pcap":
            continue
        fid = p.stem  # family-01
        if "jitter" in fid:
            continue
        found.append((fid, p))
    # jittered directory is intentionally excluded — user: "Don't put jitters but other actual families yes"
    # coherent if exists (future)
    coherent_dir = PCAP_DIR / "coherent"
    if coherent_dir.exists():
        for p in sorted(coherent_dir.glob("*.pcap")):
            fid = p.stem
            if "jitter" in fid:
                continue
            found.append((fid, p))
    # locked external
    if LOCKED_DIR.exists():
        for p in sorted(LOCKED_DIR.glob("*.pcap")):
            fid = p.stem  # family-locked-01
            found.append((fid, p))
    # dedup by family_id, sorted
    # keep first occurrence if duplicate stem across dirs (unlikely)
    uniq: dict[str, pathlib.Path] = {}
    for fid, path in found:
        if fid not in uniq:
            uniq[fid] = path
    sorted_items = sorted(uniq.items(), key=lambda kv: _family_sort_key(kv[0]))
    return sorted_items


def _get_locked_families() -> list[tuple[str, dict]]:
    """Generate family entries for locked_external pcaps not in manifest."""
    out: list[tuple[str, dict]] = []
    if not LOCKED_DIR.exists():
        return out
    for p in sorted(LOCKED_DIR.glob("*.pcap")):
        fid = p.stem
        # minimal manifest-like entry for families table
        entry = {
            "port": 587,
            "tls": "TLS1.2",
            "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
            "kex": "ECDHE",
            "cert": "rsa2048",
            "starttls": "upgrade",
            "description": f"Locked external {fid} deterministic",
            "environment_id": f"{fid}__locked",
            "pcap": str(p.relative_to(ROOT)),
        }
        out.append((fid, entry))
    return sorted(out, key=lambda kv: _family_sort_key(kv[0]))


# ---------------------------------------------------------------------------
# pg helpers
# ---------------------------------------------------------------------------

async def _wait_for_pg(dsn: str, retries: int = 5, base_delay: float = 0.5) -> None:
    """Wait for pg_isready with exponential backoff 0.5s,1s,2s,4s,8s — logs retries."""
    for attempt in range(retries):
        delay = base_delay * (2 ** attempt)
        try:
            if HAS_PSYCOPG and AsyncConnection is not None:
                conn = await AsyncConnection.connect(dsn, connect_timeout=1)
                await conn.close()
                if attempt > 0:
                    print(f"[seed] pg_isready retry {attempt}/{retries} succeeded after {delay/2:.1f}s backoff")
                return
            else:
                import psycopg as _pg  # type: ignore
                c = _pg.connect(dsn, connect_timeout=1)
                c.close()
                return
        except Exception as e:
            print(f"[seed] pg_isready attempt {attempt+1}/{retries} failed: {e} — retry in {delay:.1f}s (exponential)")
            if attempt == retries - 1:
                raise RuntimeError(f"pg_isready failed after {retries} retries: {e}") from e
            try:
                await asyncio.sleep(delay)
            except Exception:
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
                return
        except Exception as e:
            print(f"[seed] pg_isready sync attempt {attempt+1}/{retries} failed: {e} — retry in {delay:.1f}s")
            if attempt == retries - 1:
                raise RuntimeError(f"pg_isready sync failed after {retries}: {e}") from e
            time.sleep(delay)


def _families_upsert_sql() -> str:
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


def _model_runs_upsert_sql() -> str:
    return """
    INSERT INTO model_runs (model_name, trained_at, params, metrics, artifact_sha, n_eff, dataset_caveat)
    VALUES (%s, %s, %s::jsonb, %s::jsonb, %s, %s, %s)
    ON CONFLICT (model_name) DO UPDATE SET
        trained_at = EXCLUDED.trained_at,
        params = EXCLUDED.params,
        metrics = EXCLUDED.metrics,
        artifact_sha = EXCLUDED.artifact_sha,
        n_eff = EXCLUDED.n_eff,
        dataset_caveat = EXCLUDED.dataset_caveat
    WHERE model_runs.params IS DISTINCT FROM EXCLUDED.params
       OR model_runs.metrics IS DISTINCT FROM EXCLUDED.metrics
       OR model_runs.artifact_sha IS DISTINCT FROM EXCLUDED.artifact_sha
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


def _try_real_pipeline(data: bytes, hint_name: str) -> list:
    """Try _real_pipeline_for_bytes for pcap bytes, return list of FlowVerdicts or [] if unavailable."""
    try:
        from api.pipeline import _real_pipeline_for_bytes as _pipeline  # type: ignore
    except Exception as e:
        print(f"[seed] pipeline import failed for {hint_name}: {e}")
        return []
    try:
        flows = _pipeline(data, hint_name)
        # validate each via FlowVerdict.model_validate
        validated = []
        try:
            from shared.schemas import FlowVerdict as _FV  # type: ignore
        except Exception:
            _FV = None  # type: ignore
        for fv in flows:
            try:
                if _FV is not None:
                    v = _FV.model_validate(fv.model_dump() if hasattr(fv, "model_dump") else fv)
                    validated.append(v)
                else:
                    validated.append(fv)
            except Exception as ve:
                print(f"[seed] FlowVerdict validate failed {hint_name}: {ve}")
                continue
        if validated:
            print(f"[seed] real pipeline {hint_name} → {len(validated)} FlowVerdicts")
        else:
            print(f"[seed] real pipeline {hint_name} returned 0 flows, fallback to placeholder")
        return validated
    except Exception as e:
        print(f"[seed] pipeline error {hint_name}: {e}")
        return []


# ---------------------------------------------------------------------------
# model_runs helpers
# ---------------------------------------------------------------------------

def _sanitize_json(obj):
    """Recursively sanitize for Postgres JSONB: NaN/inf -> None, bytes->str, non-serializable->str."""
    import math
    if isinstance(obj, dict):
        return {str(k): _sanitize_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize_json(v) for v in obj]
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return None
        return obj
    # numpy floats
    try:
        import numpy as _np  # type: ignore
        if isinstance(obj, _np.floating):
            f = float(obj)
            if math.isnan(f) or math.isinf(f):
                return None
            return f
        if isinstance(obj, _np.integer):
            return int(obj)
        if isinstance(obj, _np.ndarray):
            return _sanitize_json(obj.tolist())
    except Exception:
        pass
    try:
        json.dumps(obj, allow_nan=False)
        return obj
    except Exception:
        return str(obj)


def _seed_model_runs_sync(conn) -> int:
    """Insert model_runs from models/*.pkl metadata, idempotent."""
    # gather metrics from eval/metrics.json if available
    metrics_data = {}
    if EVAL_METRICS.exists():
        try:
            metrics_data = json.loads(EVAL_METRICS.read_text())
        except Exception:
            metrics_data = {}
    # dataset_caveat from splits if available
    dataset_caveat = "WEAK SUPERVISION: labels rule-derived weak supervision; n_eff 500 quality target"
    try:
        splits = ROOT / "assessment/splits.json"
        if splits.exists():
            sj = json.loads(splits.read_text())
            dataset_caveat = sj.get("dataset_caveat", dataset_caveat) or dataset_caveat
    except Exception:
        pass

    pkls = sorted(MODELS_DIR.glob("*.pkl"))
    inserted = 0
    for pkl_path in pkls:
        try:
            data = pkl_path.read_bytes()
            sha = hashlib.sha256(data).hexdigest()
            # load pickle to extract params
            try:
                obj = pickle.loads(data)
                params = {}
                # XGB wrapper
                if hasattr(obj, "get_params"):
                    try:
                        params = obj.get_params()
                        params = _sanitize_json(params)
                    except Exception:
                        params = {"model_type": type(obj).__name__}
                else:
                    params = {"model_type": type(obj).__name__}
                params = _sanitize_json(params)
                # truncate large params
                try:
                    if len(json.dumps(params, allow_nan=False)) > 4000:
                        params = {"model_type": type(obj).__name__, "truncated": True}
                except Exception:
                    params = {"model_type": type(obj).__name__, "truncated": True}
            except Exception:
                params = {"model_type": pkl_path.stem}

            model_name = pkl_path.stem  # risk_clf, anomaly, etc.
            # pick metrics slice for this model if available
            metrics = {}
            if metrics_data:
                # metrics.json has top-level 'risk' and 'anomaly' keys
                if "risk" in model_name and "risk" in metrics_data:
                    metrics = metrics_data["risk"]
                elif "anomaly" in model_name and "anomaly" in metrics_data:
                    metrics = metrics_data["anomaly"]
                else:
                    metrics = metrics_data.get(model_name, metrics_data.get("risk", {}))
            # n_eff from metrics or default
            n_eff = None
            try:
                if isinstance(metrics, dict):
                    n_eff = metrics.get("n_eff") or metrics.get("n_risk") or 500
                    if isinstance(n_eff, str):
                        n_eff = None
            except Exception:
                n_eff = 500

            # trained_at from file mtime
            try:
                mtime = pkl_path.stat().st_mtime
                import datetime
                trained_at = datetime.datetime.fromtimestamp(mtime, tz=datetime.timezone.utc).isoformat()
            except Exception:
                trained_at = None

            metrics = _sanitize_json(metrics) if metrics else {}
            with conn.cursor() as cur:
                cur.execute(
                    _model_runs_upsert_sql(),
                    (model_name, trained_at, json.dumps(params, allow_nan=False) if params else "{}", json.dumps(metrics, allow_nan=False) if metrics else "{}", sha, n_eff, dataset_caveat),
                )
                try:
                    cur.execute(
                        "INSERT INTO model_runs_history (model_name, version, trained_at, params, metrics, artifact_sha, n_eff, dataset_caveat) "
                        "SELECT %s, COALESCE((SELECT MAX(version) FROM model_runs_history WHERE model_name=%s),0)+1, %s, %s::jsonb, %s::jsonb, %s, %s, %s "
                        "ON CONFLICT (model_name, version) DO NOTHING",
                        (model_name, model_name, trained_at, json.dumps(params, allow_nan=False) if params else "{}", json.dumps(metrics, allow_nan=False) if metrics else "{}", sha, n_eff, dataset_caveat),
                    )
                except Exception:
                    pass
            inserted += 1
        except Exception as e:
            print(f"[seed] model_runs {pkl_path.name} error: {e}")
            continue
    print(f"[seed] model_runs seeded {inserted} models from {MODELS_DIR}")
    return inserted


async def _seed_model_runs_async(conn) -> int:
    metrics_data = {}
    if EVAL_METRICS.exists():
        try:
            metrics_data = json.loads(EVAL_METRICS.read_text())
        except Exception:
            metrics_data = {}
    dataset_caveat = "WEAK SUPERVISION: labels rule-derived weak supervision; n_eff 500 quality target"
    try:
        splits = ROOT / "assessment/splits.json"
        if splits.exists():
            sj = json.loads(splits.read_text())
            dataset_caveat = sj.get("dataset_caveat", dataset_caveat) or dataset_caveat
    except Exception:
        pass
    pkls = sorted(MODELS_DIR.glob("*.pkl"))
    inserted = 0
    for pkl_path in pkls:
        try:
            data = pkl_path.read_bytes()
            sha = hashlib.sha256(data).hexdigest()
            try:
                obj = pickle.loads(data)
                params = {}
                if hasattr(obj, "get_params"):
                    try:
                        params = obj.get_params()
                        safe_params = {}
                        for k, v in params.items():
                            try:
                                json.dumps(v)
                                safe_params[k] = v
                            except Exception:
                                safe_params[k] = str(v)
                        params = safe_params
                    except Exception:
                        params = {"model_type": type(obj).__name__}
                else:
                    params = {"model_type": type(obj).__name__}
                if len(json.dumps(params)) > 4000:
                    params = {"model_type": type(obj).__name__, "truncated": True}
            except Exception:
                params = {"model_type": pkl_path.stem}
            model_name = pkl_path.stem
            metrics = {}
            if metrics_data:
                if "risk" in model_name and "risk" in metrics_data:
                    metrics = metrics_data["risk"]
                elif "anomaly" in model_name and "anomaly" in metrics_data:
                    metrics = metrics_data["anomaly"]
                else:
                    metrics = metrics_data.get(model_name, metrics_data.get("risk", {}))
            n_eff = None
            try:
                if isinstance(metrics, dict):
                    n_eff = metrics.get("n_eff") or metrics.get("n_risk") or 500
                    if isinstance(n_eff, str):
                        n_eff = None
            except Exception:
                n_eff = 500
            try:
                mtime = pkl_path.stat().st_mtime
                import datetime
                trained_at = datetime.datetime.fromtimestamp(mtime, tz=datetime.timezone.utc).isoformat()
            except Exception:
                trained_at = None
            await conn.execute(
                _model_runs_upsert_sql(),
                (model_name, trained_at, json.dumps(params) if params else "{}", json.dumps(metrics) if metrics else "{}", sha, n_eff, dataset_caveat),
            )
            try:
                await conn.execute(
                    "INSERT INTO model_runs_history (model_name, version, trained_at, params, metrics, artifact_sha, n_eff, dataset_caveat) "
                    "SELECT %s, COALESCE((SELECT MAX(version) FROM model_runs_history WHERE model_name=%s),0)+1, %s, %s::jsonb, %s::jsonb, %s, %s, %s "
                    "ON CONFLICT (model_name, version) DO NOTHING",
                    (model_name, model_name, trained_at, json.dumps(params) if params else "{}", json.dumps(metrics) if metrics else "{}", sha, n_eff, dataset_caveat),
                )
            except Exception:
                pass
            inserted += 1
        except Exception as e:
            print(f"[seed] model_runs async {pkl_path.name} error: {e}")
            continue
    print(f"[seed] model_runs async seeded {inserted} models")
    return inserted


# ---------------------------------------------------------------------------
# sqlite migration
# ---------------------------------------------------------------------------

def _migrate_sqlite_flows_sync(conn, dsn_for_binary=None) -> int:
    """Migrate api/flows.db sqlite rows into Postgres flows if not already present."""
    if not SQLITE_DB.exists():
        print("[seed] sqlite migration skip: no api/flows.db")
        return 0
    try:
        sconn = sqlite3.connect(str(SQLITE_DB))
        sconn.row_factory = sqlite3.Row
        cur = sconn.cursor()
        cur.execute("SELECT flow_id, data FROM flows")
        rows = cur.fetchall()
        print(f"[seed] sqlite migration found {len(rows)} rows in api/flows.db")
        migrated = 0
        import psycopg as _pg  # for Binary if needed but flows are JSON
        for r in rows:
            try:
                flow_id = r["flow_id"]
                data_str = r["data"]
                if not data_str:
                    continue
                data = json.loads(data_str) if isinstance(data_str, str) else data_str
                # ensure flow_id in data
                if isinstance(data, dict) and "flow_id" not in data:
                    data["flow_id"] = flow_id
                # validate via FlowVerdict if possible
                try:
                    from shared.schemas import FlowVerdict as _FV
                    _FV.model_validate(data)
                except Exception as ve:
                    # allow invalid but try to coerce minimal
                    print(f"[seed] sqlite FlowVerdict validate skip {flow_id}: {ve}")
                    continue
                family_id = data.get("family_id") or flow_id
                # check family FK
                _fid = family_id
                try:
                    with conn.cursor() as chk:
                        chk.execute("SELECT 1 FROM families WHERE family_id=%s", (_fid,))
                        if chk.fetchone() is None:
                            # try to find family prefix before jitter? fallback to None to avoid FK violation
                            # create minimal family row for sqlite flow if not exists
                            try:
                                chk.execute(
                                    "INSERT INTO families (family_id, display_name, port, tls_version, cipher_suite, cert_type, starttls_mode, status) "
                                    "VALUES (%s,%s,587,'TLS1.2','ECDHE-RSA-AES128-GCM-SHA256','rsa2048','upgrade','not_run') ON CONFLICT DO NOTHING",
                                    (_fid, _fid),
                                )
                            except Exception:
                                _fid = None
                                family_id = None
                except Exception:
                    _fid = None
                payload = json.dumps(data)
                fw = family_id if _fid else None
                if fw is None:
                    # use flow_id as family_id if FK fails, else NULL
                    fw = None
                else:
                    fw = family_id
                with conn.cursor() as cur2:
                    cur2.execute(_flows_upsert_sql(), (flow_id, fw, payload))
                    try:
                        cur2.execute(
                            "INSERT INTO flows_history (flow_id, version, data) "
                            "SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb "
                            "ON CONFLICT (flow_id, version) DO NOTHING",
                            (flow_id, flow_id, payload),
                        )
                    except Exception:
                        pass
                migrated += 1
            except Exception as e:
                print(f"[seed] sqlite migrate row error: {e}")
                continue
        sconn.close()
        print(f"[seed] sqlite migration done {migrated}/{len(rows)} upserted")
        return migrated
    except Exception as e:
        print(f"[seed] sqlite migration failed: {e}")
        return 0


async def _migrate_sqlite_flows_async(conn) -> int:
    if not SQLITE_DB.exists():
        print("[seed] sqlite migration async skip: no api/flows.db")
        return 0
    try:
        sconn = sqlite3.connect(str(SQLITE_DB))
        sconn.row_factory = sqlite3.Row
        cur = sconn.cursor()
        cur.execute("SELECT flow_id, data FROM flows")
        rows = cur.fetchall()
        print(f"[seed] sqlite async migration found {len(rows)} rows")
        migrated = 0
        for r in rows:
            try:
                flow_id = r["flow_id"]
                data_str = r["data"]
                if not data_str:
                    continue
                data = json.loads(data_str) if isinstance(data_str, str) else data_str
                if isinstance(data, dict) and "flow_id" not in data:
                    data["flow_id"] = flow_id
                try:
                    from shared.schemas import FlowVerdict as _FV
                    _FV.model_validate(data)
                except Exception as ve:
                    print(f"[seed] sqlite async validate skip {flow_id}: {ve}")
                    continue
                family_id = data.get("family_id") or flow_id
                _fid = family_id
                try:
                    chk = await conn.execute("SELECT 1 FROM families WHERE family_id=%s", (_fid,))
                    row = await chk.fetchone()
                    if row is None:
                        try:
                            await conn.execute(
                                "INSERT INTO families (family_id, display_name, port, tls_version, cipher_suite, cert_type, starttls_mode, status) "
                                "VALUES (%s,%s,587,'TLS1.2','ECDHE-RSA-AES128-GCM-SHA256','rsa2048','upgrade','not_run') ON CONFLICT DO NOTHING",
                                (_fid, _fid),
                            )
                        except Exception:
                            _fid = None
                except Exception:
                    _fid = None
                payload = json.dumps(data)
                fw = family_id if _fid else None
                await conn.execute(_flows_upsert_sql(), (flow_id, fw, payload))
                try:
                    await conn.execute(
                        "INSERT INTO flows_history (flow_id, version, data) "
                        "SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb "
                        "ON CONFLICT (flow_id, version) DO NOTHING",
                        (flow_id, flow_id, payload),
                    )
                except Exception:
                    pass
                migrated += 1
            except Exception as e:
                print(f"[seed] sqlite async row error: {e}")
                continue
        sconn.close()
        print(f"[seed] sqlite async migration done {migrated}/{len(rows)}")
        return migrated
    except Exception as e:
        print(f"[seed] sqlite async migration failed: {e}")
        return 0


# ---------------------------------------------------------------------------
# fixtures ingestion
# ---------------------------------------------------------------------------

def _ingest_fixtures_sync(conn) -> int:
    """Ingest shared/fixtures/*.json flows (family-*.json, censys_sampled etc) as flows."""
    count = 0
    extra = FIXTURES_DIR / "censys_sampled_200.json"
    json_paths = sorted(FIXTURES_DIR.glob("family-*.json"))
    adv = sorted((FIXTURES_DIR / "adversarial").glob("*.json")) if (FIXTURES_DIR / "adversarial").exists() else []
    json_paths.extend(adv)
    # censys sample: ingest a few as separate flows but not required; ingest 1 to verify
    if extra.exists():
        # ingest as fixture but flow_id will be from file content
        try:
            data = json.loads(extra.read_text())
            # censys file is list of 200 objects; pick first 5 as sample flows
            if isinstance(data, list) and data:
                for obj in data[:5]:
                    try:
                        # obj has id like censys-0001
                        flow_id = obj.get("flow_id") or obj.get("id") or f"censys-{count}"
                        # need to map censys raw to FlowVerdict? use minimal placeholder
                        # skip if not valid FlowVerdict, just create minimal
                        from shared.schemas import FlowVerdict as _FV
                        # build minimal dict if raw censys not FlowVerdict
                        if "tls" not in obj:
                            continue
                        _FV.model_validate(obj)
                        family_id = obj.get("family_id") or flow_id
                        payload = json.dumps(obj)
                        _fid = family_id
                        try:
                            with conn.cursor() as chk:
                                chk.execute("SELECT 1 FROM families WHERE family_id=%s", (_fid,))
                                if chk.fetchone() is None:
                                    chk.execute(
                                        "INSERT INTO families (family_id, display_name, port, tls_version, cipher_suite, cert_type, starttls_mode, status) "
                                        "VALUES (%s,%s,587,'TLS1.2','ECDHE-RSA-AES128-GCM-SHA256','rsa2048','upgrade','not_run') ON CONFLICT DO NOTHING",
                                        (_fid, _fid),
                                    )
                        except Exception:
                            _fid = None
                        with conn.cursor() as cur:
                            cur.execute(_flows_upsert_sql(), (flow_id, _fid, payload))
                            try:
                                cur.execute(
                                    "INSERT INTO flows_history (flow_id, version, data) "
                                    "SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb "
                                    "ON CONFLICT (flow_id, version) DO NOTHING",
                                    (flow_id, flow_id, payload),
                                )
                            except Exception:
                                pass
                        count += 1
                    except Exception:
                        continue
        except Exception as e:
            print(f"[seed] fixtures censys error: {e}")

    for jp in json_paths:
        try:
            raw = json.loads(jp.read_text())
            # raw may be list or dict
            objs = [raw] if isinstance(raw, dict) else raw if isinstance(raw, list) else []
            for obj in objs[:1]:  # each family json is single FlowVerdict
                try:
                    from shared.schemas import FlowVerdict as _FV
                    _FV.model_validate(obj)
                    flow_id = obj.get("flow_id") or jp.stem
                    family_id = obj.get("family_id") or flow_id
                    payload = json.dumps(obj)
                    _fid = family_id
                    try:
                        with conn.cursor() as chk:
                            chk.execute("SELECT 1 FROM families WHERE family_id=%s", (_fid,))
                            if chk.fetchone() is None:
                                # family should already exist from manifest, but handle
                                chk.execute(
                                    "INSERT INTO families (family_id, display_name, port, tls_version, cipher_suite, cert_type, starttls_mode, status) "
                                    "VALUES (%s,%s,587,'TLS1.2','ECDHE-RSA-AES128-GCM-SHA256','rsa2048','upgrade','not_run') ON CONFLICT DO NOTHING",
                                    (_fid, _fid),
                                )
                    except Exception:
                        _fid = None
                    with conn.cursor() as cur:
                        cur.execute(_flows_upsert_sql(), (flow_id, _fid, payload))
                        try:
                            cur.execute(
                                "INSERT INTO flows_history (flow_id, version, data) "
                                "SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb "
                                "ON CONFLICT (flow_id, version) DO NOTHING",
                                (flow_id, flow_id, payload),
                            )
                        except Exception:
                            pass
                    count += 1
                except Exception as ve:
                    print(f"[seed] fixtures validate skip {jp.name}: {ve}")
                    continue
        except Exception as e:
            print(f"[seed] fixtures {jp.name} error: {e}")
            continue
    print(f"[seed] fixtures seeded {count} flows from {len(json_paths)} fixture files")
    return count


async def _ingest_fixtures_async(conn) -> int:
    count = 0
    json_paths = sorted(FIXTURES_DIR.glob("family-*.json"))
    adv = sorted((FIXTURES_DIR / "adversarial").glob("*.json")) if (FIXTURES_DIR / "adversarial").exists() else []
    json_paths.extend(adv)
    extra = FIXTURES_DIR / "censys_sampled_200.json"
    if extra.exists():
        try:
            data = json.loads(extra.read_text())
            if isinstance(data, list) and data:
                for obj in data[:5]:
                    try:
                        if "tls" not in obj:
                            continue
                        from shared.schemas import FlowVerdict as _FV
                        _FV.model_validate(obj)
                        flow_id = obj.get("flow_id") or obj.get("id") or f"censys-{count}"
                        family_id = obj.get("family_id") or flow_id
                        payload = json.dumps(obj)
                        _fid = family_id
                        try:
                            chk = await conn.execute("SELECT 1 FROM families WHERE family_id=%s", (_fid,))
                            row = await chk.fetchone()
                            if row is None:
                                await conn.execute(
                                    "INSERT INTO families (family_id, display_name, port, tls_version, cipher_suite, cert_type, starttls_mode, status) "
                                    "VALUES (%s,%s,587,'TLS1.2','ECDHE-RSA-AES128-GCM-SHA256','rsa2048','upgrade','not_run') ON CONFLICT DO NOTHING",
                                    (_fid, _fid),
                                )
                        except Exception:
                            _fid = None
                        await conn.execute(_flows_upsert_sql(), (flow_id, _fid, payload))
                        try:
                            await conn.execute(
                                "INSERT INTO flows_history (flow_id, version, data) "
                                "SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb "
                                "ON CONFLICT (flow_id, version) DO NOTHING",
                                (flow_id, flow_id, payload),
                            )
                        except Exception:
                            pass
                        count += 1
                    except Exception:
                        continue
        except Exception as e:
            print(f"[seed] fixtures async censys error: {e}")

    for jp in json_paths:
        try:
            raw = json.loads(jp.read_text())
            objs = [raw] if isinstance(raw, dict) else raw if isinstance(raw, list) else []
            for obj in objs[:1]:
                try:
                    from shared.schemas import FlowVerdict as _FV
                    _FV.model_validate(obj)
                    flow_id = obj.get("flow_id") or jp.stem
                    family_id = obj.get("family_id") or flow_id
                    payload = json.dumps(obj)
                    _fid = family_id
                    try:
                        chk = await conn.execute("SELECT 1 FROM families WHERE family_id=%s", (_fid,))
                        row = await chk.fetchone()
                        if row is None:
                            await conn.execute(
                                "INSERT INTO families (family_id, display_name, port, tls_version, cipher_suite, cert_type, starttls_mode, status) "
                                "VALUES (%s,%s,587,'TLS1.2','ECDHE-RSA-AES128-GCM-SHA256','rsa2048','upgrade','not_run') ON CONFLICT DO NOTHING",
                                (_fid, _fid),
                            )
                    except Exception:
                        _fid = None
                    await conn.execute(_flows_upsert_sql(), (flow_id, _fid, payload))
                    try:
                        await conn.execute(
                            "INSERT INTO flows_history (flow_id, version, data) "
                            "SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb "
                            "ON CONFLICT (flow_id, version) DO NOTHING",
                            (flow_id, flow_id, payload),
                        )
                    except Exception:
                        pass
                    count += 1
                except Exception as ve:
                    print(f"[seed] fixtures async validate skip {jp.name}: {ve}")
                    continue
        except Exception as e:
            print(f"[seed] fixtures async {jp.name} error: {e}")
            continue
    print(f"[seed] fixtures async seeded {count} flows")
    return count


# ---------------------------------------------------------------------------
# main seed logic
# ---------------------------------------------------------------------------

async def seed_all(dsn: str | None = None, with_dashboard_run: bool = False, upsert_families: bool = False, full: bool = False) -> dict:
    """
    Startup-idempotent deterministic seed.

    - Waits for pg_isready retry 5×500ms exponential (0.5,1,2,4,8s)
    - In single transaction order families→pcap_files→flows (BEGIN wrapping, chunked 50 for large full)
    - Bulk BYTEA via looped psycopg.Binary (<50MB) — COPY BINARY documented as alternative for >50MB
    - Excludes jitter variants (family-*-jitter-*) per user; ingests all actual families (680) matching ^family-\\d+$.

    Returns dict with counts diffs.
    """
    if upsert_families:
        full = True
    dsn = dsn or DEFAULT_DSN
    use_async = HAS_PSYCOPG and AsyncConnection is not None
    try:
        if use_async:
            await _wait_for_pg(dsn, retries=5, base_delay=0.5)
        else:
            _sync_wait_for_pg(dsn, retries=5, base_delay=0.5)
    except Exception as e:
        print(f"[seed] pg_isready final failure: {e}")
        raise

    families = _get_manifest_families(upsert_families=upsert_families, full=full)
    # add locked families when full
    locked_families: list[tuple[str, dict]] = []
    if full:
        locked_families = _get_locked_families()
        # merge but keep sorted order
        all_fam_dict = {fid: entry for fid, entry in families}
        for fid, entry in locked_families:
            if fid not in all_fam_dict:
                all_fam_dict[fid] = entry
        # re-sort combined
        families = sorted(all_fam_dict.items(), key=lambda kv: _family_sort_key(kv[0]))

    pcap_paths = _discover_pcap_paths()
    # count breakdown for logging (jitter excluded per user, should be 0)
    base_cnt = len([p for fid, p in pcap_paths if fid.startswith("family-") and "-jitter-" not in fid and not fid.startswith("family-locked-")])
    jitter_cnt = len([p for fid, p in pcap_paths if "-jitter-" in fid])
    locked_cnt = len([p for fid, p in pcap_paths if fid.startswith("family-locked-")])
    print(f"[seed] seeding {len(families)} families ordered lpad(substring(family_id from 8)::int) — {[f[0] for f in families[:3]]} ... {[f[0] for f in families[-2:]]} (base {base_cnt} jitter {jitter_cnt} (excluded) locked {locked_cnt} pcap_files {len(pcap_paths)})")

    try:
        if use_async:
            return await _seed_all_async(dsn, families, pcap_paths, with_dashboard_run, full)
        else:
            return _seed_all_sync(dsn, families, pcap_paths, with_dashboard_run, full)
    except Exception as e:
        if use_async:
            print(f"[seed] async seed failed ({e}), falling back to sync")
            return _seed_all_sync(dsn, families, pcap_paths, with_dashboard_run, full)
        raise


async def _seed_all_async(dsn: str, families: list[tuple[str, dict]], pcap_paths: list[tuple[str, pathlib.Path]], with_dashboard_run: bool, full: bool) -> dict:
    conn = await AsyncConnection.connect(dsn)
    try:
        counts_before = {}
        for tbl in ("families", "pcap_files", "flows", "model_runs"):
            try:
                cur = await conn.execute(f"SELECT count(*) FROM {tbl}")
                row = await cur.fetchone()
                counts_before[tbl] = int(row[0]) if row else 0
            except Exception:
                counts_before[tbl] = 0

        # Chunked transactions for large full (680) to avoid huge TX — 50 per chunk, each BEGIN lpad ordered
        chunk_size = 50
        # Map pcap_paths by family_id for quick lookup
        pcap_map: dict[str, pathlib.Path] = {fid: p for fid, p in pcap_paths}
        # Build manifest family lookup for flow placeholder
        fam_lookup: dict[str, dict] = {fid: entry for fid, entry in families}

        # Process families in chunks
        for chunk_idx in range(0, len(families), chunk_size):
            chunk = families[chunk_idx : chunk_idx + chunk_size]
            async with conn.transaction():
                for family_id, entry in chunk:
                    display_name = entry.get("description") or entry.get("display_name") or family_id
                    port = int(entry.get("port", 587) or 587)
                    tls_version = entry.get("tls") or entry.get("tls_version") or "TLS1.2"
                    if tls_version == "none":
                        tls_version = "none"
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
                    await conn.execute(_families_upsert_sql(), (family_id, display_name, port, tls_version, cipher_suite, cert_type, starttls_mode))

        # Pcap + flows in chunks as well (still lpad ordered)
        # For each pcap found, insert pcap_files and try real pipeline
        # We also need to handle families without pcap -> still create placeholder flow
        # So first insert pcap_files for discovered pcaps
        for chunk_idx in range(0, len(pcap_paths), chunk_size):
            chunk = pcap_paths[chunk_idx : chunk_idx + chunk_size]
            async with conn.transaction():
                for family_id, pcap_path in chunk:
                    # ensure family exists for FK (locked families may not be in families list if not full, but pcap_paths includes them)
                    # if family not in families, ensure family row exists
                    if family_id not in fam_lookup:
                        # create minimal family for pcap
                        try:
                            await conn.execute(_families_upsert_sql(), (family_id, family_id, 587, "TLS1.2", "ECDHE-RSA-AES128-GCM-SHA256", "rsa2048", "upgrade"))
                        except Exception:
                            pass
                    if pcap_path.exists():
                        data = pcap_path.read_bytes()
                        if len(data) >= 100 * 1024 * 1024:
                            print(f"[seed] skip {family_id} pcap too large {len(data)}")
                        else:
                            sha256 = hashlib.sha256(data).hexdigest()
                            byte_length = len(data)
                            await conn.execute(_pcap_files_upsert_sql(), (family_id, psycopg.Binary(data), sha256, byte_length))

        # Flows: for each family + pcap, try real pipeline then placeholder
        # Also handle pcap-derived flows that may have different flow_id than family_id
        for chunk_idx in range(0, len(families), chunk_size):
            chunk = families[chunk_idx : chunk_idx + chunk_size]
            async with conn.transaction():
                for family_id, entry in chunk:
                    # try real pipeline if pcap exists for this family_id
                    pcap_path = pcap_map.get(family_id)
                    # fallback manifest pcap field
                    if pcap_path is None and entry.get("pcap"):
                        alt = ROOT / entry["pcap"]
                        if alt.exists():
                            pcap_path = alt
                    real_flows = []
                    if pcap_path is not None and pcap_path.exists():
                        try:
                            data = pcap_path.read_bytes()
                            if len(data) < 100 * 1024 * 1024:
                                real_flows = _try_real_pipeline(data, pcap_path.name)
                        except Exception:
                            real_flows = []
                    if real_flows:
                        for fv in real_flows:
                            try:
                                payload = json.dumps(fv.model_dump(mode="json") if hasattr(fv, "model_dump") else fv.model_dump() if hasattr(fv, "model_dump") else dict(fv))
                                flow_id = getattr(fv, "flow_id", family_id) or family_id
                                fam_id = getattr(fv, "family_id", family_id) if hasattr(fv, "family_id") else family_id
                                # fallback: try dict
                                if isinstance(fv, dict):
                                    flow_id = fv.get("flow_id", family_id)
                                    fam_id = fv.get("family_id", family_id)
                                else:
                                    try:
                                        d = fv.model_dump() if hasattr(fv, "model_dump") else {}
                                        fam_id = d.get("family_id", family_id)
                                    except Exception:
                                        fam_id = family_id
                                # ensure FK valid
                                _fid = fam_id
                                try:
                                    chk = await conn.execute("SELECT 1 FROM families WHERE family_id=%s", (_fid,))
                                    row = await chk.fetchone()
                                    if row is None:
                                        _fid = None
                                except Exception:
                                    _fid = None
                                await conn.execute(_flows_upsert_sql(), (flow_id, _fid, payload))
                                try:
                                    await conn.execute(
                                        "INSERT INTO flows_history (flow_id, version, data) "
                                        "SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb "
                                        "ON CONFLICT (flow_id, version) DO NOTHING",
                                        (flow_id, flow_id, payload),
                                    )
                                except Exception:
                                    pass
                            except Exception as e:
                                print(f"[seed] real flow upsert error {family_id}: {e}")
                        # also ensure placeholder for family_id if real flows used different flow_id? still upsert placeholder to keep family flow
                        # but skip duplicate if flow_id already equals family_id
                        if not any((getattr(fv, "flow_id", "") == family_id) for fv in real_flows if hasattr(fv, "flow_id")):
                            # check dict case
                            has_family_flow = False
                            for fv in real_flows:
                                try:
                                    fid = fv.flow_id if hasattr(fv, "flow_id") else fv.get("flow_id") if isinstance(fv, dict) else None
                                    if fid == family_id:
                                        has_family_flow = True
                                except Exception:
                                    pass
                            if not has_family_flow:
                                flow_data = _make_placeholder_flow(family_id, entry, seed=SEED)
                                flow_json = json.dumps(flow_data)
                                _fid2 = family_id
                                try:
                                    chk = await conn.execute("SELECT 1 FROM families WHERE family_id=%s", (_fid2,))
                                    row = await chk.fetchone()
                                    if row is None:
                                        _fid2 = None
                                except Exception:
                                    _fid2 = None
                                await conn.execute(_flows_upsert_sql(), (family_id, _fid2, flow_json))
                                try:
                                    await conn.execute(
                                        "INSERT INTO flows_history (flow_id, version, data) "
                                        "SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb "
                                        "ON CONFLICT (flow_id, version) DO NOTHING",
                                        (family_id, family_id, flow_json),
                                    )
                                except Exception:
                                    pass
                    else:
                        # placeholder
                        flow_data = _make_placeholder_flow(family_id, entry, seed=SEED)
                        flow_json = json.dumps(flow_data)
                        _fid = family_id
                        try:
                            chk = await conn.execute("SELECT 1 FROM families WHERE family_id=%s", (_fid,))
                            row = await chk.fetchone()
                            if row is None:
                                _fid = None
                        except Exception:
                            _fid = None
                        await conn.execute(_flows_upsert_sql(), (family_id, _fid, flow_json))
                        try:
                            await conn.execute(
                                "INSERT INTO flows_history (flow_id, version, data) "
                                "SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb "
                                "ON CONFLICT (flow_id, version) DO NOTHING",
                                (family_id, family_id, flow_json),
                            )
                        except Exception:
                            pass

        # Handle locked pcaps not in families chunk (if not full, they may still be in pcap_paths)
        # Already handled families for locked via pcap_map, but flows for locked not yet if locked not in families
        # If full, locked families already in families; if not full, we still want to seed locked flows separately
        locked_only = [fid for fid, _ in pcap_paths if fid not in fam_lookup]
        if locked_only:
            async with conn.transaction():
                for fid in locked_only:
                    p = pcap_map[fid]
                    entry = {"port": 587, "tls": "TLS1.2", "cipher": "ECDHE-RSA-AES128-GCM-SHA256", "cert": "rsa2048", "starttls": "upgrade", "description": fid}
                    # ensure family row
                    try:
                        await conn.execute(_families_upsert_sql(), (fid, fid, 587, "TLS1.2", "ECDHE-RSA-AES128-GCM-SHA256", "rsa2048", "upgrade"))
                    except Exception:
                        pass
                    data = p.read_bytes() if p.exists() else b""
                    real_flows = _try_real_pipeline(data, p.name) if data else []
                    if real_flows:
                        for fv in real_flows:
                            try:
                                payload = json.dumps(fv.model_dump(mode="json") if hasattr(fv, "model_dump") else dict(fv))
                                flow_id = getattr(fv, "flow_id", fid) or fid
                                if isinstance(fv, dict):
                                    flow_id = fv.get("flow_id", fid)
                                await conn.execute(_flows_upsert_sql(), (flow_id, fid, payload))
                                try:
                                    await conn.execute(
                                        "INSERT INTO flows_history (flow_id, version, data) SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb ON CONFLICT (flow_id, version) DO NOTHING",
                                        (flow_id, flow_id, payload),
                                    )
                                except Exception:
                                    pass
                            except Exception:
                                pass
                    # placeholder for locked
                    fd = _make_placeholder_flow(fid, entry, seed=SEED)
                    fj = json.dumps(fd)
                    await conn.execute(_flows_upsert_sql(), (fid, fid, fj))
                    try:
                        await conn.execute(
                            "INSERT INTO flows_history (flow_id, version, data) SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb ON CONFLICT (flow_id, version) DO NOTHING",
                            (fid, fid, fj),
                        )
                    except Exception:
                        pass

        # sqlite migration + fixtures + model_runs - each in its own transaction to avoid huge TX
        if full:
            async with conn.transaction():
                await _migrate_sqlite_flows_async(conn)
            async with conn.transaction():
                await _ingest_fixtures_async(conn)
            async with conn.transaction():
                await _seed_model_runs_async(conn)
        else:
            # Always seed model_runs so /api/models is always populated
            try:
                async with conn.transaction():
                    await _seed_model_runs_async(conn)
            except Exception:
                pass

        # counts after
        counts_after = {}
        for tbl in ("families", "pcap_files", "flows", "model_runs"):
            try:
                cur = await conn.execute(f"SELECT count(*) FROM {tbl}")
                row = await cur.fetchone()
                counts_after[tbl] = int(row[0]) if row else 0
            except Exception:
                counts_after[tbl] = 0

        for tbl in ("families", "pcap_files", "flows", "model_runs"):
            before = counts_before.get(tbl, 0)
            after = counts_after.get(tbl, 0)
            print(f"[seed] {tbl}: before={before} after={after} diff={after - before} (0 diff means idempotent)")

        if with_dashboard_run:
            await _run_dashboard_10_async(conn, families)

        await conn.commit()
        return {"before": counts_before, "after": counts_after}
    finally:
        await conn.close()


def _seed_all_sync(dsn: str, families: list[tuple[str, dict]], pcap_paths: list[tuple[str, pathlib.Path]], with_dashboard_run: bool, full: bool) -> dict:
    if not HAS_PSYCOPG:
        print("[seed] psycopg not available — skipping DB seed (dry-run mode)")
        return {"before": {}, "after": {}}
    import psycopg as _pg
    conn = _pg.connect(dsn)
    try:
        counts_before = {}
        for tbl in ("families", "pcap_files", "flows", "model_runs"):
            try:
                with conn.cursor() as cur:
                    cur.execute(f"SELECT count(*) FROM {tbl}")
                    row = cur.fetchone()
                    counts_before[tbl] = int(row[0]) if row else 0
            except Exception:
                counts_before[tbl] = 0

        chunk_size = 50
        pcap_map: dict[str, pathlib.Path] = {fid: p for fid, p in pcap_paths}
        fam_lookup: dict[str, dict] = {fid: entry for fid, entry in families}

        # families chunks
        for chunk_idx in range(0, len(families), chunk_size):
            chunk = families[chunk_idx : chunk_idx + chunk_size]
            with conn.transaction():
                for family_id, entry in chunk:
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

        # pcap_files chunks
        for chunk_idx in range(0, len(pcap_paths), chunk_size):
            chunk = pcap_paths[chunk_idx : chunk_idx + chunk_size]
            with conn.transaction():
                for family_id, pcap_path in chunk:
                    if family_id not in fam_lookup:
                        try:
                            with conn.cursor() as cur:
                                cur.execute(_families_upsert_sql(), (family_id, family_id, 587, "TLS1.2", "ECDHE-RSA-AES128-GCM-SHA256", "rsa2048", "upgrade"))
                        except Exception:
                            pass
                    if pcap_path.exists():
                        data = pcap_path.read_bytes()
                        if len(data) < 100 * 1024 * 1024:
                            sha256 = hashlib.sha256(data).hexdigest()
                            byte_length = len(data)
                            with conn.cursor() as cur2:
                                cur2.execute(_pcap_files_upsert_sql(), (family_id, _pg.Binary(data), sha256, byte_length))

        # flows chunks
        for chunk_idx in range(0, len(families), chunk_size):
            chunk = families[chunk_idx : chunk_idx + chunk_size]
            with conn.transaction():
                for family_id, entry in chunk:
                    pcap_path = pcap_map.get(family_id)
                    if pcap_path is None and entry.get("pcap"):
                        alt = ROOT / entry["pcap"]
                        if alt.exists():
                            pcap_path = alt
                    real_flows = []
                    if pcap_path is not None and pcap_path.exists():
                        try:
                            data = pcap_path.read_bytes()
                            if len(data) < 100 * 1024 * 1024:
                                real_flows = _try_real_pipeline(data, pcap_path.name)
                        except Exception:
                            real_flows = []
                    if real_flows:
                        for fv in real_flows:
                            try:
                                if hasattr(fv, "model_dump"):
                                    payload = json.dumps(fv.model_dump(mode="json"))
                                    flow_id = getattr(fv, "flow_id", family_id) or family_id
                                    fam_id = getattr(fv, "family_id", family_id) if hasattr(fv, "family_id") else family_id
                                    try:
                                        d = fv.model_dump()
                                        fam_id = d.get("family_id", family_id)
                                    except Exception:
                                        fam_id = family_id
                                elif isinstance(fv, dict):
                                    payload = json.dumps(fv)
                                    flow_id = fv.get("flow_id", family_id)
                                    fam_id = fv.get("family_id", family_id)
                                else:
                                    payload = json.dumps(dict(fv))
                                    flow_id = family_id
                                    fam_id = family_id
                                _fid = fam_id
                                try:
                                    with conn.cursor() as chk:
                                        chk.execute("SELECT 1 FROM families WHERE family_id=%s", (_fid,))
                                        if chk.fetchone() is None:
                                            _fid = None
                                except Exception:
                                    _fid = None
                                with conn.cursor() as cur3:
                                    cur3.execute(_flows_upsert_sql(), (flow_id, _fid, payload))
                                    try:
                                        cur3.execute(
                                            "INSERT INTO flows_history (flow_id, version, data) "
                                            "SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb "
                                            "ON CONFLICT (flow_id, version) DO NOTHING",
                                            (flow_id, flow_id, payload),
                                        )
                                    except Exception:
                                        pass
                            except Exception as e:
                                print(f"[seed] sync real flow error {family_id}: {e}")
                        # ensure placeholder if needed
                        has_family = False
                        for fv in real_flows:
                            try:
                                fid = fv.flow_id if hasattr(fv, "flow_id") else fv.get("flow_id") if isinstance(fv, dict) else None
                                if fid == family_id:
                                    has_family = True
                            except Exception:
                                pass
                        if not has_family:
                            flow_data = _make_placeholder_flow(family_id, entry, seed=SEED)
                            flow_json = json.dumps(flow_data)
                            _fid2 = family_id
                            try:
                                with conn.cursor() as chk:
                                    chk.execute("SELECT 1 FROM families WHERE family_id=%s", (_fid2,))
                                    if chk.fetchone() is None:
                                        _fid2 = None
                            except Exception:
                                _fid2 = None
                            with conn.cursor() as cur3:
                                cur3.execute(_flows_upsert_sql(), (family_id, _fid2, flow_json))
                                try:
                                    cur3.execute(
                                        "INSERT INTO flows_history (flow_id, version, data) "
                                        "SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb "
                                        "ON CONFLICT (flow_id, version) DO NOTHING",
                                        (family_id, family_id, flow_json),
                                    )
                                except Exception:
                                    pass
                    else:
                        flow_data = _make_placeholder_flow(family_id, entry, seed=SEED)
                        flow_json = json.dumps(flow_data)
                        _fid = family_id
                        try:
                            with conn.cursor() as chk:
                                chk.execute("SELECT 1 FROM families WHERE family_id=%s", (_fid,))
                                if chk.fetchone() is None:
                                    _fid = None
                        except Exception:
                            _fid = None
                        with conn.cursor() as cur3:
                            cur3.execute(_flows_upsert_sql(), (family_id, _fid, flow_json))
                            try:
                                cur3.execute(
                                    "INSERT INTO flows_history (flow_id, version, data) "
                                    "SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb "
                                    "ON CONFLICT (flow_id, version) DO NOTHING",
                                    (family_id, family_id, flow_json),
                                )
                            except Exception:
                                pass

        # locked only
        locked_only = [fid for fid, _ in pcap_paths if fid not in fam_lookup]
        if locked_only:
            with conn.transaction():
                for fid in locked_only:
                    p = pcap_map[fid]
                    entry = {"port": 587, "tls": "TLS1.2", "cipher": "ECDHE-RSA-AES128-GCM-SHA256", "cert": "rsa2048", "starttls": "upgrade", "description": fid}
                    try:
                        with conn.cursor() as cur:
                            cur.execute(_families_upsert_sql(), (fid, fid, 587, "TLS1.2", "ECDHE-RSA-AES128-GCM-SHA256", "rsa2048", "upgrade"))
                    except Exception:
                        pass
                    data = p.read_bytes() if p.exists() else b""
                    real_flows = _try_real_pipeline(data, p.name) if data else []
                    if real_flows:
                        for fv in real_flows:
                            try:
                                payload = json.dumps(fv.model_dump(mode="json") if hasattr(fv, "model_dump") else dict(fv))
                                flow_id = getattr(fv, "flow_id", fid) or fid
                                if isinstance(fv, dict):
                                    flow_id = fv.get("flow_id", fid)
                                with conn.cursor() as cur:
                                    cur.execute(_flows_upsert_sql(), (flow_id, fid, payload))
                                    try:
                                        cur.execute(
                                            "INSERT INTO flows_history (flow_id, version, data) SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb ON CONFLICT (flow_id, version) DO NOTHING",
                                            (flow_id, flow_id, payload),
                                        )
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                    fd = _make_placeholder_flow(fid, entry, seed=SEED)
                    fj = json.dumps(fd)
                    with conn.cursor() as cur:
                        cur.execute(_flows_upsert_sql(), (fid, fid, fj))
                        try:
                            cur.execute(
                                "INSERT INTO flows_history (flow_id, version, data) SELECT %s, COALESCE((SELECT MAX(version) FROM flows_history WHERE flow_id=%s),0)+1, %s::jsonb ON CONFLICT (flow_id, version) DO NOTHING",
                                (fid, fid, fj),
                            )
                        except Exception:
                            pass

        if full:
            with conn.transaction():
                _migrate_sqlite_flows_sync(conn)
            with conn.transaction():
                _ingest_fixtures_sync(conn)
            with conn.transaction():
                _seed_model_runs_sync(conn)
        else:
            try:
                with conn.transaction():
                    _seed_model_runs_sync(conn)
            except Exception:
                pass

        counts_after = {}
        for tbl in ("families", "pcap_files", "flows", "model_runs"):
            try:
                with conn.cursor() as cur:
                    cur.execute(f"SELECT count(*) FROM {tbl}")
                    row = cur.fetchone()
                    counts_after[tbl] = int(row[0]) if row else 0
            except Exception:
                counts_after[tbl] = 0

        for tbl in ("families", "pcap_files", "flows", "model_runs"):
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
    dash_families = [fid for fid, _ in families if 1 <= int(fid.split("-")[1].split("-")[0]) <= 10 and "-jitter-" not in fid and not fid.startswith("family-locked-")]
    dash_families = sorted(dash_families, key=_family_sort_key)
    dash_families = [fid for fid in dash_families if 1 <= int(fid.split("-")[1]) <= 10][:10]
    print(f"[seed] --run-dashboard processing {len(dash_families)} families 01-10")
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
    dash_families = [fid for fid, _ in families if 1 <= int(fid.split("-")[1].split("-")[0]) <= 10 and "-jitter-" not in fid and not fid.startswith("family-locked-")]
    dash_families = sorted(dash_families, key=_family_sort_key)
    dash_families = [fid for fid in dash_families if 1 <= int(fid.split("-")[1]) <= 10][:10]
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


def _dry_run(upsert_families: bool = False, full: bool = False) -> None:
    if upsert_families:
        full = True
    families = _get_manifest_families(upsert_families=upsert_families, full=full)
    pcap_paths = _discover_pcap_paths()
    base_cnt = len([fid for fid, _ in pcap_paths if fid.startswith("family-") and "-jitter-" not in fid and not fid.startswith("family-locked-")])
    jitter_cnt = len([fid for fid, _ in pcap_paths if "-jitter-" in fid])
    locked_cnt = len([fid for fid, _ in pcap_paths if fid.startswith("family-locked-")])
    # manifest counts
    try:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        all_family_keys = [k for k in data if k.startswith("family-")]
        canon = [k for k in all_family_keys if CANON_RE.match(k)]
        jitter_keys = [k for k in all_family_keys if "-jitter-" in k or "jitter" in k.lower()]
    except Exception:
        all_family_keys = []
        canon = []
        jitter_keys = []
    if full:
        print(f"{len(families)} families (full: {len(canon)} actual excluding jitter, {len(jitter_keys)} jitter excluded)")
        print(f"  pcaps on disk: {base_cnt} base + {jitter_cnt} jittered (excluded) + {locked_cnt} locked = {len(pcap_paths)} total")
        jitter_fams = [fid for fid, _ in families if "jitter" in fid.lower()]
        if jitter_fams:
            print(f"  ERROR: jitter families still in manifest selection: {jitter_fams[:3]}")
        else:
            print(f"  jitter families excluded: 0 in selection (manifest has {len(jitter_keys)} jitter variants excluded)")
    else:
        print(f"{len(families)} families (all actual, jitter excluded)")
        print(f"  pcaps on disk: {base_cnt} base + {jitter_cnt} jittered (excluded) + {locked_cnt} locked = {len(pcap_paths)} total (use --full to include sqlite/fixtures/model_runs)")

    for fid, entry in families[:3]:
        print(f"  {fid} port={entry.get('port')} tls={entry.get('tls')} cipher={entry.get('cipher')} cert={entry.get('cert')} starttls={entry.get('starttls')} source_id={deterministic_source_id(fid)[:8]}")
    if len(families) > 6:
        print("  ...")
        for fid, entry in families[-2:]:
            print(f"  {fid} port={entry.get('port')} tls={entry.get('tls')} cipher={entry.get('cipher')} cert={entry.get('cert')} starttls={entry.get('starttls')} source_id={deterministic_source_id(fid)[:8]}")
    elif len(families) > 3:
        for fid, entry in families[3:]:
            print(f"  {fid} port={entry.get('port')} tls={entry.get('tls')} cipher={entry.get('cipher')} cert={entry.get('cert')} starttls={entry.get('starttls')} source_id={deterministic_source_id(fid)[:8]}")
    if families:
        order = [fid for fid, _ in families]
        lexical = sorted([fid for fid, _ in families])
        if order != lexical:
            print(f"[dry-run] numeric order verified: {order[:5]} ... lexical would be {lexical[:5]} (avoids 11/100/2 bug)")
        print("ORDER BY lpad(substring(family_id from 8)::int) — numeric order applied (jitter excluded)")
        jitter_ordered = [fid for fid, _ in families if "jitter" in fid.lower()]
        if jitter_ordered:
            print(f"[dry-run] ERROR: jitter families found in selection: {jitter_ordered[:3]}")
        else:
            print(f"[dry-run] jitter excluded verified: 0 jitter families in selection")
        # sqlite and fixtures counts
        try:
            if SQLITE_DB.exists():
                sconn = sqlite3.connect(str(SQLITE_DB))
                cnt = sconn.execute("SELECT count(*) FROM flows").fetchone()[0]
                print(f"[dry-run] sqlite api/flows.db: {cnt} flows to migrate")
                sconn.close()
        except Exception:
            pass
        print(f"[dry-run] fixtures: {len(sorted(FIXTURES_DIR.glob('family-*.json')))} family json + {len(sorted((FIXTURES_DIR / 'adversarial').glob('*.json')) if (FIXTURES_DIR / 'adversarial').exists() else [])} adversarial")
        print(f"[dry-run] models: {len(sorted(MODELS_DIR.glob('*.pkl')))} pkl files to seed into model_runs")
        print(f"[dry-run] pcap_files BYTEA: looped psycopg.Binary for <50MB per entry — COPY BINARY alternative for >50MB documented")
        if full:
            print(f"[dry-run] mode: --full comprehensive ingest ALL sources (families {len(families)} + pcaps {len(pcap_paths)} + sqlite + fixtures + model_runs)")


def main() -> None:
    parser = argparse.ArgumentParser(description="CipherCrest seed — startup-idempotent deterministic seed + comprehensive ingest")
    parser.add_argument("--dsn", type=str, default=os.environ.get("POSTGRES_DSN", DEFAULT_DSN), help="Postgres DSN (default POSTGRES_DSN env)")
    parser.add_argument("--dry-run", action="store_true", help="print families ordered lpad without DB")
    parser.add_argument("--run-dashboard", action="store_true", help="iterate families 01-10 through pipeline → FlowVerdict → upsert + NOTIFY flows_upsert")
    parser.add_argument("--upsert-families", action="store_true", help="allow adding all actual families without docker compose down -v (seeds all actual families excluding jitter, alias for --full)")
    parser.add_argument("--full", action="store_true", help="comprehensive ingest ALL sources: all actual families excluding jitter (680) + all pcaps excluding jitter + sqlite + fixtures + model_runs")
    parser.add_argument("--with-dashboard", dest="run_dashboard_alias", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    with_dashboard = bool(args.run_dashboard or args.run_dashboard_alias)
    full = bool(args.full or args.upsert_families)

    if args.dry_run:
        _dry_run(upsert_families=bool(args.upsert_families), full=full)
        return

    async def _amain():
        try:
            await seed_all(dsn=args.dsn, with_dashboard_run=with_dashboard, upsert_families=bool(args.upsert_families), full=full)
        except Exception as e:
            print(f"[seed] async error: {e}")
            try:
                _sync_wait_for_pg(args.dsn)
                fam = _get_manifest_families(upsert_families=bool(args.upsert_families), full=full)
                pcap_paths = _discover_pcap_paths()
                _seed_all_sync(args.dsn, fam, pcap_paths, with_dashboard, full)
            except Exception as e2:
                print(f"[seed] sync fallback error: {e2}", file=sys.stderr)
                sys.exit(1)

    try:
        asyncio.run(_amain())
    except RuntimeError as re:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(_amain())


if __name__ == "__main__":
    main()
