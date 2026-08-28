-- init-db/01_schema.sql — canonical Postgres DDL for CipherCrest
-- Idempotent: all CREATE ... IF NOT EXISTS; CONCURRENTLY indexes outside transaction.
-- No seed data — schema only.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- Transactional DDL: tables, FKs, CHECKs, generated cols, triggers
-- ============================================================
BEGIN;

-- families: 60 distinct TLS families, lexical order via lpad(substring(family_id from 8)::int)
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
);

-- pcap_files: BYTEA store with 100MB guard, sha256, byte_length, UNIQUE(family_id,sha256)
CREATE TABLE IF NOT EXISTS pcap_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    family_id TEXT REFERENCES families(family_id) ON DELETE CASCADE,
    data BYTEA NOT NULL CHECK (octet_length(data) < 100*1024*1024),
    sha256 TEXT CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'),
    byte_length INT CHECK (byte_length IS NULL OR byte_length = octet_length(data)),
    created_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE (family_id, sha256)
);

-- flows: JSONB with generated columns for sorting/filtering without json extract
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
);

-- flows_history: versioned history, PK (flow_id,version), FOR UPDATE pattern
CREATE TABLE IF NOT EXISTS flows_history (
    flow_id TEXT REFERENCES flows(flow_id) ON DELETE CASCADE,
    version INT NOT NULL,
    data JSONB,
    created_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (flow_id, version)
);

-- live_captures: live WS captures
CREATE TABLE IF NOT EXISTS live_captures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_id TEXT,
    data JSONB,
    pcap_id UUID REFERENCES pcap_files(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- model_runs: model metadata seeded from pkl sha
CREATE TABLE IF NOT EXISTS model_runs (
    model_name TEXT PRIMARY KEY,
    trained_at TIMESTAMPTZ,
    params JSONB,
    metrics JSONB,
    artifact_sha TEXT,
    n_eff INT,
    dataset_caveat TEXT
);

-- Append-only histories for live/lab/model

CREATE TABLE IF NOT EXISTS live_captures_history (
    id UUID NOT NULL,
    flow_id TEXT,
    data JSONB,
    pcap_id UUID,
    version INT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (id, version)
);

CREATE TABLE IF NOT EXISTS lab_runs_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    family_id TEXT REFERENCES families(family_id) ON DELETE SET NULL,
    flow_id TEXT,
    data JSONB,
    version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE (id, version)
);

CREATE TABLE IF NOT EXISTS model_runs_history (
    model_name TEXT NOT NULL,
    version INT NOT NULL,
    trained_at TIMESTAMPTZ,
    params JSONB,
    metrics JSONB,
    artifact_sha TEXT,
    n_eff INT,
    dataset_caveat TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (model_name, version)
);

-- ---------- triggers: updated_at + families status derived ----------

-- updated_at trigger function
CREATE OR REPLACE FUNCTION trg_set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_families_updated_at ON families;
CREATE TRIGGER trg_families_updated_at
    BEFORE UPDATE ON families
    FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();

DROP TRIGGER IF EXISTS trg_flows_updated_at ON flows;
CREATE TRIGGER trg_flows_updated_at
    BEFORE UPDATE ON flows
    FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();

-- AFTER INSERT ON flows → mark family done + last_run_at
CREATE OR REPLACE FUNCTION trg_flows_mark_family_done() RETURNS TRIGGER AS $$
BEGIN
    UPDATE families
       SET status = 'done',
           last_run_at = now(),
           updated_at = now()
     WHERE family_id = NEW.family_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_flows_after_insert_family_done ON flows;
CREATE TRIGGER trg_flows_after_insert_family_done
    AFTER INSERT ON flows
    FOR EACH ROW EXECUTE FUNCTION trg_flows_mark_family_done();

-- Non-concurrent indexes that CAN run inside transaction (btree on generated cols + FK)
CREATE INDEX IF NOT EXISTS idx_pcap_family ON pcap_files(family_id);
CREATE INDEX IF NOT EXISTS idx_flows_family_id ON flows(family_id);
CREATE INDEX IF NOT EXISTS idx_flows_risk_score ON flows(risk_score DESC, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_flows_posture_score ON flows(posture_score);
CREATE INDEX IF NOT EXISTS idx_flows_risk_level ON flows(risk_level);
CREATE INDEX IF NOT EXISTS idx_flows_source_id ON flows(source_id);
CREATE INDEX IF NOT EXISTS idx_flows_history_flow_version ON flows_history(flow_id, version);
CREATE INDEX IF NOT EXISTS idx_live_captures_created ON live_captures(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_live_captures_flow_id ON live_captures(flow_id);
CREATE INDEX IF NOT EXISTS idx_model_runs_trained_at ON model_runs(trained_at DESC);

COMMIT;

-- ============================================================
-- Outside transaction: CONCURRENTLY indexes + GIN + matviews
-- CONCURRENTLY cannot run inside a transaction block — must be
-- outside BEGIN/COMMIT. Also required for REFRESH CONCURRENTLY
-- which needs a UNIQUE index on each matview.
-- ============================================================

-- GIN index for JSONB containment queries (data @> ...)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_flows_data_gin ON flows USING GIN (data jsonb_path_ops);

-- Additional concurrent btree indexes (idempotent IF NOT EXISTS, outside tx for CONCURRENTLY)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pcap_family_conc ON pcap_files(family_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_flows_risk_score_conc ON flows(risk_score DESC, updated_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_flows_posture_conc ON flows(posture_score);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_history_flow_version_conc ON flows_history(flow_id, version);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_live_created_conc ON live_captures(created_at DESC);

-- Materialized views
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_dashboard_metrics AS
SELECT
    risk_level,
    COUNT(*)::int AS cnt,
    AVG(posture_score)::float AS avg_posture
FROM flows
WHERE risk_level IS NOT NULL
GROUP BY risk_level
WITH DATA;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_protocol_stats AS
SELECT
    COALESCE(data->>'app_protocol', 'unknown') AS protocol,
    COALESCE(data->'tls'->>'version', data->>'tls_version', 'unknown') AS tls_version,
    COALESCE(data->'tls'->>'cipher_suite', data->>'cipher_suite', 'unknown') AS cipher_suite,
    COUNT(*)::int AS cnt
FROM flows
GROUP BY 1, 2, 3
WITH DATA;

-- UNIQUE indexes enabling REFRESH MATERIALIZED VIEW CONCURRENTLY
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_mv_dash_risk ON mv_dashboard_metrics(risk_level);
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_mv_proto ON mv_protocol_stats(protocol, tls_version, cipher_suite);
