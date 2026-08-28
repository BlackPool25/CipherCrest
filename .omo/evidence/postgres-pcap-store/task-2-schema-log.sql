==== FIRST RUN LOG ====
CREATE EXTENSION
BEGIN
CREATE TABLE
CREATE TABLE
CREATE TABLE
CREATE TABLE
CREATE TABLE
CREATE TABLE
CREATE TABLE
CREATE TABLE
CREATE TABLE
CREATE FUNCTION
psql:/tmp/01_schema.sql:125: NOTICE:  trigger "trg_families_updated_at" for relation "families" does not exist, skipping
DROP TRIGGER
CREATE TRIGGER
psql:/tmp/01_schema.sql:130: NOTICE:  trigger "trg_flows_updated_at" for relation "flows" does not exist, skipping
DROP TRIGGER
CREATE TRIGGER
CREATE FUNCTION
psql:/tmp/01_schema.sql:147: NOTICE:  trigger "trg_flows_after_insert_family_done" for relation "flows" does not exist, skipping
DROP TRIGGER
CREATE TRIGGER
CREATE INDEX
CREATE INDEX
CREATE INDEX
CREATE INDEX
CREATE INDEX
CREATE INDEX
CREATE INDEX
CREATE INDEX
CREATE INDEX
CREATE INDEX
COMMIT
CREATE INDEX
CREATE INDEX
CREATE INDEX
CREATE INDEX
CREATE INDEX
CREATE INDEX
SELECT 0
SELECT 0
CREATE INDEX
CREATE INDEX

==== SECOND RUN LOG (idempotent) ====
psql:/tmp/01_schema.sql:5: NOTICE:  extension "pgcrypto" already exists, skipping
CREATE EXTENSION
BEGIN
psql:/tmp/01_schema.sql:25: NOTICE:  relation "families" already exists, skipping
CREATE TABLE
psql:/tmp/01_schema.sql:36: NOTICE:  relation "pcap_files" already exists, skipping
CREATE TABLE
psql:/tmp/01_schema.sql:49: NOTICE:  relation "flows" already exists, skipping
CREATE TABLE
psql:/tmp/01_schema.sql:58: NOTICE:  relation "flows_history" already exists, skipping
CREATE TABLE
psql:/tmp/01_schema.sql:67: NOTICE:  relation "live_captures" already exists, skipping
CREATE TABLE
psql:/tmp/01_schema.sql:78: NOTICE:  relation "model_runs" already exists, skipping
CREATE TABLE
psql:/tmp/01_schema.sql:90: NOTICE:  relation "live_captures_history" already exists, skipping
CREATE TABLE
psql:/tmp/01_schema.sql:100: NOTICE:  relation "lab_runs_history" already exists, skipping
CREATE TABLE
psql:/tmp/01_schema.sql:113: NOTICE:  relation "model_runs_history" already exists, skipping
CREATE TABLE
CREATE FUNCTION
DROP TRIGGER
CREATE TRIGGER
DROP TRIGGER
CREATE TRIGGER
CREATE FUNCTION
DROP TRIGGER
CREATE TRIGGER
psql:/tmp/01_schema.sql:153: NOTICE:  relation "idx_pcap_family" already exists, skipping
CREATE INDEX
psql:/tmp/01_schema.sql:154: NOTICE:  relation "idx_flows_family_id" already exists, skipping
CREATE INDEX
psql:/tmp/01_schema.sql:155: NOTICE:  relation "idx_flows_risk_score" already exists, skipping
CREATE INDEX
psql:/tmp/01_schema.sql:156: NOTICE:  relation "idx_flows_posture_score" already exists, skipping
CREATE INDEX
psql:/tmp/01_schema.sql:157: NOTICE:  relation "idx_flows_risk_level" already exists, skipping
CREATE INDEX
psql:/tmp/01_schema.sql:158: NOTICE:  relation "idx_flows_source_id" already exists, skipping
CREATE INDEX
psql:/tmp/01_schema.sql:159: NOTICE:  relation "idx_flows_history_flow_version" already exists, skipping
CREATE INDEX
psql:/tmp/01_schema.sql:160: NOTICE:  relation "idx_live_captures_created" already exists, skipping
CREATE INDEX
psql:/tmp/01_schema.sql:161: NOTICE:  relation "idx_live_captures_flow_id" already exists, skipping
CREATE INDEX
psql:/tmp/01_schema.sql:162: NOTICE:  relation "idx_model_runs_trained_at" already exists, skipping
CREATE INDEX
COMMIT
psql:/tmp/01_schema.sql:174: NOTICE:  relation "idx_flows_data_gin" already exists, skipping
CREATE INDEX
psql:/tmp/01_schema.sql:177: NOTICE:  relation "idx_pcap_family_conc" already exists, skipping
CREATE INDEX
psql:/tmp/01_schema.sql:178: NOTICE:  relation "idx_flows_risk_score_conc" already exists, skipping
CREATE INDEX
psql:/tmp/01_schema.sql:179: NOTICE:  relation "idx_flows_posture_conc" already exists, skipping
CREATE INDEX
psql:/tmp/01_schema.sql:180: NOTICE:  relation "idx_history_flow_version_conc" already exists, skipping
CREATE INDEX
psql:/tmp/01_schema.sql:181: NOTICE:  relation "idx_live_created_conc" already exists, skipping
CREATE INDEX
psql:/tmp/01_schema.sql:192: NOTICE:  relation "mv_dashboard_metrics" already exists, skipping
CREATE MATERIALIZED VIEW
psql:/tmp/01_schema.sql:202: NOTICE:  relation "mv_protocol_stats" already exists, skipping
CREATE MATERIALIZED VIEW
psql:/tmp/01_schema.sql:205: NOTICE:  relation "idx_mv_dash_risk" already exists, skipping
CREATE INDEX
psql:/tmp/01_schema.sql:206: NOTICE:  relation "idx_mv_proto" already exists, skipping
CREATE INDEX

==== \d families ====
                              Table "public.families"
    Column     |           Type           | Collation | Nullable |     Default     
---------------+--------------------------+-----------+----------+-----------------
 family_id     | text                     |           | not null | 
 display_name  | text                     |           |          | 
 port          | integer                  |           |          | 
 tls_version   | text                     |           |          | 
 cipher_suite  | text                     |           |          | 
 cert_type     | text                     |           |          | 
 starttls_mode | text                     |           |          | 
 status        | text                     |           |          | 'not_run'::text
 last_run_at   | timestamp with time zone |           |          | 
 created_at    | timestamp with time zone |           |          | now()
 updated_at    | timestamp with time zone |           |          | now()
Indexes:
    "families_pkey" PRIMARY KEY, btree (family_id)
Check constraints:
    "families_port_check" CHECK (port = ANY (ARRAY[25, 110, 143, 587, 993]))
    "families_starttls_mode_check" CHECK (starttls_mode = ANY (ARRAY['upgrade'::text, 'implicit'::text, 'stripped'::text, 'none'::text]))
    "families_status_check" CHECK (status = ANY (ARRAY['not_run'::text, 'running'::text, 'done'::text, 'failed'::text]))
    "families_tls_version_check" CHECK (tls_version = ANY (ARRAY['TLS1.0'::text, 'TLS1.1'::text, 'TLS1.2'::text, 'TLS1.3'::text, 'none'::text]))
Referenced by:
    TABLE "flows" CONSTRAINT "flows_family_id_fkey" FOREIGN KEY (family_id) REFERENCES families(family_id) ON DELETE SET NULL
    TABLE "lab_runs_history" CONSTRAINT "lab_runs_history_family_id_fkey" FOREIGN KEY (family_id) REFERENCES families(family_id) ON DELETE SET NULL
    TABLE "pcap_files" CONSTRAINT "pcap_files_family_id_fkey" FOREIGN KEY (family_id) REFERENCES families(family_id) ON DELETE CASCADE
Triggers:
    trg_families_updated_at BEFORE UPDATE ON families FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at()


==== \d flows ====
                                                                       Table "public.flows"
    Column     |           Type           | Collation | Nullable |                                            Default                                             
---------------+--------------------------+-----------+----------+------------------------------------------------------------------------------------------------
 flow_id       | text                     |           | not null | 
 family_id     | text                     |           |          | 
 data          | jsonb                    |           | not null | 
 risk_score    | integer                  |           |          | generated always as (((data -> 'assessment'::text) ->> 'risk_score'::text)::integer) stored
 posture_score | integer                  |           |          | generated always as (((data -> 'assessment'::text) ->> 'posture_score'::text)::integer) stored
 risk_level    | text                     |           |          | generated always as ((data -> 'assessment'::text) ->> 'risk_level'::text) stored
 source_id     | text                     |           |          | generated always as (data ->> 'source_id'::text) stored
 created_at    | timestamp with time zone |           |          | now()
 updated_at    | timestamp with time zone |           |          | now()
Indexes:
    "flows_pkey" PRIMARY KEY, btree (flow_id)
    "idx_flows_data_gin" gin (data jsonb_path_ops)
    "idx_flows_family_id" btree (family_id)
    "idx_flows_posture_conc" btree (posture_score)
    "idx_flows_posture_score" btree (posture_score)
    "idx_flows_risk_level" btree (risk_level)
    "idx_flows_risk_score" btree (risk_score DESC, updated_at DESC)
    "idx_flows_risk_score_conc" btree (risk_score DESC, updated_at DESC)
    "idx_flows_source_id" btree (source_id)
Check constraints:
    "flows_data_check" CHECK (jsonb_typeof(data) = 'object'::text)
Foreign-key constraints:
    "flows_family_id_fkey" FOREIGN KEY (family_id) REFERENCES families(family_id) ON DELETE SET NULL
Referenced by:
    TABLE "flows_history" CONSTRAINT "flows_history_flow_id_fkey" FOREIGN KEY (flow_id) REFERENCES flows(flow_id) ON DELETE CASCADE
Triggers:
    trg_flows_after_insert_family_done AFTER INSERT ON flows FOR EACH ROW EXECUTE FUNCTION trg_flows_mark_family_done()
    trg_flows_updated_at BEFORE UPDATE ON flows FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at()


==== \d pcap_files ====
                             Table "public.pcap_files"
   Column    |           Type           | Collation | Nullable |      Default      
-------------+--------------------------+-----------+----------+-------------------
 id          | uuid                     |           | not null | gen_random_uuid()
 family_id   | text                     |           |          | 
 data        | bytea                    |           | not null | 
 sha256      | text                     |           |          | 
 byte_length | integer                  |           |          | 
 created_at  | timestamp with time zone |           |          | now()
Indexes:
    "pcap_files_pkey" PRIMARY KEY, btree (id)
    "idx_pcap_family" btree (family_id)
    "idx_pcap_family_conc" btree (family_id)
    "pcap_files_family_id_sha256_key" UNIQUE CONSTRAINT, btree (family_id, sha256)
Check constraints:
    "pcap_files_check" CHECK (byte_length IS NULL OR byte_length = octet_length(data))
    "pcap_files_data_check" CHECK (octet_length(data) < (100 * 1024 * 1024))
    "pcap_files_sha256_check" CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'::text)
Foreign-key constraints:
    "pcap_files_family_id_fkey" FOREIGN KEY (family_id) REFERENCES families(family_id) ON DELETE CASCADE
Referenced by:
    TABLE "live_captures" CONSTRAINT "live_captures_pcap_id_fkey" FOREIGN KEY (pcap_id) REFERENCES pcap_files(id) ON DELETE SET NULL


==== \d flows_history ====
                      Table "public.flows_history"
   Column   |           Type           | Collation | Nullable | Default 
------------+--------------------------+-----------+----------+---------
 flow_id    | text                     |           | not null | 
 version    | integer                  |           | not null | 
 data       | jsonb                    |           |          | 
 created_at | timestamp with time zone |           |          | now()
Indexes:
    "flows_history_pkey" PRIMARY KEY, btree (flow_id, version)
    "idx_flows_history_flow_version" btree (flow_id, version)
    "idx_history_flow_version_conc" btree (flow_id, version)
Foreign-key constraints:
    "flows_history_flow_id_fkey" FOREIGN KEY (flow_id) REFERENCES flows(flow_id) ON DELETE CASCADE


==== \d live_captures ====
                           Table "public.live_captures"
   Column   |           Type           | Collation | Nullable |      Default      
------------+--------------------------+-----------+----------+-------------------
 id         | uuid                     |           | not null | gen_random_uuid()
 flow_id    | text                     |           |          | 
 data       | jsonb                    |           |          | 
 pcap_id    | uuid                     |           |          | 
 created_at | timestamp with time zone |           |          | now()
Indexes:
    "live_captures_pkey" PRIMARY KEY, btree (id)
    "idx_live_captures_created" btree (created_at DESC)
    "idx_live_captures_flow_id" btree (flow_id)
    "idx_live_created_conc" btree (created_at DESC)
Foreign-key constraints:
    "live_captures_pcap_id_fkey" FOREIGN KEY (pcap_id) REFERENCES pcap_files(id) ON DELETE SET NULL


==== \d model_runs ====
                         Table "public.model_runs"
     Column     |           Type           | Collation | Nullable | Default 
----------------+--------------------------+-----------+----------+---------
 model_name     | text                     |           | not null | 
 trained_at     | timestamp with time zone |           |          | 
 params         | jsonb                    |           |          | 
 metrics        | jsonb                    |           |          | 
 artifact_sha   | text                     |           |          | 
 n_eff          | integer                  |           |          | 
 dataset_caveat | text                     |           |          | 
Indexes:
    "model_runs_pkey" PRIMARY KEY, btree (model_name)
    "idx_model_runs_trained_at" btree (trained_at DESC)


==== \d mv_dashboard_metrics ====
         Materialized view "public.mv_dashboard_metrics"
   Column    |       Type       | Collation | Nullable | Default 
-------------+------------------+-----------+----------+---------
 risk_level  | text             |           |          | 
 cnt         | integer          |           |          | 
 avg_posture | double precision |           |          | 
Indexes:
    "idx_mv_dash_risk" UNIQUE, btree (risk_level)


==== \d mv_protocol_stats ====
      Materialized view "public.mv_protocol_stats"
    Column    |  Type   | Collation | Nullable | Default 
--------------+---------+-----------+----------+---------
 protocol     | text    |           |          | 
 tls_version  | text    |           |          | 
 cipher_suite | text    |           |          | 
 cnt          | integer |           |          | 
Indexes:
    "idx_mv_proto" UNIQUE, btree (protocol, tls_version, cipher_suite)


==== pg_indexes (CONCURRENTLY unique) ====
 schemaname |      tablename       |     indexname      |                                                    indexdef                                                    
------------+----------------------+--------------------+----------------------------------------------------------------------------------------------------------------
 public     | flows                | idx_flows_data_gin | CREATE INDEX idx_flows_data_gin ON public.flows USING gin (data jsonb_path_ops)
 public     | mv_dashboard_metrics | idx_mv_dash_risk   | CREATE UNIQUE INDEX idx_mv_dash_risk ON public.mv_dashboard_metrics USING btree (risk_level)
 public     | mv_protocol_stats    | idx_mv_proto       | CREATE UNIQUE INDEX idx_mv_proto ON public.mv_protocol_stats USING btree (protocol, tls_version, cipher_suite)
(3 rows)


==== pgcrypto check ====
                 uuid                 |   status    
--------------------------------------+-------------
 f7e33856-fa8b-4948-84c1-28e6498bea2c | pgcrypto ok
(1 row)


==== REFRESH CONCURRENTLY ====
REFRESH MATERIALIZED VIEW
             result             
--------------------------------
 mv_dashboard_metrics refreshed
(1 row)

REFRESH MATERIALIZED VIEW
           result            
-----------------------------
 mv_protocol_stats refreshed
(1 row)


==== docker compose config check ====
 count 
-------
     2
(1 row)

docker compose config: OK
