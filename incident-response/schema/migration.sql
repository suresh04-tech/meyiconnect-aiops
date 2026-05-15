-- ============================================================
-- Incident Response Schema
-- Run once against your existing RDS / Docker Postgres
-- Compatible with your existing MeyiConnect DB
-- ============================================================
SET search_path TO meyiconnect;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- ─── Enums ───────────────────────────────────────────────────

DO $$ BEGIN
    CREATE TYPE severity_level AS ENUM ('low', 'medium', 'high', 'critical');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE incident_status AS ENUM (
        'queued',
        'fetching_data',
        'finding_rca',
        'completed',
        'failed'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ─── incidents ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS incidents (
    event_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id           VARCHAR(64)      NOT NULL,
    issue                 TEXT             NOT NULL,
    severity              severity_level   NOT NULL DEFAULT 'low',
    incident_start_time   TIMESTAMPTZ      NOT NULL,
    incident_end_time     TIMESTAMPTZ      NOT NULL,
    region                VARCHAR(32)      NOT NULL DEFAULT 'ap-south-1',
    log_group_name        VARCHAR(256)     NOT NULL,
    dependency_context    JSONB,
    status                incident_status  NOT NULL DEFAULT 'queued',
    created_at            TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);

-- ─── incident_logs ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS incident_logs (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id              UUID             NOT NULL REFERENCES incidents(event_id) ON DELETE CASCADE,
    ec2_details           JSONB,
    ec2_status_checks     JSONB,
    cloudwatch_metrics    JSONB,
    raw_logs              JSONB,           -- [ ... logs ... ]
    logs_count            INT              DEFAULT 0,
    fetched_at            TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);

-- ─── incident_rca ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS incident_rca (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id              UUID             NOT NULL REFERENCES incidents(event_id) ON DELETE CASCADE,
    rca_report            TEXT,
    remediation_steps     TEXT,
    confidence_score      REAL,
    ai_model_used         VARCHAR(128),
    impacted_dependencies JSONB,
    processing_status     VARCHAR(32)      DEFAULT 'pending',
    generated_at          TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);

-- ─── Indexes ──────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_incidents_status     ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity   ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_instance   ON incidents(instance_id);
CREATE INDEX IF NOT EXISTS idx_incidents_created    ON incidents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_logs_event  ON incident_logs(event_id);
CREATE INDEX IF NOT EXISTS idx_incident_rca_event   ON incident_rca(event_id);
