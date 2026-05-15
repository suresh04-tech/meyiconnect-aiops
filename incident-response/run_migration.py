"""
run_migration.py

Run this ONCE to create the incident response schema
on your existing RDS / Docker Postgres database.

Usage:
    pip install psycopg2-binary python-dotenv
    python run_migration.py
"""

import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

SQL = """
DO $$ BEGIN
    CREATE TYPE severity_level AS ENUM ('low', 'medium', 'high', 'critical');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE incident_status AS ENUM (
        'queued', 'fetching_data', 'finding_rca', 'completed', 'failed'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS incidents (
    event_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id           VARCHAR(64)      NOT NULL,
    issue                 TEXT             NOT NULL,
    severity              severity_level   NOT NULL,
    incident_start_time   TIMESTAMPTZ      NOT NULL,
    log_group_name        VARCHAR(256)     NOT NULL,
    dependency_context    JSONB,
    status                incident_status  NOT NULL DEFAULT 'queued',
    account_id            VARCHAR(64),
    created_at            TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incident_logs (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id              UUID             NOT NULL REFERENCES incidents(event_id) ON DELETE CASCADE,
    ec2_details           JSONB,
    ec2_status_checks     JSONB,
    cloudwatch_metrics    JSONB,
    raw_logs              JSONB,
    logs_before_count     INT              DEFAULT 0,
    logs_after_count      INT              DEFAULT 0,
    logs_recent_count     INT              DEFAULT 0,
    fetched_at            TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);

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

CREATE INDEX IF NOT EXISTS idx_incidents_status    ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity  ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_instance  ON incidents(instance_id);
CREATE INDEX IF NOT EXISTS idx_incidents_created   ON incidents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_logs_event ON incident_logs(event_id);
CREATE INDEX IF NOT EXISTS idx_incident_rca_event  ON incident_rca(event_id);
"""


def main():
    print("Connecting to database...")
    conn = psycopg2.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ.get("DB_PORT", 5432)),
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        sslmode=os.environ.get("DB_SSL_MODE", "require"),
    )

    try:
        with conn.cursor() as cur:
            print("Running migration SQL...")
            cur.execute(SQL)
        conn.commit()
        print("Migration complete — all tables and indexes created.")
    except Exception as e:
        conn.rollback()
        print(f"Migration failed: {e}")
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
