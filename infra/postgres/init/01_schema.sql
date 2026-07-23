-- Medusa v1 schema alerts and snapshots

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE alerts (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    received_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rule           TEXT NOT NULL,
    priority       TEXT NOT NULL,
    output         TEXT NOT NULL,
    container_name TEXT,
    image          TEXT,
    tags           TEXT[],
    raw_event      JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS forensic_events(
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ,
    alert_id       UUID REFERENCES alerts(id),
    pod_name       TEXT,
    namespace      TEXT,
    container_name TEXT,
    phase          TEXT NOT NULL DEFAULT 'pending',
    trigger_source TEXT,
    triggered_rule TEXT,
    triggered_priority TEXT,
    checkpoint_location TEXT,
    raw_alert      JSONB,
    raw_report     JSONB,
    operator_cr_name TEXT,
    idempotency_key  TEXT UNIQUE
);

CREATE INDEX idx_alerts_received_at ON alerts (received_at DESC);
CREATE INDEX idx_alerts_priority    ON alerts (priority);
CREATE INDEX idx_alerts_container   ON alerts (container_name);

CREATE TABLE snapshots (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    alert_id       UUID REFERENCES alerts(id),
    container_name TEXT NOT NULL,
    storage_path   TEXT NOT NULL,
    size_bytes     BIGINT,
    status         TEXT DEFAULT 'pending'
);

CREATE INDEX idx_snapshots_created_at ON snapshots (created_at DESC);