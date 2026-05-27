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