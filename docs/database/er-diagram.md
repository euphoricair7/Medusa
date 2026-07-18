# Entity-Relationship Diagram

```mermaid
erDiagram
    alerts {
        UUID id PK
        TIMESTAMPTZ received_at
        TEXT rule
        TEXT priority
        TEXT output
        TEXT container_name
        TEXT image
        TEXT[] tags
        JSONB raw_event
    }

    forensic_events {
        UUID id PK
        TIMESTAMPTZ created_at
        TIMESTAMPTZ updated_at
        UUID alert_id FK
        TEXT pod_name
        TEXT namespace
        TEXT container_name
        TEXT phase
        TEXT trigger_source
        TEXT triggered_rule
        TEXT triggered_priority
        TEXT checkpoint_location
        TEXT operator_cr_name
        TEXT idempotency_key UK
        JSONB raw_alert
        JSONB raw_report
    }

    alerts ||--o{ forensic_events : "alert_id"
```

## Relationship semantics

- One **alert** may have **zero or more** forensic events.
- Each forensic event optionally references one alert via `forensic_events.alert_id` (nullable FK).
- **Manual flow:** `POST /alerts/manual` creates a new alert or links via optional `alert_id`.
- **`idempotency_key`** is unique per event — used to deduplicate triggers within a time window.
- **`operator_cr_name`** links the DB row to the `ForensicSnapshotChain` CR in Kubernetes.
