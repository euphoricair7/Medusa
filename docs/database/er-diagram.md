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

- One **alert** may have **zero or more** forensic events (typically one per alert when forensic triggering succeeds).
- Each forensic event optionally references one alert via `forensic_events.alert_id` (nullable FK).
- **Falco flow:** `POST /alerts/falco` persists the alert and runs the shared forensic trigger when k8s context is present.
- **Manual flow:** `POST /alerts/manual` creates a new alert or links via optional `alert_id`.
- **`idempotency_key`** is unique per event — SHA-256 of `{alert_id}:{namespace}:{pod_name}:{container_name}`. Duplicate submits for the same alert reuse the row; missing or failed CRs trigger recreation on that row.
- **`operator_cr_name`** links the DB row to the `ForensicSnapshotChain` CR in Kubernetes.
