# Entity-Relationship Diagram

The diagram below shows the relationship between the core Medusa tables for alerts and forensic events.

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
        JSONB raw_alert
        JSONB raw_report
    }

    alerts ||--o{ forensic_events : triggers
```

## Relationship semantics

- One **alert** may trigger **zero or more** forensic events (`||--o{`).
- Each forensic event optionally references exactly one alert via `forensic_events.alert_id`.
- The foreign key is nullable: forensic events can exist without a linked alert row.
