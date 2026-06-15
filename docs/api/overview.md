# API Overview

The Medusa API is the central REST interface for the container forensics framework. It receives runtime security alerts from Falco, persists them for analysis, and coordinates forensic checkpoint events that capture container memory state for incident response.

## Interactive documentation


| Resource              | URL                                                   | Description                                         |
| --------------------- | ----------------------------------------------------- | --------------------------------------------------- |
| Swagger UI            | `[/docs](http://localhost:8000/docs)`                 | Interactive API explorer with try-it-out requests   |
| ReDoc                 | `[/redoc](http://localhost:8000/redoc)`               | Read-only, structured reference documentation       |
| OpenAPI specification | `[/openapi.json](http://localhost:8000/openapi.json)` | Machine-readable OpenAPI 3 schema served by FastAPI |


An exported copy of the OpenAPI specification is also checked into the repository at `[docs/api/openapi.json](openapi.json)`.

## Alert ingestion flow

1. **Falco** detects a rule match on a monitored container and emits a JSON alert via its HTTP output webhook.
2. The webhook **POST** request is sent to `/alerts/falco` on the Medusa API.
3. The API normalizes the payload, extracting `rule`, `priority`, `output`, container metadata from `output_fields`, and `tags`, and stores the full raw event in PostgreSQL.
4. Analysts can list or update stored alerts via `/alerts/` and `/alerts/{alert_id}`.

```
Falco ──webhook (JSON)──▶ POST /alerts/falco ──▶ PostgreSQL (alerts)
```

## Forensic event workflow

Forensic events represent checkpoint capture jobs triggered either automatically by Falco or manually by an analyst.

### Automatic flow (Falco-triggered)

1. Falco (or an integration layer) sends a alert payload to **POST** `/forensic-checkpoint/falco_alert`.
2. The API validates alert priority against a minimum threshold (`warning` and above).
3. A `forensic_events` row is created in phase `pending` with `trigger_source=falco`. Kubernetes context (`pod_name`, `namespace`, `container_name`) is not yet populated.
4. The event may optionally reference an existing alert via `alert_id`.
5. Downstream checkpoint pipeline workers pick up the event, enrich it with Kubernetes context, and advance it through the lifecycle.

### Manual flow (analyst-triggered)

1. An analyst submits **POST** `/forensic-checkpoint/manual_alert` with explicit Kubernetes context (`pod_name`, `namespace`, `container_name`) and an optional `alert_id` to link to a prior Falco alert.
2. A `forensic_events` row is created in phase `pending` with `trigger_source=manual`.
3. The checkpoint pipeline processes the event and stores the resulting CRIU snapshot.

### Querying events

Use **GET** `/forensic-checkpoint/{event_id}` to retrieve the current state of a forensic event, including its phase and checkpoint location once available.

```
                    
Falco ─────────────▶POST /forensic-checkpoint/falco_alert ──┐
                                                             │
                                                             ▼
Analyst ──────────▶ POST /forensic-checkpoint/manual_alert ─▶ PostgreSQL (forensic_events)
                                                             │
                                                             ▼
                                              Checkpoint Pipeline ──▶ Checkpoint Storage
```

## Forensic event lifecycle states

The `phase` field on a forensic event tracks progress through the checkpoint pipeline:


| Phase         | Meaning                                                                                      |
| ------------- | -------------------------------------------------------------------------------------------- |
| `pending`     | Event registered; alert received but Kubernetes context may not yet be resolved.             |
| `queued`      | Kubernetes context is known; the event is waiting for the checkpoint operator to process it. |
| `in_progress` | A checkpoint operator is actively capturing the container memory snapshot.                   |
| `success`     | Checkpoint completed; `checkpoint_location` points to the stored artifact.                   |
| `failed`      | Checkpoint attempt failed; details may be recorded in `raw_report`.                          |
| `ignored`     | Event was skipped (e.g. low priority, duplicate, or policy exclusion).                       |


## Key endpoints


| Method | Path                                | Purpose                                    |
| ------ | ----------------------------------- | ------------------------------------------ |
| `POST` | `/alerts/falco`                     | Ingest a Falco webhook alert               |
| `GET`  | `/alerts/`                          | List all persisted alerts                  |
| `PUT`  | `/alerts/{alert_id}`                | Update an existing alert                   |
| `POST` | `/forensic-checkpoint/falco_alert`  | Create a forensic event from a Falco alert |
| `POST` | `/forensic-checkpoint/manual_alert` | Manually trigger a forensic checkpoint     |
| `GET`  | `/forensic-checkpoint/{event_id}`   | Retrieve a forensic event by ID            |
| `GET`  | `/health`                           | Service health check                       |


