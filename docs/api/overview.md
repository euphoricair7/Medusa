# API Overview

The Medusa API receives Falco alerts, persists them for analysis, and coordinates forensic checkpoint events that capture container memory state via the checkpoint-restore-operator.

## Interactive documentation

| Resource              | URL                                                   | Description                                         |
| --------------------- | ----------------------------------------------------- | --------------------------------------------------- |
| Swagger UI            | `[/docs](http://localhost:8000/docs)`                 | Interactive API explorer with try-it-out requests   |
| ReDoc                 | `[/redoc](http://localhost:8000/redoc)`               | Read-only, structured reference documentation       |
| OpenAPI specification | `[/openapi.json](http://localhost:8000/openapi.json)` | Machine-readable OpenAPI 3 schema served by FastAPI |

An exported copy of the OpenAPI specification is also checked into the repository at `[docs/api/openapi.json](openapi.json)`.

## Alert ingestion (Falco)

1. **Falco** detects a rule match and emits JSON via its HTTP webhook.
2. In Docker Compose, Falco posts to `http://api:8000/alerts/falco` (configured in `infra/falco/falco.yaml`). Both services must share the `lab-net` network so the `api` hostname resolves.
3. The API normalizes the payload and stores it in PostgreSQL (`alerts` table).

```
Falco (lab-net) ──webhook http://api:8000/alerts/falco──▶ POST /alerts/falco ──▶ PostgreSQL (alerts)
```

From the host, trigger a lab alert via the vulnerable target (`curl "http://localhost:8080/ping?host=localhost;id"`) and list ingested alerts with `GET /alerts/`. The target response may show `ping: not found` in stderr; the shell injection still fires Falco rules.

## Manual forensic checkpoint

1. Analyst submits **POST** `/alerts/manual` with `pod_name`, `namespace`, `container_name`, and optional `alert_id`.
2. The API creates or links an `alerts` row, then runs shared trigger logic (`process_trigger_forensic`, `trigger_source=manual`).
3. A `forensic_events` row is created and a `ForensicSnapshotChain` CR is submitted to Kubernetes. Phase becomes `queued`.
4. A background sync loop polls operator CR status and updates the DB (`Completed` → `success`, sets `checkpoint_location`).
5. **GET** `/forensic-checkpoint/{event_id}` returns current event state.

```
Analyst ──▶ POST /alerts/manual ──▶ Alert (create/link) ──▶ forensic_events 
                                                                        │
                                                                        ▼
                                                                ForensicSnapshotChain CR
                                                                        │
                                                                        ▼
                                                                    checkpoint-restore-operator
                                                                                        │
                                  GET /forensic-checkpoint/{id} ◀── status sync ◀─────┘
```

Unified automatic ingestion via `/alerts/falco` is planned. A legacy **POST** `/forensic-checkpoint/falco_alert` stub exists but does not create operator CRs.

## Forensic event lifecycle

| Phase           | Meaning                                                              |
| --------------- | -------------------------------------------------------------------- |
| `pending`       | Event registered; Kubernetes context not yet resolved.               |
| `queued`        | CR created; operator reconciliation pending or starting.             |
| `in_progress`   | Operator is actively capturing snapshots.                            |
| `success`       | Checkpoint completed; `checkpoint_location` set.                     |
| `failed`        | CR creation or checkpoint failed; see `raw_report`.                |
| `ignored`       | Skipped (low priority, duplicate, or policy exclusion).            |

## Key endpoints

| Method | Path                               | Purpose                                   |
| ------ | ---------------------------------- | ----------------------------------------- |
| `POST` | `/alerts/falco`                    | Ingest a Falco webhook alert              |
| `POST` | `/alerts/manual`                   | Manually trigger a forensic checkpoint    |
| `GET`  | `/alerts/`                         | List persisted alerts                     |
| `PUT`  | `/alerts/{alert_id}`               | Update an existing alert                  |
| `POST` | `/forensic-checkpoint/falco_alert` | Legacy Falco forensic stub (follow-up)    |
| `GET`  | `/forensic-checkpoint/{event_id}`  | Retrieve a forensic event by ID           |
| `GET`  | `/health`                          | Service health check                      |
