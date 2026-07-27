# API Overview

The Medusa API receives Falco alerts, persists them for analysis, and coordinates forensic checkpoint events that capture container memory state via the checkpoint-restore-operator.

## Documents:

| Resource              | URL                                                   | Description                                         |
| --------------------- | ----------------------------------------------------- | --------------------------------------------------- |
| Swagger UI            | `[/docs](http://localhost:8000/docs)`                 | Interactive API explorer with try-it-out requests   |
| ReDoc                 | `[/redoc](http://localhost:8000/redoc)`               | Read-only, structured reference documentation       |
| OpenAPI specification | `[/openapi.json](http://localhost:8000/openapi.json)` | Machine-readable OpenAPI 3 schema served by FastAPI |

The live OpenAPI schema is served at `http://localhost:8000/openapi.json` when the API is running.

## Alert ingestion (Falco)

1. **Falco** detects a rule match and emits JSON via its HTTP webhook.
2. Falco posts to **POST** `/alerts/falco`. The webhook URL depends on the install:
   - **Docker Compose Falco:** `http://api:8000/alerts/falco` (`infra/falco/falco.yaml`, `lab-net` DNS).
   - **Cluster Falco (Helm):** `http://<NODE_IP>:8000/alerts/falco` (configured by `scripts/falco-daemonset-setup.sh`; must be reachable from Falco pods).
3. The API normalizes the payload and stores it in PostgreSQL (`alerts` table).
4. When the alert includes Kubernetes context in `output_fields` (e.g. `k8s.pod.name`) and priority meets the configured threshold, the API runs the shared forensic trigger (`process_trigger_forensic`) for the new alert row. Forensic errors are logged but do not fail ingestion — the endpoint still returns `{"status": "ok"}`.

See [`docs/installation/falco.md`](../installation/falco.md) for install steps and the Docker vs Helm distinction.

```
Falco ──webhook──▶ POST /alerts/falco ──▶ PostgreSQL (alerts)
                                              │
                                              ▼
                                      process_trigger_forensic
                                              │
                                              ▼
                             ForensicSnapshotChain CR (when k8s context present)
```

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

Both `/alerts/falco` and `/alerts/manual` use the same shared trigger and idempotency semantics below. A legacy **POST** `/forensic-checkpoint/falco_alert` stub exists but does not create operator CRs and does not participate in alert-scoped dedup.

## Idempotency and CR retry

Forensic triggers are deduplicated per alert row, not by time bucket:

```
idempotency_key = sha256("{alert_id}:{namespace}:{pod_name}:{container_name}")
```

| Situation | Behavior |
| --------- | -------- |
| Same `alert_id` resubmitted, CR exists, phase `queued` / `in_progress` / `success` | Return existing forensic event |
| CR deleted from cluster, or phase `failed` | Recreate `ForensicSnapshotChain` on the same DB row; reset `checkpoint_location` |
| Two different alerts, same pod within seconds | Two distinct forensic events (distinct `alert_id`) |

Unit tests: `tests/api-test/test_idempotency_key.py`, `test_idempotency_dedup.py`, `test_forensic_cr_retry.py`.

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
| `POST` | `/alerts/falco`                    | Ingest a Falco webhook alert; triggers forensic capture when k8s context is present |
| `POST` | `/alerts/manual`                   | Manually trigger a forensic checkpoint    |
| `GET`  | `/alerts/`                         | List persisted alerts                     |
| `PUT`  | `/alerts/{alert_id}`               | Update an existing alert                  |
| `POST` | `/forensic-checkpoint/falco_alert` | Legacy Falco forensic stub (follow-up)    |
| `GET`  | `/forensic-checkpoint/{event_id}`  | Retrieve a forensic event by ID           |
| `GET`  | `/health`                          | Service health check                      |
