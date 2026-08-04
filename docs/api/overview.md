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

**POST** `/alerts/falco` is the standard Falco integration. Every webhook payload is persisted to the `alerts` table for auditing, listing, and correlation. The API then evaluates whether that alert should also trigger a checkpoint via the shared forensic pipeline.

### Webhook URL (dev vs prod)

| Environment | Falco install | Webhook URL |
| ----------- | ------------- | ----------- |
| **Local lab** | Docker Compose (`falco` service) | `http://api:8000/alerts/falco` - Docker DNS on `medusa-lab-net` (`infra/falco/falco.yaml`) |
| **Cluster / production** | Helm DaemonSet (`scripts/falco-daemonset-setup.sh`) | `http://<NODE_IP>:8000/alerts/falco` - node IP must be reachable from Falco pods |

See [`docs/installation/falco.md`](../installation/falco.md) for install steps. Do not run both Falco installs at once unless you intend to.

### Ingestion flow

1. **Falco** detects a rule match and POSTs the raw JSON webhook.
2. The API normalizes fields (`rule`, `priority`, `output`, `container_name`, `namespace`, `pod_name`, `tags`, `raw_event`) and **always** persists a new `alerts` row.
3. Forensic triggering runs only when **all** of the following hold:
   - **`medusa` tag present** - `"medusa"` must appear in the Falco rule's `tags` array. Alerts from default Falco rules (no `medusa` tag) are stored only; no checkpoint is attempted.
   - **Priority ≥ threshold** - default minimum is `warning` (`MIN_ALERT_PRIORITY` in API config; see `services/api/config.py`).
   - **Kubernetes pod context** - `k8s.pod.name` (or `k8smeta.pod.name` / `pod.name` fallback) in `output_fields`. Missing context is logged; ingestion still succeeds.
4. When eligible, the API calls `process_trigger_forensic` with `trigger_source=falco`, creates or reuses a `forensic_events` row, and submits a **ForensicSnapshotChain** CR to Kubernetes.
5. The endpoint **always** returns `{"status": "ok"}` - forensic errors (missing k8s context, CR creation failure, low priority) are logged but do not fail ingestion.

```
Falco ──webhook──▶ POST /alerts/falco ──▶ PostgreSQL (alerts)  [always]
                                              │
                         medusa tag + priority + k8s.pod.name?
                                              │ yes
                                              ▼
                                      process_trigger_forensic
                                              │
                         ┌────────────────────┼────────────────────┐
                         ▼                    ▼                    ▼
                  pod dedup (active)   alert idempotency    new event + CR
                         │                    │                    │
                         └────────────────────┴────────────────────┘
                                              ▼
                             ForensicSnapshotChain CR (default namespace)
```

### Acceptance criteria (Falco pipeline)

| Scenario | Expected behavior |
| -------- | ----------------- |
| Medusa-tagged alert, k8s metadata, priority ≥ warning | Alert saved **and** `ForensicSnapshotChain` CR created |
| Alert without `k8s.pod.name` | Alert saved; no CR; `200 {"status": "ok"}` |
| Low-priority alert (below `MIN_ALERT_PRIORITY`) | Alert saved; no CR |
| Same alert row resubmitted (same `alert_id`) | No duplicate CR - alert-scoped idempotency reuses `forensic_events` row |
| Burst of syscalls on same pod (distinct `alert_id`s) | One active CR per pod while phase is `queued` or `in_progress` - pod dedup reuses the in-flight event |
| Non-`medusa` Falco rule | Alert saved; forensic skipped |

`GET /alerts/` returns all persisted alerts ordered by `received_at` descending. Normalized `namespace` and `pod_name` columns are populated from `output_fields` when present.

## Manual forensic checkpoint

1. Analyst submits **POST** `/alerts/manual` with `pod_name`, `namespace`, `container_name`, and optional `alert_id`.
2. The API creates or links an `alerts` row, then runs shared trigger logic (`process_trigger_forensic`, `trigger_source=manual`).
3. A `forensic_events` row is created and a `ForensicSnapshotChain` CR is submitted to Kubernetes. Phase becomes `queued`.
4. A background sync loop polls operator CR status and updates the DB (`Completed` → `success`, sets `checkpoint_location`, merges `raw_report.operator`).
5. **GET** `/forensic-checkpoint/{event_id}` returns current event state (including `raw_report` when present).
6. A future DaemonSet analyzer can **POST** `/forensic-checkpoint/{event_id}/analysis` to attach checkpointctl output under `raw_report.checkpointctl` (see [Checkpointctl analysis ingest](#checkpointctl-analysis-ingest)).

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
                                                                  (raw_report.operator)
```

Both `/alerts/falco` and `/alerts/manual` use the same shared trigger and idempotency semantics below.

## Idempotency, pod dedup, and CR retry

Both `/alerts/falco` and `/alerts/manual` use `process_trigger_forensic`. Dedup happens in two layers:

### Pod dedup (cross-alert)

Before creating a new forensic event, the API checks for an **active** event on the same `(namespace, pod_name, container_name)` where:

- `phase` is `queued` or `in_progress`, **and**
- the linked `ForensicSnapshotChain` CR still exists in the cluster.

If found, that existing `forensic_events` row is returned. A **new alert row is still created**; the returned event may reference an earlier `alert_id`. This prevents duplicate CRs when one syscall burst produces many Falco alerts on the same pod.

After a capture completes (`success`) or fails (`failed`), a new alert on the same pod can create a new forensic event and CR.

### Alert-scoped idempotency

When no active pod-level capture exists, the API keys forensic rows per alert:

```
idempotency_key = sha256("{alert_id}:{namespace}:{pod_name}:{container_name}")
```

| Situation | Behavior |
| --------- | -------- |
| Same `alert_id` resubmitted, CR exists, phase `queued` / `in_progress` / `success` | Return existing forensic event (no duplicate CR) |
| CR deleted from cluster, or phase `failed` | Recreate `ForensicSnapshotChain` on the same DB row; reset `checkpoint_location` |
| New `alert_id`, same pod, active capture already running | Pod dedup - return existing in-flight event |
| New `alert_id`, same pod, prior capture `success` or `failed` | New forensic event and CR |

Unit tests: `tests/api-test/test_idempotency_key.py`, `tests/api-test/test_idempotency_dedup.py`, `tests/api-test/test_forensic_cr_retry.py`.

## Forensic event lifecycle

| Phase           | Meaning                                                              |
| --------------- | -------------------------------------------------------------------- |
| `pending`       | Event registered; Kubernetes context not yet resolved.               |
| `queued`        | CR created; operator reconciliation pending or starting.             |
| `in_progress`   | Operator is actively capturing snapshots.                            |
| `success`       | Checkpoint completed; `checkpoint_location` set.                     |
| `failed`        | CR creation or checkpoint failed; see `raw_report.error`.          |
| `ignored`       | Skipped (low priority, duplicate, or policy exclusion).            |

## `raw_report` shape

`forensic_events.raw_report` is a single JSONB object. Writers update **only their own key** so sync and analysis do not overwrite each other:

| Key | Written by | Purpose |
| --- | ---------- | ------- |
| `operator` | `forensic_sync` (CR poll) | Operator phase, snapshot chain records, conditions, signatures |
| `checkpointctl` | **POST** `/forensic-checkpoint/{event_id}/analysis` | Structured checkpointctl inspect output plus path/node metadata |
| `error` | `forensic_service` on CR create failure | e.g. `{"cr_create_error": "..."}`; cleared on successful recreate |

Example after capture completes and analysis is posted:

```json
{
  "operator": {
    "operator_phase": "Completed",
    "snapshot_count": 3,
    "snapshot_chain_records": [],
    "conditions": [],
    "error_message": null,
    "start_time": "...",
    "completion_time": "..."
  },
  "checkpointctl": {
    "checkpoint_path": "/var/lib/kubelet/checkpoints/checkpoint-....tar",
    "node_name": "kind-control-plane",
    "analyzer": "checkpointctl",
    "analyzed_at": "2026-08-04T06:12:15+00:00",
    "report": {}
  }
}
```

## Checkpointctl analysis ingest

**POST** `/forensic-checkpoint/{event_id}/analysis` merges a checkpointctl report into `raw_report.checkpointctl` (does not run checkpointctl). Used by a planned DaemonSet analyzer.

```bash
curl -X POST "http://localhost:8000/forensic-checkpoint/<EVENT_ID>/analysis" \
  -H "Content-Type: application/json" \
  -d '{
    "checkpoint_path": "/var/lib/kubelet/checkpoints/example.tar",
    "node_name": "kind-control-plane",
    "analyzer": "checkpointctl",
    "report": {"processes": [{"pid": 1, "comm": "bash"}]}
  }'
```

## Key endpoints

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `POST` | `/alerts/falco` | Ingest a Falco webhook alert; triggers forensic capture when `medusa` tag, k8s context, and priority threshold are met |
| `POST` | `/alerts/manual` | Manually trigger a forensic checkpoint |
| `GET` | `/alerts/` | List persisted alerts |
| `PUT` | `/alerts/{alert_id}` | Update an existing alert |
| `GET` | `/forensic-checkpoint/{event_id}` | Retrieve a forensic event by ID (includes `raw_report`) |
| `POST` | `/forensic-checkpoint/{event_id}/analysis` | Attach checkpointctl analysis under `raw_report.checkpointctl` |
| `GET` | `/health` | Service health check |
