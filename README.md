# Medusa

> A container forensics framework for automated evidence capture and attack chain analysis.

Medusa detects attacks on containerised workloads using Falco, automatically captures CRIU memory snapshots on alert, correlates events into MITRE ATT&CK chains, and exposes everything to analysts through a REST API, a React dashboard, and a forensic CLI.

---

## Current state — v1

v1 is the minimal working foundation: a vulnerable target container monitored by Falco, with alerts persisted to PostgreSQL via a FastAPI backend. Falco webhook ingestion and manual analyst triggers both run the shared forensic pipeline (`process_trigger_forensic`) to create CRIU checkpoint capture jobs via the checkpoint-restore-operator.

```
Medusa/
├── docker-compose.yml
├── .env.example
├── docs/
│   ├── api/overview.md
│   ├── architecture/overview.md
│   ├── installation/
│   │   └── falco.md                # Docker vs Helm Falco install guide
│   └── database/
│       ├── schema.md
│       └── er-diagram.md
├── infra/
│   ├── falco/
│   │   ├── falco.yaml              # Docker Compose Falco only → POST /alerts/falco
│   │   └── rules/medusa_rules.yaml # shared rules (compose + Helm)
│   └── postgres/init/01_schema.sql
├── scripts/
│   ├── falco-daemonset-setup.sh    # Helm install for cluster Falco
│   └── .env.example
└── services/
    ├── api/                        # FastAPI backend
    │   ├── main.py
    │   ├── config.py
    │   ├── forensic_service.py       # shared checkpoint trigger
    │   ├── forensic_chain.py       # ForensicSnapshotChain CR builder
    │   ├── forensic_sync.py        # operator CR status → DB sync
    │   ├── db/session.py
    │   ├── k8s/client.py           # Kubernetes client wrapper
    │   ├── models/
    │   │   ├── alert.py
    │   │   └── forensic.py
    │   └── routers/
    │       ├── alerts.py           # /alerts/falco, /alerts/manual
    │       └── forensic.py         # GET /forensic-checkpoint/{id}
    └── target/                     # intentionally vulnerable app
        └── app/
```

### How v1 works

![Medusa_v1_architecture](images/medusa_v1_architecture.png)

```
 target  ──syscalls──▶  falco  ──webhook──▶  api  ──▶  postgres
 analyst ──manual────▶  api  ──▶  ForensicSnapshotChain CR  ──▶  operator
                              ▲
                              └── falco ingest: medusa tag + k8s context + priority → forensic CR
```

1. **target** runs a FastAPI app with intentional vulnerabilities (command injection, path traversal, weak SSH).
2. **falco** monitors syscalls via eBPF and sends alerts to **POST `/alerts/falco`**.
3. **api** persists every Falco alert, then runs the shared forensic trigger when the rule has the `medusa` tag, k8s pod context is present, and priority meets the threshold. Manual **POST `/alerts/manual`** uses the same pipeline. Pod dedup avoids duplicate CRs during active captures on the same pod.
4. **postgres** stores alerts and forensic event state; a background sync updates phases from operator CR status.

### Quickstart

**Prerequisites:** Docker Compose, a local Kubernetes cluster with the checkpoint-restore-operator installed, and a host kubeconfig mounted into the API container. The apiserver URL in kubeconfig must be reachable from Docker containers (use your node IP, not `127.0.0.1`).

```bash
# One-time: point kubeconfig at a container-reachable apiserver
export NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
kubectl config set-cluster $(kubectl config view --minify -o jsonpath='{.clusters[0].name}') \
  --server=https://${NODE_IP}:6443

cp .env.example .env
docker compose up --build

# verify
curl http://localhost:8000/health
curl "http://localhost:8080/ping?host=localhost;id"   # trigger a Falco alert (see note below)
curl http://localhost:8000/alerts/
```

The `/ping` endpoint is intentionally vulnerable: the `;id` suffix runs shell injection as root. `ping` may be missing in the target image (`ping: not found` in stderr is normal); Falco still detects the spawned shell.

### Falco: Docker Compose vs cluster (Helm)

Medusa supports two Falco deployments. Both post to **POST** `/alerts/falco`; pick one based on what you want to monitor.

| Mode | Command | Monitors |
|------|---------|----------|
| **Docker Compose** (lab) | `docker compose up` includes the `falco` service | Compose `target` container via Docker socket |
| **Cluster** (Helm) | `scripts/falco-daemonset-setup.sh` | Pods in your Kubernetes cluster |

Use **cluster Falco** for the full pipeline (`medusa`-tagged rules, k8s metadata in alerts, automatic forensic CRs on cluster pods). Use **compose Falco** for local lab demos — alerts are stored, but the lab `target` usually lacks `k8s.pod.name` so CRs are not created automatically.

When using cluster Falco, start only `api` and `postgres` from compose (omit the `falco` service). See [`docs/installation/falco.md`](docs/installation/falco.md) for install steps, env vars, and troubleshooting.

### Docker lab networking

All compose services share the **`medusa-lab-net`** bridge network (`lab-net` in `docker-compose.yml`). Service DNS names match container hostnames:

| Service  | Hostname   | Host access        | In-network access        |
|----------|------------|--------------------|--------------------------|
| target   | `target`   | `localhost:8080`   | `http://target:8080`     |
| api      | `api`      | `localhost:8000`   | `http://api:8000`        |
| postgres | `postgres` | `localhost:5432`   | `postgres:5432`          |
| falco    | `falco`    | —                  | webhook → `http://api:8000/alerts/falco` |

The API connects to PostgreSQL at `postgres:5432` and mounts `${HOME}/.kube/config` for Kubernetes CR creation. Falco delivers alerts to the API over Docker DNS (`api:8000`), which requires the API to be on `lab-net` rather than `network_mode: host`.

Manual checkpoint test (requires a running pod in the cluster):

```bash
curl -X POST http://localhost:8000/alerts/manual \
  -H "Content-Type: application/json" \
  -d '{"pod_name":"nginx","namespace":"default","container_name":"nginx"}'
```

### API endpoints (v1)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/alerts/falco` | Receive alert from Falco; always persisted; triggers forensic when `medusa` tag, k8s context, and priority ≥ warning |
| `GET` | `/alerts/` | List all persisted alerts |
| `PUT` | `/alerts/{alert_id}` | Update an existing alert |
| `POST` | `/alerts/manual` | Manually trigger a forensic checkpoint |
| `GET` | `/forensic-checkpoint/{event_id}` | Retrieve a forensic event by ID |
| `GET` | `/health` | Health check |

### API documentation

FastAPI generates interactive and machine-readable API documentation automatically:

| Resource | URL | Description |
|----------|-----|-------------|
| Swagger UI | `/docs` | Interactive API explorer |
| ReDoc | `/redoc` | Read-only reference documentation |
| OpenAPI specification | `/openapi.json` | Machine-readable OpenAPI 3 schema |

See [`docs/api/overview.md`](docs/api/overview.md) for ingestion flows, webhook URLs (dev vs prod), pod dedup, idempotency semantics, and forensic event lifecycle details.

### Tests

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest
```

Run a single file or test with `pytest tests/api-test/test_idempotency_dedup.py` or `pytest path/to/test.py::test_name`.

---


## Contributing

This project is part of an academic research framework on container forensics.
Issues and pull requests are welcome.
