# Falco installation

Medusa can run Falco in two ways. Both send alerts to the same API endpoint (**POST** `/alerts/falco`); they differ in **where Falco runs**, **what workloads it sees**, and **how the webhook URL is configured**.

| | Docker Compose Falco | Cluster Falco (Helm) |
| --- | --- | --- |
| **Use when** | Local lab, docker-compose `target` container | Real Kubernetes workloads (pods in your cluster) |
| **Install** | `docker compose up` (service in `docker-compose.yml`) | `scripts/falco-daemonset-setup.sh` |
| **Config** | `infra/falco/falco.yaml` | Generated Helm values (script) |
| **Rules** | `infra/falco/rules/medusa_rules.yaml` mounted into the container | Same file, embedded via Helm `customRules` |
| **Webhook URL** | `http://api:8000/alerts/falco` (Docker DNS on `lab-net`) | `http://<NODE_IP>:8000/alerts/falco` (must be reachable from cluster pods) |
| **K8s metadata** | Limited (Docker target only; no `k8s.pod.name` on lab target) | Full (`k8s.ns.name`, `k8s.pod.name` via container/CRI collector) |
| **Forensic auto-trigger** | Only if payload includes k8s context (usually via cluster Falco) | Yes, for Medusa-tagged rules on cluster pods |

**Do not run both at once** unless you intend to — you will get duplicate or confusing alerts.

Shared custom rules live in [`infra/falco/rules/medusa_rules.yaml`](../../infra/falco/rules/medusa_rules.yaml). Both install paths load that file; only the delivery mechanism differs.

---

## Prerequisites (both paths)

- Medusa API and PostgreSQL running (`docker compose up -d api postgres` or full compose stack).
- API published on host port **8000** (default in `docker-compose.yml`).
- For forensic capture: Kubernetes cluster with checkpoint-restore-operator, and API kubeconfig pointing at a node-reachable apiserver (see [README quickstart](../../README.md#quickstart)).

---

## Option A — Docker Compose Falco (lab)

Best for hacking on the intentional **target** container in compose, without a cluster workload.

### Install

```bash
cp .env.example .env   # if not done already
docker compose up --build
```

This starts `medusa-falco` alongside `target`, `api`, and `postgres`. Falco config is [`infra/falco/falco.yaml`](../../infra/falco/falco.yaml):

- Webhook: `http://api:8000/alerts/falco`
- Rules: default Falco rules + `medusa_rules.yaml`
- Engine: eBPF, monitoring via Docker socket

### Verify

```bash
curl http://localhost:8000/health
curl "http://localhost:8080/ping?host=localhost;id"   # shell injection on target
curl http://localhost:8000/alerts/
```

Alerts from the lab target typically **lack** `k8s.pod.name`; ingestion still works, but automatic forensic CR creation needs cluster Falco (Option B).

### Stop

```bash
docker compose stop falco
# or bring down the whole stack
docker compose down
```

---

## Option B — Cluster Falco (Helm)

### Prerequisites

- `kubectl` and `helm` installed, with cluster admin or sufficient RBAC.
- Node internal IP reachable from pods (script auto-detects if `MEDUSA_API_HOST` is unset).
- Medusa API listening on `localhost:8000` on the host (or adjust `MEDUSA_API_PORT`).

### Configure (optional)

Copy and edit [`scripts/.env.example`](../../scripts/.env.example) to `scripts/.env`:

```bash
cp scripts/.env.example scripts/.env
```

### Install

```bash
# API must be up first
docker compose up -d api postgres

cd scripts
./falco-daemonset-setup.sh
```

The script:

1. Checks API health on localhost and cluster → API connectivity.
2. Adds the `falcosecurity` Helm repo.
3. Installs/upgrades Falco with:
   - Base `falco-rules` (macros required by Medusa rules) + `medusa_rules.yaml`
   - `http_output` → `http://<NODE_IP>:8000/alerts/falco`
   - `priority: warning` (reduces low-severity default noise)
   - Container engine collector enabled; k8s-meta collector disabled by default

For cluster installs, **skip** the compose `falco` service:

```bash
docker compose up -d api postgres target   # no falco service
```

### Verify

```bash
kubectl get pods -n falco
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20
# expect: falco_rules.yaml and medusa_rules.yaml loaded, pod Running

kubectl exec -it -n default deploy/nginx -- cat /etc/passwd

curl -s http://localhost:8000/alerts/ | jq '[.[] | select(.tags != null and (.tags | index("medusa")))] | .[0]'
kubectl get forensicsnapshotchains -n default | grep fsc-medusa
```

### Uninstall

```bash
./scripts/falco-daemonset-setup.sh --uninstall
```

---
