# Medusa

> A container forensics framework for automated evidence capture and attack chain analysis.

Medusa detects attacks on containerised workloads using Falco, automatically captures CRIU memory snapshots on alert, correlates events into MITRE ATT&CK chains, and exposes everything to analysts through a REST API, a React dashboard, and a forensic CLI.

---

## Current state — v1

v1 is the minimal working foundation: a vulnerable target container monitored by Falco, with alerts persisted to PostgreSQL via a FastAPI backend.

```
medusa-v1/
├── docker-compose.yml
├── .env.example
├── infra/
│   ├── falco/
│   │   ├── falco.yaml              # Falco config — webhook → api
│   │   └── rules/
│   │       └── medusa_rules.yaml   # Custom rules: T1059, T1005, T1110
│   └── postgres/
│       └── init/
│           └── 01_schema.sql       # alerts + snapshots tables
└── services/
    ├── target/                     # Intentionally vulnerable app (FastAPI)
    │   ├── Dockerfile
    │   └── app/
    │       ├── main.py
    │       └── requirements.txt
    └── api/                        # FastAPI backend
        ├── Dockerfile
        ├── main.py
        ├── requirements.txt
        ├── db/session.py
        ├── models/alert.py
        └── routers/alerts.py
```

### How v1 works

![Medusa_v1_architecture](images/medusa_v1_architecture.png)

```
 target  ──syscalls──▶  falco  ──webhook──▶  api (FastAPI)  ──▶  postgres
```

1. **target** runs a FastAPI app with intentional vulnerabilities (command injection, path traversal, weak SSH).
2. **falco** monitors the target's kernel syscalls via eBPF and fires an HTTP webhook on every rule match - **currently very dummies rules, just for testing the env**
3. **api** receives Falco alerts, normalises them, and persists them to PostgreSQL.
4. **postgres** stores raw alerts with full JSONB payloads for later querying.

### Quickstart

```bash
cp .env.example .env
docker compose up --build

# verify
curl http://localhost:8000/health
curl "http://localhost:8080/ping?host=localhost;id"   # trigger a Falco alert
curl http://localhost:8000/alerts/
```

### API endpoints (v1)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/alerts/falco` | Receive alert from Falco |
| `GET` | `/alerts/` | List alerts — params: `priority`, `container`, `since`, `limit` |
| `GET` | `/alerts/{id}` | Single alert detail |
| `GET` | `/health` | Health check |


---


## Contributing

This project is part of an academic research framework on container forensics.
Issues and pull requests are welcome.
