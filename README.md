# snyk-scanner

Async, fan-out Snyk scanning of git repos: a RabbitMQ-driven dispatcher
detects project stacks in a repo and spins up one Kubernetes Job per
detected project path. Each Job clones the repo once and runs whichever
of Snyk's four scan types (`sca`, `sast`, `iac`, `container`) apply to
that path, uploads raw results to object storage, indexes them in
Postgres, and publishes per-unit results plus one aggregate
`scan.completed` event when all units for a scan finish.

## Layout

- `dispatcher/` — RabbitMQ consumer that clones, detects stacks, creates Jobs.
- `scanner/` — Dockerfile + entrypoint that wraps the upstream `snyk/snyk:*`
  images; this is what actually runs `snyk test` / `snyk code test` /
  `snyk iac test` / `snyk container test` inside each Job.
- `migrations/` — Postgres schema (`scans`, `scan_units`).
- `k8s/` — namespace, RBAC, dispatcher Deployment, secret templates.
- `deploy/docker-compose.yml` — local RabbitMQ + Postgres + MinIO for dev.

## Local dev

```sh
docker compose -f deploy/docker-compose.yml up -d
pip install -r dispatcher/requirements.txt
export RABBITMQ_URL=amqp://guest:guest@localhost:5672/
export DATABASE_URL=postgresql://scanner:scanner@localhost:5432/snyk_scanner
export ALLOWED_GIT_HOSTS=github.com,gitlab.com
python dispatcher/main.py   # requires in-cluster k8s config; run against a kind/minikube cluster
```

Build a scan-job image per ecosystem:

```sh
docker build --build-arg BASE_TAG=golang -t snyk-scan-job:golang scanner/
docker build --build-arg BASE_TAG=node   -t snyk-scan-job:node   scanner/
```

## Known follow-ups (not yet implemented in this scaffold)

- DLQ wiring on `scan.requests` / `scan.results` (queue declarations with
  `x-dead-letter-exchange` need to be added at deploy time).
- Per-org `SNYK_TOKEN` lookup (currently one shared secret).
- Stuck-scan sweeper (a scan stuck `in_progress` past a timeout never
  self-heals yet).
- Metrics/structured logging correlation by `scan_id`.
- Object storage lifecycle policy for old scan results.
