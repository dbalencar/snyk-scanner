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
- `k8s/` — namespace, RBAC, dispatcher Deployment, Vault policies (production).
- `k8s-local/` — RabbitMQ, Postgres, MinIO manifests for a local Kind cluster.
- `deploy/docker-compose.yml` — local RabbitMQ + Postgres + MinIO for dev.
- `tests/` — unit tests for the scanner pipeline scripts.

For deploying to real on-prem infra (Harbor, existing RabbitMQ/Postgres,
on-prem S3, Vault), see `DEPLOY.md`.

## Local dev

Two local paths exist: docker-compose (no Kubernetes) and Kind (full k8s).

### docker-compose (dispatcher only, no scan Jobs)

```sh
docker compose -f deploy/docker-compose.yml up -d
pip install -r dispatcher/requirements.txt
export RABBITMQ_URL=amqp://guest:guest@localhost:5672/
export DATABASE_URL=postgresql://scanner:scanner@localhost:5432/snyk_scanner
export ALLOWED_GIT_HOSTS=github.com,gitlab.com
python dispatcher/main.py   # requires in-cluster k8s; use main_local.py for kind
```

### Kind cluster (full end-to-end local testing)

```sh
# Start RabbitMQ, Postgres, MinIO and create the scan-results bucket
kubectl apply -f k8s-local/

# Load local env vars (sets K8S_NAMESPACE, JOB_IMAGE_PREFIX, etc.)
source local-env.sh

# Run the dispatcher against the local kind cluster
cd dispatcher && python main_local.py
```

`main_local.py` loads the `kind-snyk-scanner-local` kubeconfig context and
uses `k8s_jobs_local.py` (inline env vars, no Vault) instead of the prod job
builder.

Send a test scan request:

```sh
export GIT_URL=https://github.com/example/repo
python test-scan-request.py
```

### Build scan-job images

```sh
# Production (for Harbor)
docker build --build-arg BASE_TAG=golang -t snyk-scan-job:golang scanner/
docker build --build-arg BASE_TAG=node   -t snyk-scan-job:node   scanner/

# Local (for Kind) — requires scanner/custom.crt (obtain from internal CA store)
docker build -f scanner/Dockerfile.local --build-arg BASE_TAG=python \
  -t localhost/snyk-scan-job:python-local scanner/
kind load docker-image localhost/snyk-scan-job:python-local --name snyk-scanner-local
```

`scanner/custom.crt` is gitignored. Place your corporate CA certificate there
before building the local image so `uv` and `pip` can reach internal registries.

## Running tests

```sh
pip install -r dispatcher/requirements.txt  # pika, psycopg2-binary (boto3 via pip)
pip install boto3
python3 -m unittest discover -s tests -v
```

28 tests covering `summarize.py`, `publish_result.py`, and `upload_result.py`
using stdlib `unittest` and `unittest.mock` — no external test runner needed.

## Known follow-ups (not yet implemented)

- DLQ wiring on `scan.requests` / `scan.results` (queue declarations with
  `x-dead-letter-exchange` need to be added at deploy time).
- Per-org `SNYK_TOKEN` lookup (currently one Vault path shared by all scan jobs).
- Stuck-scan sweeper (a scan stuck `in_progress` past a timeout never
  self-heals yet).
- Metrics/structured logging correlation by `scan_id`.
- Object storage lifecycle policy for old scan results.
