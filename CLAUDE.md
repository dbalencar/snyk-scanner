# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this system does

RabbitMQ-driven Kubernetes dispatcher for async Snyk scanning. It consumes `{git_url, ref, org_id}` messages, shallow-clones the repo, detects project stacks via `dispatcher/detector.py`, and fans out one K8s Job per detected project path. Each Job runs whichever Snyk scan types apply (`sca`, `sast`, `iac`, `container`), uploads raw JSON to S3-compatible storage, and publishes results back via Postgres + RabbitMQ. An atomic counter in the `scans` table fires exactly one `scan.completed` event when all units finish.

## Two target environments

- **Prod (`main.py`, `k8s_jobs.py`, `entrypoint.sh`)**: Vault Agent Injector renders secrets into `/vault/secrets/config`; Harbor as registry; namespace `eventus` (no cluster-scoped access). Configured via `k8s/` manifests and documented in `DEPLOY.md`.
- **Local (`main_local.py`, `k8s_jobs_local.py`, `entrypoint_local.sh`)**: Kind cluster; secrets via env vars; `localhost/snyk-scan-job` image prefix. Configured via `k8s-local/` + `local-env.sh`.

## Commands

### Local development (docker-compose + Kind)

```sh
# Start RabbitMQ, Postgres, MinIO
docker compose -f deploy/docker-compose.yml up -d

# Install dispatcher dependencies
pip install -r dispatcher/requirements.txt

# Load local env vars
source local-env.sh

# Run dispatcher against local Kind cluster
cd dispatcher && python main_local.py
```

### Build scan-job images

```sh
# Production (for Harbor)
docker build --build-arg BASE_TAG=python -t snyk-scan-job:python scanner/
docker build --build-arg BASE_TAG=node   -t snyk-scan-job:node   scanner/

# Local (for Kind)
docker build -f scanner/Dockerfile.local --build-arg BASE_TAG=python -t localhost/snyk-scan-job:python scanner/
```

### Run tests

```sh
python3 -m unittest discover -s tests -v
```

### Syntax checking

```sh
# Check Python files
python3 -m py_compile dispatcher/main.py dispatcher/detector.py dispatcher/k8s_jobs.py

# Check shell scripts
sh -n scanner/entrypoint.sh scanner/entrypoint_local.sh
```

### Send a test scan request

```sh
# Required: GIT_URL; optional: GIT_REF, ORG_ID, RABBITMQ_URL
export GIT_URL=https://github.com/example/repo
python test-scan-request.py
```

### Database migration

```sh
psql "$DATABASE_URL" -f migrations/0001_init.sql
```

## Architecture

### Key data flow

1. `dispatcher/main.py` (or `main_local.py`) consumes from `scan.requests` queue.
2. `git_utils.py` shallow-clones the repo; `ALLOWED_GIT_HOSTS` is the SSRF allowlist — it must be non-empty or all requests are rejected.
3. `detector.py` walks the clone (max depth 2, skips `IGNORED_DIRS`) and builds `ProjectUnit` objects. `SCA_MARKERS` maps filenames to `(image_tag, priority)` — lock files beat manifests beat loose requirement files.
4. `k8s_jobs.py` creates one K8s `batch/v1 Job` per unit. Job name is deterministic (`scan-<scan_id_prefix>-<path_hash>`) so re-dispatch on dispatcher crash is idempotent (409 = already exists = OK).
5. Inside each Job: `scanner/entrypoint.sh` sources Vault-rendered secrets, clones the repo again, converts `uv.lock` → `requirements.txt` via `uv export` if needed, then runs each `snyk` subcommand. Exit code 1 = findings (success); ≥2 = actual failure.
6. `scanner/publish_result.py` uses an atomic Postgres counter (`completed_units >= expected_units`) to fire `scan.completed` exactly once after all units finish.

### Notable design constraints

- `uv.lock` is flagged as `UNSUPPORTED_BY_SNYK` — the entrypoint exports it to `requirements.txt` before scanning. This plumbing runs through `detector.py` → `k8s_jobs*.py` → `entrypoint*.sh` via the `DEPENDENCY_FILE` env var.
- The dispatcher and scan-job use separate Vault paths / Postgres users / RabbitMQ users — least-privilege by design.
- `psycopg2.connect(DATABASE_URL)` is used directly for DSN parsing (not a hand-rolled parser) because Postgres DSNs allow special characters in passwords.
- `GIT_SSL_NO_VERIFY` is opt-in via `.env.local` only — never hardcoded.

### Branch state

Two branches exist and have **not been merged**:
- `claude/affectionate-tesla-nt6ndo` — scaffold, prod-facing baseline
- `feature/enhanced-detector-and-local-testing` — Python lockfile detection improvements + local Kind testing infra on top of scaffold

Decide on a merge strategy before extending either branch.

## Known gaps (deferred)

- DLQ wiring: messages are nacked with `requeue=False` on permanent failures but no `x-dead-letter-exchange` binding is configured.
- Per-org `SNYK_TOKEN` lookup (single shared token currently).
- Sweeper for scans stuck `in_progress` after a dispatcher crash mid-fan-out.
- Structured logging / metrics.
- Object storage lifecycle policy (raw scan JSON kept indefinitely).
