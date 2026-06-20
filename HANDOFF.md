# Handoff: Snyk repo-scanning pipeline

## To pick this up locally

```bash
git clone <remote-url> snyk-scanner
cd snyk-scanner
git checkout feature/enhanced-detector-and-local-testing
```

Two branches exist on the remote:

- `claude/affectionate-tesla-nt6ndo` — the main scaffold, on-prem deploy target
  (Vault Agent Injector, Harbor, namespace-only `eventus` access). This is the
  "production-facing" branch.
- `feature/enhanced-detector-and-local-testing` — Python lockfile detection
  improvements, a full local (Kind/docker-compose) testing setup, bug fixes, and
  unit tests on top of the scaffold. Latest commit: `98f1e8a`.

These two branches have **not been merged into each other**. Decide whether
`feature/enhanced-detector-and-local-testing` should be rebased onto/merged
into `claude/affectionate-tesla-nt6ndo`, or vice versa, before going further.

## What the system does

RabbitMQ-driven Kubernetes dispatcher: consumes `{git_url, ref, org_id}`
messages, shallow-clones the repo, detects project stacks/scan types via
`dispatcher/detector.py`, and fans out one K8s Job per `(scan_id,
project_path)` running all applicable Snyk scan types (`sca`, `sast`, `iac`,
`container`) against a single shared clone. Each Job uploads raw `snyk --json`
output to S3-compatible storage, publishes a summary row to Postgres, and an
atomic counter (`completed_units >= expected_units` in `scans` table) ensures
exactly one "scan complete" signal once all units for a scan finish.

Key files:
- `dispatcher/main.py` / `main_local.py` — consumer loop (prod vs. local k8s)
- `dispatcher/detector.py` — stack detection, `SCA_MARKERS` priority table,
  flags `uv.lock` as `UNSUPPORTED_BY_SNYK` (needs conversion)
- `dispatcher/k8s_jobs.py` / `k8s_jobs_local.py` — Job builders (prod uses
  Vault Agent Injector annotations + Harbor pull secret; local uses inline
  env vars, no Vault)
- `scanner/entrypoint.sh` / `entrypoint_local.sh` — in-Job script; converts
  `uv.lock` → `requirements.txt` via `uv export` before `snyk test`, sources
  Vault-rendered secrets (prod) or takes env vars directly (local)
- `scanner/summarize.py` — reduces raw snyk JSON to severity counts; handles
  both object and array output from `snyk test --json`
- `migrations/0001_init.sql` — `scans` + `scan_units` tables
- `DEPLOY.md` — on-prem deploy guide (Harbor, Vault, namespace `eventus`,
  no cluster-scoped resources — namespace-only access)
- `k8s/` — prod manifests; `k8s-local/` — Kind/docker-compose local infra
- `tests/` — 28 unit tests for scanner pipeline scripts

## What was fixed across the two development sessions

### Session 1 (commit `2dfd6c5`, on `feature/enhanced-detector-and-local-testing`)

- Committed 9.9MB `kind` binary — removed from working tree, history purged
- Leaked internal hostname/repo path and token-in-URL pattern in
  `test-scan-request.py` — rewritten to take everything from env vars
- Hardcoded SSRF-allowlist bypass for an internal host in
  `dispatcher/git_utils_local.py` — removed
- `uv.lock` conversion/`dependency_file` plumbing never reached the production
  dispatch path — wired `dependency_file` through
  `detector.py → k8s_jobs.py/k8s_jobs_local.py → main.py/main_local.py →
  entrypoint.sh/entrypoint_local.sh`
- Hand-rolled `DATABASE_URL` parser (broke on special characters in passwords)
  in `dispatcher/db.py` and `scanner/publish_result.py` — reverted to plain
  `psycopg2.connect(DATABASE_URL)`
- TLS-verification-bypass `pip --trusted-host` flags in Dockerfiles — removed
- `GIT_SSL_NO_VERIFY=true` hardcoded in `k8s_jobs_local.py` — made opt-in via
  `.env.local`
- Normalised `SCA_MARKERS` dict in `detector.py` to consistent
  `(tag, priority)` tuples

### Session 2 (commit `98f1e8a`, on `feature/enhanced-detector-and-local-testing`)

- **uv SSL verification** (`Dockerfile.local`): uv defaults to `rustls` which
  ignores the system CA store. Added `ENV UV_SYSTEM_CERTS=true` so uv uses the
  OS TLS stack, which reads `/etc/ssl/certs/ca-certificates.crt` where the
  corporate CA cert is installed via `update-ca-certificates`.
- **JSON parsing error** (`scanner/summarize.py`): `snyk test --json` returns
  a JSON array when multiple projects are detected in one directory. The old
  `data.get("vulnerabilities", [])` call raised `AttributeError` on a list
  (not caught by the narrow `except (json.JSONDecodeError, FileNotFoundError)`),
  causing `summarize.py` to exit non-zero. Fixed by normalising data to a list
  of items before iterating, and broadening the exception catch to `except
  Exception`.
- **Entrypoint abort** (`scanner/entrypoint_local.sh`): An unnecessary
  `| python3 -c 'json.loads...'` round-trip pipe was appended to the `SUMMARY`
  capture. When `summarize.py` exited non-zero (see above), the inline
  `json.loads("")` also failed, making the whole command substitution exit
  non-zero. With `set -eu`, sh aborted the script — so `publish_result.py` was
  never called and the DB was never updated. Removed the pipe; `summarize.py`
  now always outputs valid JSON.
- **MinIO bucket** (`k8s-local/minio.yaml`): MinIO was deployed but the
  `snyk-scan-results` bucket was never created. `upload_result.py` raised
  `NoSuchBucket` on every upload, aborting the entrypoint before
  `publish_result.py` ran. Added a `minio/mc` Job that waits for MinIO readiness
  then runs `mc mb --ignore-existing`.
- **Gitignore** (`.gitignore`): Added `scanner/custom.crt` (corporate CA cert —
  should not be committed) and `.vscode/`.
- **Unit tests** (`tests/`): 28 tests covering the three scanner pipeline
  scripts; `python3 -m unittest discover -s tests -v`.

## Local testing setup

`docker-compose.yml` under `deploy/` brings up RabbitMQ/Postgres/MinIO for a
plain local run (no scan Jobs). `k8s-local/*.yaml` + Kind give you the full
end-to-end stack in a local Kubernetes cluster — apply `k8s-local/` first so
the MinIO bucket-creation Job runs before any scan Jobs attempt to upload.

`local-env.sh` sets the env vars for the local (non-Vault, non-Harbor) path.
`test-scan-request.py` publishes a test scan request — set `GIT_URL`
(required), `GIT_REF`, `ORG_ID`, `RABBITMQ_URL` as env vars before running.

`scanner/custom.crt` is gitignored. Copy your corporate CA cert there before
building `scanner/Dockerfile.local` so uv and pip can reach internal registries
over the corporate TLS proxy.

## Known follow-ups (not yet started, deliberately deferred)

- DLQ wiring for malformed/poison messages (currently nacked with
  `requeue=False`, no DLQ binding configured)
- Per-org `SNYK_TOKEN` lookup via Vault (currently a single shared token)
- A sweeper for scans stuck in-progress (e.g. dispatcher crash mid-fan-out
  after some Jobs created but before `ch.basic_ack`)
- Structured logging / metrics
- Object storage lifecycle policy (raw scan JSON currently kept forever)
- Decide on merge strategy between the two branches (see above)
- `k8s-local/*.yaml` and `local-env.sh` use plaintext default credentials
  (`guest`/`guest`, `minioadmin`/`minioadmin`, `scanner`/`scanner`) — fine for
  a local Kind cluster, but don't reuse these patterns outside local testing
