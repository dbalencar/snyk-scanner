# Handoff: Snyk repo-scanning pipeline

## To pick this up locally

```bash
git clone <remote-url> snyk-scanner
cd snyk-scanner
git checkout feature/enhanced-detector-and-local-testing   # force-pushed, history rewritten — see below
```

Two branches exist on the remote:

- `claude/affectionate-tesla-nt6ndo` — the main scaffold, on-prem deploy target
  (Vault Agent Injector, Harbor, namespace-only `eventus` access). This is the
  "production-facing" branch.
- `feature/enhanced-detector-and-local-testing` — adds Python lockfile
  detection improvements and a full local (kind/docker-compose) testing setup
  on top of the scaffold. **Just had a security/cleanup pass; was force-pushed
  (`73ebf8d` → `2dfd6c5`)** to amend the commit and purge a 9.9MB `kind`
  binary from history. If you have an old local copy of this branch, discard
  it and re-fetch rather than merging — the history was rewritten.

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
  `scanner/entrypoint.sh` / `entrypoint_local.sh` — in-Job script; converts
  `uv.lock` → `requirements.txt` via `uv export` before `snyk test`, sources
  Vault-rendered secrets (prod) or takes env vars directly (local)
- `migrations/0001_init.sql` — `scans` + `scan_units` tables
- `DEPLOY.md` — on-prem deploy guide (Harbor, Vault, namespace `eventus`,
  no cluster-scoped resources — namespace-only access)
- `k8s/` — prod manifests; `k8s-local/` — kind/docker-compose local infra

## What was just fixed (this session, on feature/enhanced-detector-and-local-testing)

A full review of this branch found and fixed:
- Committed 9.9MB `kind` binary — removed from working tree, then **history
  purged** by amending the branch's single commit (safe: unmerged feature
  branch)
- Leaked internal hostname/repo path (`gitlab.dell.com`, an internal Dell
  repo) and a token-in-URL pattern in `test-scan-request.py` — rewritten to
  take everything from env vars
- A hardcoded SSRF-allowlist bypass for `gitlab.dell.com` in
  `dispatcher/git_utils_local.py` — removed
- `uv.lock` was detected but never converted before scanning, and the
  conversion/`dependency_file` plumbing never reached the **production**
  dispatch path — wired `dependency_file` through
  `detector.py → k8s_jobs.py/k8s_jobs_local.py → main.py/main_local.py →
  entrypoint.sh/entrypoint_local.sh` for both prod and local
- Hand-rolled `DATABASE_URL` parser (broke on special characters in
  passwords) in `dispatcher/db.py` and `scanner/publish_result.py` — reverted
  to plain `psycopg2.connect(DATABASE_URL)`, which parses DSNs natively
- TLS-verification-bypass `pip --trusted-host` flags and an unverified
  Alpine-base assumption in `scanner/Dockerfile` / `Dockerfile.local` —
  removed; Dockerfiles now detect `apk` vs `apt-get` instead of guessing
- `GIT_SSL_NO_VERIFY=true` was hardcoded in `k8s_jobs_local.py` — made opt-in
  via `.env.local` instead of defaulting on (MITM risk if it leaked into a
  non-local config)
- Normalized `SCA_MARKERS` dict in `detector.py` to consistent
  `(tag, priority)` tuples, simplifying the marker-selection loop

All edited `.py` files pass `python3 -m py_compile`; all edited shell scripts
pass `sh -n`. Everything above is committed as a single amended commit
(`2dfd6c5`) and pushed.

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
  a local kind cluster, but don't reuse these patterns outside local testing

## Local testing setup

`docker-compose.yml` under `deploy/` brings up RabbitMQ/Postgres/MinIO for a
plain local run; `k8s-local/*.yaml` + `kind` give you the same in a local k8s
cluster instead. `local-env.sh` sets the env vars for the local (non-Vault,
non-Harbor) path. `test-scan-request.py` publishes a test scan request — set
`GIT_URL` (required), `GIT_REF`, `ORG_ID`, `RABBITMQ_URL` as env vars before
running it.
