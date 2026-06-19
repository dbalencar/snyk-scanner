# Deploying to on-prem Kubernetes

Assumes: RabbitMQ and Postgres already running and reachable from the
cluster, Harbor as the container registry, an on-prem S3-compatible store
(MinIO, Ceph RGW, etc.), and Vault with Kubernetes auth already enabled
against this cluster.

## 1. Build and push images to Harbor

```sh
HARBOR=harbor.internal.example.com/snyk-scanner

docker build -t $HARBOR/dispatcher:latest dispatcher/
docker push $HARBOR/dispatcher:latest

for tag in golang node python maven gradle ruby dotnet php linux; do
  docker build --build-arg BASE_TAG=$tag -t $HARBOR/scan-job:$tag scanner/
  docker push $HARBOR/scan-job:$tag
done
```

`k8s/dispatcher-deployment.yaml` and `dispatcher/config.py`'s
`JOB_IMAGE_PREFIX` already point at `harbor.internal.example.com/snyk-scanner/...`
— change the host to match your real Harbor instance.

## 2. Image pull secret

```sh
kubectl create secret docker-registry harbor-pull-secret \
  --namespace eventus \
  --docker-server=harbor.internal.example.com \
  --docker-username=<robot-account> \
  --docker-password=<robot-account-token>
```

Use a Harbor robot account scoped to pull-only on the `snyk-scanner` project,
not a personal account.

## 3. RBAC and quota (namespace `eventus`, no cluster access)

We only have access to the `eventus` namespace — no cluster-scoped
permissions. There's no `Namespace` object to apply (it already exists
and is managed elsewhere), and every manifest in `k8s/` is intentionally
namespace-scoped (`Role`/`RoleBinding`, never `ClusterRole`/`ClusterRoleBinding`).

```sh
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/resourcequota.yaml   # only if your namespace role permits creating ResourceQuota
```

If `kubectl apply -f k8s/resourcequota.yaml` fails with a permissions
error, the quota is likely centrally managed for `eventus` already —
skip it and move on.

`k8s/rbac.yaml` only grants the `snyk-dispatcher` ServiceAccount Job
create/get/list/watch/delete within the `eventus` namespace — it has
no cluster-wide permissions. Also create the `snyk-scan-job` ServiceAccount
referenced by `dispatcher/k8s_jobs.py` (Jobs run under their own identity,
distinct from the dispatcher's, so each gets only the Vault role it needs):

```sh
kubectl create serviceaccount snyk-scan-job -n eventus
```

## 4. Vault: policies, roles, and secrets

Two distinct identities need two distinct policies — the dispatcher never
needs `SNYK_TOKEN` or S3 credentials, and scan jobs never need to know
about RabbitMQ's admin connection, just the publish credentials. Don't
collapse these into one shared policy.

```sh
vault policy write snyk-dispatcher - <<'EOF'
path "secret/data/snyk-scanner/dispatcher" {
  capabilities = ["read"]
}
EOF

vault policy write snyk-scan-job - <<'EOF'
path "secret/data/snyk-scanner/scan-job" {
  capabilities = ["read"]
}
EOF

vault write auth/kubernetes/role/snyk-dispatcher \
  bound_service_account_names=snyk-dispatcher \
  bound_service_account_namespaces=eventus \
  policies=snyk-dispatcher \
  ttl=1h

vault write auth/kubernetes/role/snyk-scan-job \
  bound_service_account_names=snyk-scan-job \
  bound_service_account_namespaces=eventus \
  policies=snyk-scan-job \
  ttl=30m   # short — scan jobs are short-lived, no reason to mint long-lived tokens
```

Populate the two kv-v2 paths:

```sh
vault kv put secret/snyk-scanner/dispatcher \
  rabbitmq_url="amqp://snyk-dispatcher:<password>@rabbitmq.internal:5672/snyk-scanner" \
  database_url="postgresql://snyk_dispatcher:<password>@postgres.internal:5432/snyk_scanner"

vault kv put secret/snyk-scanner/scan-job \
  snyk_token="<snyk-org-api-token>" \
  rabbitmq_url="amqp://snyk-scan-job:<password>@rabbitmq.internal:5672/snyk-scanner" \
  database_url="postgresql://snyk_scan_job:<password>@postgres.internal:5432/snyk_scanner" \
  s3_endpoint="https://s3.internal.example.com" \
  s3_bucket="snyk-scan-results" \
  s3_access_key="<access-key>" \
  s3_secret_key="<secret-key>"
```

Use separate RabbitMQ/Postgres users for dispatcher vs. scan-job (the
dispatcher only needs publish-free consume rights on `scan.requests` plus
DB write access to `scans`/`scan_units`; scan jobs only need publish rights
on `scan.results`/`scan.completed` plus row-level DB write — neither needs
the other's surface). Provisioning those users/grants in RabbitMQ and
Postgres is on you per "already provisioned" — just make sure they're
actually separate principals, not the same shared user reused twice.

The Vault Agent Injector's `MutatingWebhookConfiguration` is a cluster-scoped
object we can't inspect without cluster access. If injection silently
doesn't happen (no `vault-agent` init/sidecar container shows up on `kubectl
describe pod`), ask whoever manages the cluster whether `eventus` is
excluded from injection by namespace label (`vault.hashicorp.com/agent-inject`
selector / namespace-exclude annotations on the injector itself).

## 5. RabbitMQ: queues and DLQ

Already provisioned per your setup, but confirm these exist with dead-lettering
configured (not yet wired up in this scaffold's code — it currently
nacks-without-requeue on permanent failures, which only works as a DLQ if
the queue itself has `x-dead-letter-exchange` set):

- `scan.requests` (with DLX to `scan.requests.dlq`)
- `scan.results`
- `scan.completed`

## 6. Postgres

Run `migrations/0001_init.sql` against the existing database/schema this
service should use.

## 7. Deploy

```sh
kubectl apply -f k8s/dispatcher-deployment.yaml
kubectl -n eventus rollout status deployment/snyk-dispatcher
```

## 8. Smoke test

Publish a message to `scan.requests` against a repo on a host listed in
`ALLOWED_GIT_HOSTS` (currently set to `git.internal.example.com` in the
manifest — change to your real internal Git host(s)), then watch:

```sh
kubectl -n eventus get jobs -w
kubectl -n eventus logs -l app=snyk-dispatcher -f
```

A Job should appear per detected project path, and a `scan.completed`
message should land once all units finish.
