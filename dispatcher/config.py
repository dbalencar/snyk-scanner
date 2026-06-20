import os


def _list_env(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


class Config:
    RABBITMQ_URL = os.environ["RABBITMQ_URL"]
    REQUEST_QUEUE = os.environ.get("REQUEST_QUEUE", "scan.requests")
    REQUEST_DLQ = os.environ.get("REQUEST_DLQ", "scan.requests.dlq")

    DATABASE_URL = os.environ["DATABASE_URL"]

    K8S_NAMESPACE = os.environ.get("K8S_NAMESPACE", "eventus")
    JOB_IMAGE_PREFIX = os.environ.get("JOB_IMAGE_PREFIX", "ghcr.io/example/snyk-scan-job")
    JOB_TTL_SECONDS_AFTER_FINISHED = int(os.environ.get("JOB_TTL_SECONDS_AFTER_FINISHED", "3600"))
    JOB_BACKOFF_LIMIT = int(os.environ.get("JOB_BACKOFF_LIMIT", "1"))
    JOB_ACTIVE_DEADLINE_SECONDS = int(os.environ.get("JOB_ACTIVE_DEADLINE_SECONDS", "1800"))

    # Allowlist of git hosts the dispatcher is permitted to clone from.
    # Prevents scan.requests from being used as an SSRF primitive against
    # internal infrastructure. Must be set explicitly; empty means "deny all".
    ALLOWED_GIT_HOSTS = _list_env("ALLOWED_GIT_HOSTS")

    # RABBITMQ_URL / DATABASE_URL above, and SNYK_TOKEN / S3_* used by scan
    # jobs, are supplied via Vault Agent Injector (see k8s/dispatcher-deployment.yaml
    # and dispatcher/k8s_jobs.py VAULT_TEMPLATE) rather than K8s Secrets.

    # Personal access token for authenticated HTTPS git clones.
    # Never embed in a URL that gets logged or stored — inject at clone time only.
    GIT_TOKEN = os.environ.get("GIT_TOKEN", "")

    CLONE_DEPTH = int(os.environ.get("CLONE_DEPTH", "1"))
    CLONE_TIMEOUT_SECONDS = int(os.environ.get("CLONE_TIMEOUT_SECONDS", "60"))
