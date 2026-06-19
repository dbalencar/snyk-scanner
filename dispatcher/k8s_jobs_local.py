import hashlib
import os
from pathlib import Path

from kubernetes import client

from config import Config


def load_env_local():
    """Load environment variables from .env.local file if it exists."""
    env_local_path = Path(__file__).parent.parent / ".env.local"
    if env_local_path.exists():
        with open(env_local_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key.strip()] = value.strip()


def job_name(scan_id: str, project_path: str) -> str:
    """Deterministic name so re-dispatch after a dispatcher crash is idempotent
    (creating a Job that already exists is a 409, treated as a no-op by caller).
    """
    path_hash = hashlib.sha1(project_path.encode()).hexdigest()[:8]
    short_scan = scan_id.replace("-", "")[:12]
    return f"scan-{short_scan}-{path_hash}"


def build_job(scan_id: str, git_url: str, ref: str, image_tag: str,
              project_path: str, scan_types: list[str], dependency_file: str = "") -> client.V1Job:
    # Load environment variables from .env.local file
    load_env_local()
    
    name = job_name(scan_id, project_path)
    # For local testing, append -local suffix to image tags
    local_image_tag = f"{image_tag}-local" if not image_tag.endswith("-local") else image_tag
    # For kind, use the full image name with localhost/ prefix
    # since images are loaded directly into the cluster with that name
    image = f"localhost/snyk-scan-job:{local_image_tag}"

    # Local testing environment variables (instead of Vault)
    # For kind with services deployed in-cluster, use Kubernetes service names
    snyk_token = os.environ.get("SNYK_TOKEN", "")
    local_secrets = [
        client.V1EnvVar(name="SNYK_TOKEN", value=snyk_token),
        client.V1EnvVar(name="RABBITMQ_URL", value="amqp://guest:guest@rabbitmq:5672/"),
        client.V1EnvVar(name="DATABASE_URL", value="postgresql://scanner:scanner@postgres:5432/snyk_scanner"),
        client.V1EnvVar(name="S3_ENDPOINT", value="http://minio:9000"),
        client.V1EnvVar(name="S3_BUCKET", value="snyk-scan-results"),
        client.V1EnvVar(name="S3_ACCESS_KEY", value="minioadmin"),
        client.V1EnvVar(name="S3_SECRET_KEY", value="minioadmin"),
    ]

    # Job-specific environment variables
    job_env = [
        client.V1EnvVar(name="SCAN_ID", value=scan_id),
        client.V1EnvVar(name="GIT_URL", value=git_url),
        client.V1EnvVar(name="GIT_REF", value=ref),
        client.V1EnvVar(name="PROJECT_PATH", value=project_path),
        client.V1EnvVar(name="SCAN_TYPES", value=",".join(scan_types)),
        client.V1EnvVar(name="DEPENDENCY_FILE", value=dependency_file),
    ]
    # If a local self-signed git host genuinely needs TLS verification
    # disabled, opt in explicitly via .env.local (GIT_SSL_NO_VERIFY=true) —
    # don't default it on, since that's a MITM hole if it leaks into any
    # non-local config.
    if os.environ.get("GIT_SSL_NO_VERIFY"):
        job_env.append(client.V1EnvVar(name="GIT_SSL_NO_VERIFY", value=os.environ["GIT_SSL_NO_VERIFY"]))

    # Combine local secrets with job environment variables
    env = local_secrets + job_env

    container = client.V1Container(
        name="scan",
        image=image,
        env=env,
        resources=client.V1ResourceRequirements(
            requests={"cpu": "250m", "memory": "256Mi"},
            limits={"cpu": "1", "memory": "1Gi"},
        ),
    )

    pod_spec = client.V1PodSpec(
        containers=[container],
        restart_policy="Never",
        service_account_name="default",  # Use default service account for local testing
    )

    template = client.V1PodTemplateSpec(
        metadata=client.V1ObjectMeta(
            labels={
                "app": "snyk-scan-job",
                "scan-id": scan_id,
                "project-path-hash": name.split("-")[-1],
            },
        ),
        spec=pod_spec,
    )

    spec = client.V1JobSpec(
        template=template,
        backoff_limit=Config.JOB_BACKOFF_LIMIT,
        active_deadline_seconds=Config.JOB_ACTIVE_DEADLINE_SECONDS,
        ttl_seconds_after_finished=Config.JOB_TTL_SECONDS_AFTER_FINISHED,
    )

    return client.V1Job(
        api_version="batch/v1",
        kind="Job",
        metadata=client.V1ObjectMeta(
            name=name,
            labels={"app": "snyk-scan-job", "scan-id": scan_id},
        ),
        spec=spec,
    )


def create_job(batch_api: client.BatchV1Api, job: client.V1Job) -> None:
    try:
        batch_api.create_namespaced_job(namespace=Config.K8S_NAMESPACE, body=job)
    except client.exceptions.ApiException as e:
        if e.status == 409:
            # Already exists from a prior dispatch attempt for this scan_id;
            # treat as success so redelivery after a crash is idempotent.
            return
        raise