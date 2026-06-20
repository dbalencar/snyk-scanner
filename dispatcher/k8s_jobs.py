import hashlib

from kubernetes import client

from config import Config


def job_name(scan_id: str, project_path: str) -> str:
    """Deterministic name so re-dispatch after a dispatcher crash is idempotent
    (creating a Job that already exists is a 409, treated as a no-op by caller).
    """
    path_hash = hashlib.sha1(project_path.encode()).hexdigest()[:8]
    short_scan = scan_id.replace("-", "")[:12]
    return f"scan-{short_scan}-{path_hash}"


# Vault Agent Injector renders this file inside the pod at
# /vault/secrets/config; entrypoint.sh sources it before running snyk.
VAULT_TEMPLATE = """\
{{- with secret "secret/data/snyk-scanner/scan-job" }}
export SNYK_TOKEN="{{ .Data.data.snyk_token }}"
export GIT_TOKEN="{{ .Data.data.git_token }}"
export RABBITMQ_URL="{{ .Data.data.rabbitmq_url }}"
export S3_ENDPOINT="{{ .Data.data.s3_endpoint }}"
export S3_BUCKET="{{ .Data.data.s3_bucket }}"
export S3_ACCESS_KEY="{{ .Data.data.s3_access_key }}"
export S3_SECRET_KEY="{{ .Data.data.s3_secret_key }}"
export DATABASE_URL="{{ .Data.data.database_url }}"
{{- end }}
"""


def build_job(scan_id: str, git_url: str, ref: str, image_tag: str,
              project_path: str, scan_types: list[str], dependency_file: str = "") -> client.V1Job:
    name = job_name(scan_id, project_path)
    image = f"{Config.JOB_IMAGE_PREFIX}:{image_tag}"

    env = [
        client.V1EnvVar(name="SCAN_ID", value=scan_id),
        client.V1EnvVar(name="GIT_URL", value=git_url),
        client.V1EnvVar(name="GIT_REF", value=ref),
        client.V1EnvVar(name="PROJECT_PATH", value=project_path),
        client.V1EnvVar(name="SCAN_TYPES", value=",".join(scan_types)),
        client.V1EnvVar(name="DEPENDENCY_FILE", value=dependency_file),
    ]

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
        image_pull_secrets=[client.V1LocalObjectReference(name="harbor-pull-secret")],
        service_account_name="snyk-scan-job",
    )

    template = client.V1PodTemplateSpec(
        metadata=client.V1ObjectMeta(
            labels={
                "app": "snyk-scan-job",
                "scan-id": scan_id,
                "project-path-hash": name.split("-")[-1],
            },
            annotations={
                "vault.hashicorp.com/agent-inject": "true",
                "vault.hashicorp.com/role": "snyk-scan-job",
                "vault.hashicorp.com/agent-inject-secret-config": "secret/data/snyk-scanner/scan-job",
                "vault.hashicorp.com/agent-inject-template-config": VAULT_TEMPLATE,
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
