# Apply with: vault policy write snyk-dispatcher dispatcher-policy.hcl  (etc.)
# Mirrors the two kv-v2 paths read by the Vault Agent Injector templates in
# k8s/dispatcher-deployment.yaml and dispatcher/k8s_jobs.py.

# --- dispatcher-policy.hcl ---
path "secret/data/snyk-scanner/dispatcher" {
  capabilities = ["read"]
}

# --- scan-job-policy.hcl ---
path "secret/data/snyk-scanner/scan-job" {
  capabilities = ["read"]
}
