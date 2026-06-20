#!/bin/bash
# Environment variables for local testing

# RabbitMQ connection (using docker-compose services)
export RABBITMQ_URL=amqp://guest:guest@localhost:5672/

# Database connection (using docker-compose Postgres)
export DATABASE_URL=postgresql://scanner:scanner@localhost:5432/snyk_scanner

# Kubernetes configuration
export K8S_NAMESPACE=default
export JOB_IMAGE_PREFIX=localhost/snyk-scan-job

# Git host allowlist for testing
export ALLOWED_GIT_HOSTS=github.com,gitlab.com

# Job configuration
export JOB_TTL_SECONDS_AFTER_FINISHED=3600
export JOB_BACKOFF_LIMIT=1
export JOB_ACTIVE_DEADLINE_SECONDS=1800

# Personal access token for authenticated HTTPS git clones (GitLab, GitHub, etc.)
# Required for private repos. Never commit the actual value.
export GIT_TOKEN=

# Git cloning configuration
export CLONE_DEPTH=1
export CLONE_TIMEOUT_SECONDS=60

echo "Local environment variables set for Snyk scanner testing"
echo "RabbitMQ: localhost:5672"
echo "Postgres: localhost:5432/snyk_scanner"
echo "Kubernetes: kind-snyk-scanner-local context"
echo "Namespace: default"
echo "Image prefix: localhost/snyk-scan-job"
