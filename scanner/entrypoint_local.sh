#!/usr/bin/env sh
set -eu

# Local testing version - environment variables are passed directly
# instead of being sourced from Vault Agent Injector
# SCAN_ID, GIT_URL, GIT_REF, PROJECT_PATH, SCAN_TYPES come from the Job's env
# SNYK_TOKEN, RABBITMQ_URL, DATABASE_URL, S3_* are passed as env vars

WORKDIR="$(mktemp -d)"
CLI_VERSION="$(snyk --version)"

cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

publish_result() {
  # args: scan_type status object_key summary_json
  python3 /usr/local/bin/publish_result.py \
    --scan-id "$SCAN_ID" \
    --project-path "$PROJECT_PATH" \
    --scan-type "$1" \
    --status "$2" \
    --object-key "${3:-}" \
    --summary "${4:-{}}" \
    --cli-version "$CLI_VERSION"
}

# For local testing with private GitLab instances, use custom certificate
# The custom.crt file is installed in the system CA store by the Dockerfile
# Configure git to use the system certificate store
export GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt

git clone --depth 1 --branch "$GIT_REF" --single-branch "$GIT_URL" "$WORKDIR/repo"
TARGET_DIR="$WORKDIR/repo/$PROJECT_PATH"
cd "$TARGET_DIR"

# Snyk's CLI doesn't read uv.lock directly; export it to requirements.txt
# (a format Snyk fully supports) before running the sca scan.
# UV_NATIVE_TLS=true is set in the Dockerfile, so uv will use the system
# certificate store which includes the custom Dell certificate.
SCA_FILE_ARG=""
if [ "${DEPENDENCY_FILE:-}" = "uv.lock" ]; then
  uv export --format requirements-txt --no-hashes -o requirements.txt
  SCA_FILE_ARG="--file=requirements.txt"
elif [ -n "${DEPENDENCY_FILE:-}" ] && [ -f "$DEPENDENCY_FILE" ]; then
  SCA_FILE_ARG="--file=$DEPENDENCY_FILE"
fi

# Snyk CLI exit codes: 0 = no issues, 1 = issues found (still a successful
# scan), 2+ = actual failure (auth error, bad manifest, network, etc).
run_snyk() {
  set +e
  "$@" > "$OUT_FILE"
  CODE=$?
  set -e
  if [ "$CODE" -ge 2 ]; then
    STATUS="failed"
  fi
}

IFS=','
for SCAN_TYPE in $SCAN_TYPES; do
  OUT_FILE="$WORKDIR/${SCAN_TYPE}.json"
  STATUS="completed"

  case "$SCAN_TYPE" in
    sca)
      run_snyk snyk test $SCA_FILE_ARG --json
      ;;
    sast)
      run_snyk snyk code test --json
      ;;
    iac)
      run_snyk snyk iac test --json
      ;;
    container)
      if [ -f Dockerfile ]; then
        BASE_IMAGE="$(grep -m1 -i '^FROM' Dockerfile | awk '{print $2}')"
        run_snyk snyk container test --file=Dockerfile "$BASE_IMAGE" --json
      else
        STATUS="skipped"
        echo '{}' > "$OUT_FILE"
      fi
      ;;
    *)
      echo "unknown scan type: $SCAN_TYPE" >&2
      STATUS="failed"
      echo '{}' > "$OUT_FILE"
      ;;
  esac

  OBJECT_KEY="scans/${SCAN_ID}/${PROJECT_PATH:-root}/${SCAN_TYPE}.json"
  python3 /usr/local/bin/upload_result.py \
    --file "$OUT_FILE" --object-key "$OBJECT_KEY" \
    --endpoint "$S3_ENDPOINT" --bucket "$S3_BUCKET" \
    --access-key "$S3_ACCESS_KEY" --secret-key "$S3_SECRET_KEY"

  SUMMARY="$(python3 /usr/local/bin/summarize.py --file "$OUT_FILE" --scan-type "$SCAN_TYPE")"

  publish_result "$SCAN_TYPE" "$STATUS" "$OBJECT_KEY" "$SUMMARY"
done