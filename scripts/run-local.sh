#!/usr/bin/env bash
# Run grant_access or revoke_access locally with functions-framework, against
# emulated env vars. Does NOT talk to real GCP — the underlying clients will
# fail with auth/permission errors unless you've run `gcloud auth application-default
# login` and point PROJECT_ID at a real project you control. This script exists
# for exercising validation logic and request/response shape locally, and for
# manually smoke-testing against a real dev project once you deploy.
#
# Usage:
#   scripts/run-local.sh grant   # serves grant_access on :8080
#   scripts/run-local.sh revoke  # serves revoke_access on :8081 (Pub/Sub emulation)
set -euo pipefail

PROJECT_ID="${BANKVAULT_PROJECT_ID:-local-dev-project}"
PII_BUCKET_NAME="${BANKVAULT_PII_BUCKET_NAME:-${PROJECT_ID}-loan-origination-pii}"

export GOOGLE_CLOUD_PROJECT="$PROJECT_ID"
export PII_BUCKET_NAME
export AUDIT_DATASET="bankvault_audit"
export AUDIT_TABLE="access_grants"
export SESSION_SECRET_PREFIX="bankvault-session-"
export MAX_GRANT_DURATION_MINUTES="240"
export ALLOWED_REQUESTER_DOMAIN="${BANKVAULT_ALLOWED_DOMAIN:-}"

case "${1:-}" in
  grant)
    cd "$(dirname "$0")/../functions/grant_access"
    echo "Serving grant_access on http://localhost:8080 (POST /)"
    echo 'Try: curl -s localhost:8080 -H "Content-Type: application/json" -d '"'"'{"requested_by":"officer@bank.example.com","approved_by":"manager@bank.example.com","justification":"LN-4471","duration_minutes":30}'"'"' | python3 -m json.tool'
    functions-framework --target=grant_access --port=8080
    ;;
  revoke)
    cd "$(dirname "$0")/../functions/revoke_access"
    echo "Serving revoke_access on http://localhost:8081 (CloudEvent target — POST a Pub/Sub-shaped event)"
    echo "This function ignores the event payload and queries BigQuery directly, so it will fail fast without real GCP credentials + a populated audit table."
    functions-framework --target=revoke_access --signature-type=cloudevent --port=8081
    ;;
  *)
    echo "Usage: $0 {grant|revoke}" >&2
    exit 1
    ;;
esac
