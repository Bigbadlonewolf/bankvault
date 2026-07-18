#!/usr/bin/env bash
# Serve either Cloud Function locally via functions-framework.
# The broker boots without real GCP: a stale-login or self-approval request is
# rejected before any PAM or BigQuery call. A request that passes validation will
# attempt the real seams and needs credentials + a deployed entitlement.
#
#   scripts/run-local.sh broker      # HTTP on :8080, entry handle_request
#   scripts/run-local.sh reconcile   # CloudEvent target on :8081, entry handle_event
set -euo pipefail

target="${1:-}"

case "$target" in
  broker)
    cd "$(dirname "$0")/../functions/request_broker"
    exec functions-framework --target=handle_request --debug --port=8080
    ;;
  reconcile)
    cd "$(dirname "$0")/../functions/reconcile"
    exec functions-framework --target=handle_event --signature-type=cloudevent --debug --port=8081
    ;;
  *)
    echo "usage: run-local.sh [broker|reconcile]" >&2
    exit 2
    ;;
esac
