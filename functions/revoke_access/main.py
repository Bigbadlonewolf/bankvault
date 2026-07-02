"""BankVault — revoke_access.

Pub/Sub-triggered revocation sweep. Cloud Scheduler publishes to the
revocation-trigger topic every few minutes (see terraform/scheduler.tf);
each message fires this function, which does not act on the message
contents — it queries the audit ledger directly for the source of truth.

Enforcement does not depend on this function running. Every binding
grant_access writes carries a `request.time < timestamp(...)` CEL
condition, so GCP denies access the moment the window closes regardless of
sweep timing. This function's job is cleanup and audit completeness:
removing the now-inert binding from the bucket's IAM policy, destroying the
session secret, and writing the REVOKE row that closes out the ledger entry
for that request.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any

import functions_framework
from google.api_core.exceptions import GoogleAPIError, NotFound
from google.cloud import bigquery, secretmanager, storage

# ── Structured logging ────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
PROJECT_ID = os.environ["GOOGLE_CLOUD_PROJECT"]
PII_BUCKET_NAME = os.environ["PII_BUCKET_NAME"]
AUDIT_DATASET = os.environ["AUDIT_DATASET"]
AUDIT_TABLE = os.environ["AUDIT_TABLE"]
SESSION_SECRET_PREFIX = os.environ.get("SESSION_SECRET_PREFIX", "bankvault-session-")

AUDIT_TABLE_ID = f"{PROJECT_ID}.{AUDIT_DATASET}.{AUDIT_TABLE}"

_EXPIRED_UNREVOKED_QUERY = f"""
    SELECT
        g.request_id,
        g.requested_by,
        g.resource,
        g.window_end,
        g.iam_condition_expression,
        g.session_secret_name
    FROM `{AUDIT_TABLE_ID}` AS g
    WHERE g.action_type = 'GRANT'
      AND g.window_end <= @now
      AND NOT EXISTS (
          SELECT 1
          FROM `{AUDIT_TABLE_ID}` AS r
          WHERE r.action_type = 'REVOKE'
            AND r.request_id = g.request_id
      )
"""

# ── Entrypoint ────────────────────────────────────────────────────────────────


@functions_framework.cloud_event
def revoke_access(cloud_event: Any) -> None:
    """Pub/Sub entrypoint. Triggered by Cloud Scheduler on a fixed cadence."""
    now = datetime.now(timezone.utc)
    expired_grants = find_expired_unrevoked_grants(now)

    logger.info(
        "Revocation sweep starting",
        extra={"json_fields": {"expired_grant_count": len(expired_grants)}},
    )

    for grant in expired_grants:
        revoke_grant(grant, now)


# ── Query ──────────────────────────────────────────────────────────────────────


def find_expired_unrevoked_grants(now: datetime) -> list[dict]:
    """Return GRANT rows whose window has closed with no matching REVOKE row.

    The ledger is append-only, so "currently active" is derived at query
    time rather than tracked as mutable state: a request is active if it has
    a GRANT row and no corresponding REVOKE row yet.
    """
    client = bigquery.Client(project=PROJECT_ID)
    job_config = bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("now", "TIMESTAMP", now.isoformat())]
    )
    result = client.query(_EXPIRED_UNREVOKED_QUERY, job_config=job_config).result()
    return [dict(row) for row in result]


# ── Revocation ─────────────────────────────────────────────────────────────────


def revoke_grant(grant: dict, now: datetime) -> None:
    """Remove the IAM binding and session secret for one expired grant, then
    write the REVOKE audit row. Best-effort and idempotent: if the binding or
    secret is already gone, that's logged and treated as success — the
    outcome we care about (no standing access, ledger closed out) already
    holds.
    """
    request_id = grant["request_id"]
    requested_by = grant["requested_by"]
    resource = grant["resource"]
    condition_expression = grant["iam_condition_expression"]
    session_secret_name = grant["session_secret_name"]

    try:
        removed = remove_iam_binding(requested_by, condition_expression)
        if not removed:
            logger.warning(
                "No matching IAM binding found during revoke — may have been removed already",
                extra={"json_fields": {"request_id": request_id, "requested_by": requested_by}},
            )

        if session_secret_name:
            delete_session_secret(session_secret_name)

    except GoogleAPIError:
        logger.exception(
            "Infrastructure failure while revoking grant — will retry next sweep",
            extra={"json_fields": {"request_id": request_id}},
        )
        raise

    write_revoke_row(
        request_id=request_id,
        requested_by=requested_by,
        resource=resource,
        revoked_at=now,
        event_timestamp=now,
    )

    logger.info(
        "Grant revoked",
        extra={"json_fields": {"request_id": request_id, "requested_by": requested_by, "resource": resource}},
    )


def remove_iam_binding(requested_by: str, condition_expression: str) -> bool:
    """Remove the conditional binding matching this grant's exact CEL
    expression and member. Leaves every other binding on the bucket policy
    untouched. Returns False if no matching binding was found.
    """
    client = storage.Client(project=PROJECT_ID)
    bucket = client.bucket(PII_BUCKET_NAME)

    policy = bucket.get_iam_policy(requested_policy_version=3)
    policy.version = 3

    member = f"user:{requested_by}"
    remaining = []
    removed = False

    for binding in policy.bindings:
        condition = binding.get("condition") or {}
        is_match = (
            binding.get("role") == "roles/storage.objectViewer"
            and member in binding.get("members", set())
            and condition.get("expression") == condition_expression
        )
        if is_match:
            removed = True
            continue
        remaining.append(binding)

    if removed:
        policy.bindings = remaining
        bucket.set_iam_policy(policy)

    return removed


def delete_session_secret(secret_name: str) -> None:
    """Destroy the Secret Manager secret backing this grant's session token."""
    client = secretmanager.SecretManagerServiceClient()
    try:
        client.delete_secret(request={"name": secret_name})
    except NotFound:
        logger.warning("Session secret already deleted", extra={"json_fields": {"secret_name": secret_name}})


# ── BigQuery audit ledger ──────────────────────────────────────────────────────


def write_revoke_row(
    request_id: str,
    requested_by: str,
    resource: str,
    revoked_at: datetime,
    event_timestamp: datetime,
) -> None:
    """Append the REVOKE row that closes out this request_id in the ledger."""
    client = bigquery.Client(project=PROJECT_ID)

    row = {
        "request_id": request_id,
        "action_type": "REVOKE",
        "requested_by": requested_by,
        "resource": resource,
        "justification": None,
        "window_start": None,
        "window_end": None,
        "approved_by": None,
        "granted_at": None,
        "revoked_at": revoked_at.isoformat(),
        "iam_condition_expression": None,
        "session_secret_name": None,
        "denial_reason": None,
        "event_timestamp": event_timestamp.isoformat(),
    }

    errors = client.insert_rows_json(AUDIT_TABLE_ID, [row])
    if errors:
        raise GoogleAPIError(f"BigQuery insert errors: {errors}")
