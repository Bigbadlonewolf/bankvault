"""BankVault — grant_access.

HTTP-triggered approval workflow engine for the JIT privilege elevation
broker. A loan officer (or a system acting on their behalf) POSTs a grant
request; this function validates it against the bank's least-privilege
rules, applies a time-bound, resource-bound IAM condition on the
loan-origination PII bucket, mints a short-lived session token in Secret
Manager, and writes an append-only audit row to BigQuery — whether the
request is granted or denied.

This function never grants standing access. Every binding it writes carries
a `request.time < timestamp(...)` CEL condition, so GCP itself starts
denying the access the instant the window closes — independent of whether
revoke_access has run its cleanup sweep yet.
"""

import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import functions_framework
from google.api_core.exceptions import GoogleAPIError
from google.cloud import bigquery, secretmanager, storage
from flask import Request

# ── Structured logging ────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
PROJECT_ID = os.environ["GOOGLE_CLOUD_PROJECT"]
PII_BUCKET_NAME = os.environ["PII_BUCKET_NAME"]
AUDIT_DATASET = os.environ["AUDIT_DATASET"]
AUDIT_TABLE = os.environ["AUDIT_TABLE"]
SESSION_SECRET_PREFIX = os.environ.get("SESSION_SECRET_PREFIX", "bankvault-session-")
MAX_GRANT_DURATION_MINUTES = int(os.environ.get("MAX_GRANT_DURATION_MINUTES", "240"))
ALLOWED_REQUESTER_DOMAIN = os.environ.get("ALLOWED_REQUESTER_DOMAIN", "").strip()
DEFAULT_GRANT_DURATION_MINUTES = 60

AUDIT_TABLE_ID = f"{PROJECT_ID}.{AUDIT_DATASET}.{AUDIT_TABLE}"

# ── Entrypoint ────────────────────────────────────────────────────────────────


@functions_framework.http
def grant_access(request: Request):
    """HTTP entrypoint. Expects a JSON body — see validate_request for shape."""
    try:
        payload = request.get_json(silent=True) or {}
    except Exception:
        payload = {}

    result = process_grant_request(payload)
    status_code = 200 if result["status"] == "GRANTED" else 400
    return json.dumps(result), status_code, {"Content-Type": "application/json"}


# ── Orchestration ──────────────────────────────────────────────────────────────


def process_grant_request(payload: dict) -> dict:
    """Validate a grant request, apply the IAM binding, and write the audit row.

    Returns a JSON-serializable dict describing the outcome. Never raises for
    business-rule failures (bad input, policy violations) — those come back
    as a DENY result. Infrastructure failures (IAM API, BigQuery, Secret
    Manager) are logged and re-raised so Cloud Functions retries/alerts.
    """
    request_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    errors = validate_request(payload)
    if errors:
        reason = "; ".join(errors)
        logger.warning("Grant request denied: %s", reason, extra={"json_fields": {"request_id": request_id}})
        _write_audit_row_safe(
            request_id=request_id,
            action_type="DENY",
            requested_by=payload.get("requested_by", "unknown"),
            resource=payload.get("resource", PII_BUCKET_NAME),
            justification=payload.get("justification"),
            approved_by=payload.get("approved_by"),
            denial_reason=reason,
            event_timestamp=now,
        )
        return {"status": "DENIED", "request_id": request_id, "reason": reason}

    requested_by = payload["requested_by"]
    approved_by = payload["approved_by"]
    justification = payload["justification"]
    duration_minutes = int(payload.get("duration_minutes", DEFAULT_GRANT_DURATION_MINUTES))
    loan_application_id = payload.get("loan_application_id")

    window_start = now
    window_end = now + timedelta(minutes=duration_minutes)

    condition_expression = build_condition_expression(window_end, loan_application_id)

    try:
        apply_iam_binding(requested_by, condition_expression)
        session_secret_name = create_session_secret(request_id)
    except GoogleAPIError:
        logger.exception("Infrastructure failure while granting access", extra={"json_fields": {"request_id": request_id}})
        raise

    resource = (
        f"gs://{PII_BUCKET_NAME}/applications/{loan_application_id}"
        if loan_application_id
        else f"gs://{PII_BUCKET_NAME}"
    )

    _write_audit_row_safe(
        request_id=request_id,
        action_type="GRANT",
        requested_by=requested_by,
        resource=resource,
        justification=justification,
        window_start=window_start,
        window_end=window_end,
        approved_by=approved_by,
        granted_at=now,
        iam_condition_expression=condition_expression,
        session_secret_name=session_secret_name,
        event_timestamp=now,
    )

    logger.info(
        "Grant issued",
        extra={
            "json_fields": {
                "request_id": request_id,
                "requested_by": requested_by,
                "resource": resource,
                "window_end": window_end.isoformat(),
            }
        },
    )

    return {
        "status": "GRANTED",
        "request_id": request_id,
        "requested_by": requested_by,
        "resource": resource,
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "approved_by": approved_by,
        "iam_condition_expression": condition_expression,
        "session_secret_name": session_secret_name,
    }


# ── Validation ─────────────────────────────────────────────────────────────────


def validate_request(payload: dict) -> list[str]:
    """Return a list of validation errors. Empty list means the request is valid.

    Rules enforced here are the least-privilege gate for the whole system —
    everything downstream trusts that a request reaching apply_iam_binding
    already passed these checks.
    """
    errors: list[str] = []

    requested_by = payload.get("requested_by", "").strip()
    approved_by = payload.get("approved_by", "").strip()
    justification = payload.get("justification", "").strip()
    duration_minutes = payload.get("duration_minutes", DEFAULT_GRANT_DURATION_MINUTES)

    if not requested_by:
        errors.append("requested_by is required")
    elif ALLOWED_REQUESTER_DOMAIN and not requested_by.lower().endswith(f"@{ALLOWED_REQUESTER_DOMAIN.lower()}"):
        errors.append(f"requested_by must belong to domain {ALLOWED_REQUESTER_DOMAIN}")

    if not approved_by:
        errors.append("approved_by is required")
    elif requested_by and approved_by.lower() == requested_by.lower():
        # Segregation of duties: the requester cannot approve their own
        # access. This is the control SOX 404 ITGC reviewers look for first.
        errors.append("approved_by must differ from requested_by (segregation of duties)")

    if not justification:
        errors.append("justification is required")

    try:
        duration_minutes = int(duration_minutes)
        if duration_minutes <= 0:
            errors.append("duration_minutes must be positive")
        elif duration_minutes > MAX_GRANT_DURATION_MINUTES:
            errors.append(f"duration_minutes exceeds the {MAX_GRANT_DURATION_MINUTES}-minute cap")
    except (TypeError, ValueError):
        errors.append("duration_minutes must be an integer")

    return errors


# ── IAM ────────────────────────────────────────────────────────────────────────


def build_condition_expression(window_end: datetime, loan_application_id: str | None) -> str:
    """Build the CEL expression for the conditional IAM binding.

    Always time-bound. Additionally resource-bound (scoped to one loan
    application's object prefix) when the caller supplies
    loan_application_id — otherwise the grant is bucket-wide for the
    duration of the window.
    """
    expiry = window_end.strftime("%Y-%m-%dT%H:%M:%SZ")
    time_clause = f'request.time < timestamp("{expiry}")'

    if not loan_application_id:
        return time_clause

    prefix = f"projects/_/buckets/{PII_BUCKET_NAME}/objects/applications/{loan_application_id}"
    resource_clause = f'resource.name.startsWith("{prefix}")'
    return f"{time_clause} && {resource_clause}"


def apply_iam_binding(requested_by: str, condition_expression: str) -> None:
    """Add a conditional storage.objectViewer binding for one loan officer.

    Uses IAM policy version 3 — conditional bindings are not visible or
    settable under policy version 1. This does not touch any other binding
    already on the bucket's policy.
    """
    client = storage.Client(project=PROJECT_ID)
    bucket = client.bucket(PII_BUCKET_NAME)

    policy = bucket.get_iam_policy(requested_policy_version=3)
    policy.version = 3

    policy.bindings.append(
        {
            "role": "roles/storage.objectViewer",
            "members": {f"user:{requested_by}"},
            "condition": {
                "title": "bankvault-jit-grant",
                "description": "Time-bound, resource-bound BankVault JIT access grant",
                "expression": condition_expression,
            },
        }
    )

    bucket.set_iam_policy(policy)


# ── Secret Manager ─────────────────────────────────────────────────────────────


def create_session_secret(request_id: str) -> str:
    """Mint a short-lived session token and store it in Secret Manager.

    The token itself is never logged, returned in a log line, or written to
    BigQuery — only the secret's resource name is. revoke_access destroys
    this secret when the grant window closes.
    """
    client = secretmanager.SecretManagerServiceClient()
    parent = f"projects/{PROJECT_ID}"
    secret_id = f"{SESSION_SECRET_PREFIX}{request_id}"

    secret = client.create_secret(
        request={
            "parent": parent,
            "secret_id": secret_id,
            "secret": {"replication": {"automatic": {}}},
        }
    )

    token = secrets.token_urlsafe(32)
    client.add_secret_version(
        request={
            "parent": secret.name,
            "payload": {"data": token.encode("utf-8")},
        }
    )

    return secret.name


# ── BigQuery audit ledger ──────────────────────────────────────────────────────


def _write_audit_row_safe(**kwargs: Any) -> None:
    """Write an audit row, logging (but not raising) on failure.

    A BigQuery outage should not be able to either block a legitimate DENY
    response or crash a successful GRANT after the IAM binding is already
    live — but it must be loud. This is the one place in the module where a
    failure is swallowed, and it's logged at ERROR specifically so it's easy
    to alert on.
    """
    try:
        write_audit_row(**kwargs)
    except GoogleAPIError:
        logger.exception("Failed to write audit row — ledger is incomplete for this event", extra={"json_fields": kwargs})


def write_audit_row(
    request_id: str,
    action_type: str,
    requested_by: str,
    resource: str,
    event_timestamp: datetime,
    justification: str | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    approved_by: str | None = None,
    granted_at: datetime | None = None,
    iam_condition_expression: str | None = None,
    session_secret_name: str | None = None,
    denial_reason: str | None = None,
) -> None:
    """Append one row to the access_grants audit ledger. Never an UPDATE."""
    client = bigquery.Client(project=PROJECT_ID)

    row = {
        "request_id": request_id,
        "action_type": action_type,
        "requested_by": requested_by,
        "resource": resource,
        "justification": justification,
        "window_start": window_start.isoformat() if window_start else None,
        "window_end": window_end.isoformat() if window_end else None,
        "approved_by": approved_by,
        "granted_at": granted_at.isoformat() if granted_at else None,
        "revoked_at": None,
        "iam_condition_expression": iam_condition_expression,
        "session_secret_name": session_secret_name,
        "denial_reason": denial_reason,
        "event_timestamp": event_timestamp.isoformat(),
    }

    errors = client.insert_rows_json(AUDIT_TABLE_ID, [row])
    if errors:
        raise GoogleAPIError(f"BigQuery insert errors: {errors}")
