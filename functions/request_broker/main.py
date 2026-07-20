"""BankVault request broker.

One HTTP entry point. It is a pre-flight gate and an audit record. It is **not** a
chokepoint, and it does not create grants (ADR-006).

PAM attaches a grant's privileges to the calling principal, and there is no grantee
parameter on `CreateGrant`. A broker that called PAM would therefore elevate its own
service account, not the underwriter, which is the standing access this project exists
to remove. So the underwriter requests their own grant directly against the entitlement
this broker names back to them.

What it does:
  - refuses stale-login and malformed requests before they reach PAM, with a reason
  - writes the `auth_time` that gated each request into the append-only ledger

Enforced recency is an Access Context Manager reauth binding at the platform's one-hour
minimum. The 15-minute check here is early rejection and evidence, not enforcement; an
underwriter who skips this endpoint reaches PAM anyway (ADR-006).

PAM owns approval and expiry (ADR-001); nothing here revokes anything. The BigQuery call
sits behind a seam (`_bq_client`) so validation and freshness logic is unit-tested without
touching the network.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone

import functions_framework

APPLICATION_ID_RE = re.compile(r"^APP-\d{3,}$")


def _config() -> dict:
    return {
        "project_id": os.environ.get("PROJECT_ID", "local-dev"),
        "location": os.environ.get("LOCATION", "global"),
        "audit_dataset": os.environ.get("AUDIT_DATASET", "bankvault_audit"),
        "ledger_table": os.environ.get("LEDGER_TABLE", "access_grants"),
        "credit_bucket": os.environ.get("CREDIT_BUCKET", "local-credit-reports"),
        "allowed_domain": os.environ.get("ALLOWED_DOMAIN", "lender.example.com"),
        "max_auth_age_seconds": int(os.environ.get("MAX_AUTH_AGE_SECONDS", "900")),
        "max_grant_minutes": int(os.environ.get("MAX_GRANT_MINUTES", "30")),
        "entitlement_prefix": os.environ.get("ENTITLEMENT_PREFIX", "bankvault-credit-report-"),
    }


class RequestRejected(Exception):
    """Raised when a request fails a check. Carries the reason for the ledger."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# --- MFA freshness (ADR-004) -------------------------------------------------

def _decode_jwt_auth_time(id_token: str) -> int | None:
    """Read auth_time from a JWT payload.

    This decodes the claims segment only. It does NOT verify the signature; a real
    deployment verifies against the IdP JWKS. That stub boundary is called out in the
    README under "What this isn't".
    """
    try:
        payload_b64 = id_token.split(".")[1]
        padding = "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    except (IndexError, ValueError, binascii.Error):
        return None
    auth_time = claims.get("auth_time")
    return int(auth_time) if isinstance(auth_time, (int, float)) else None


def _extract_auth_time(payload: dict) -> int | None:
    if "auth_time" in payload:
        try:
            return int(payload["auth_time"])
        except (TypeError, ValueError):
            return None
    if "id_token" in payload and isinstance(payload["id_token"], str):
        return _decode_jwt_auth_time(payload["id_token"])
    return None


def verify_mfa_freshness(payload: dict, max_auth_age_seconds: int, now: int | None = None) -> int:
    """Return the gating auth_time, or raise RequestRejected if the login is stale.

    Fail-closed: a missing or unreadable auth_time is a rejection, not a pass.
    """
    now = int(time.time()) if now is None else now
    auth_time = _extract_auth_time(payload)
    if auth_time is None:
        raise RequestRejected("no readable auth_time; cannot confirm login freshness")
    age = now - auth_time
    if age < 0:
        raise RequestRejected("auth_time is in the future; rejecting")
    if age > max_auth_age_seconds:
        raise RequestRejected(
            f"login is stale: {age}s old, limit is {max_auth_age_seconds}s"
        )
    return auth_time


# --- Validation (ADR-003) ----------------------------------------------------

def validate_request(payload: dict, cfg: dict) -> dict:
    """Check domain, segregation of duties, duration cap, and application id.

    Returns a normalized request dict, or raises RequestRejected.
    """
    requested_by = (payload.get("requested_by") or "").strip().lower()
    approved_by = (payload.get("approved_by") or "").strip().lower()
    application_id = (payload.get("application_id") or "").strip()
    justification = (payload.get("justification") or "").strip()

    if not requested_by or not approved_by:
        raise RequestRejected("requested_by and approved_by are both required")

    domain = "@" + cfg["allowed_domain"]
    if not requested_by.endswith(domain) or not approved_by.endswith(domain):
        raise RequestRejected(f"both parties must be in {cfg['allowed_domain']}")

    if requested_by == approved_by:
        raise RequestRejected("segregation of duties: requester cannot approve their own request")

    if not APPLICATION_ID_RE.match(application_id):
        raise RequestRejected(f"unrecognized application_id: {application_id!r}")

    if not justification:
        raise RequestRejected("a written justification is required")

    requested_minutes = payload.get("duration_minutes", cfg["max_grant_minutes"])
    try:
        requested_minutes = int(requested_minutes)
    except (TypeError, ValueError):
        raise RequestRejected("duration_minutes must be an integer")
    if requested_minutes <= 0 or requested_minutes > cfg["max_grant_minutes"]:
        raise RequestRejected(
            f"duration_minutes must be 1..{cfg['max_grant_minutes']}"
        )

    return {
        "requested_by": requested_by,
        "approved_by": approved_by,
        "application_id": application_id,
        "justification": justification,
        "duration_seconds": requested_minutes * 60,
    }


# --- Seams (patched in tests) ------------------------------------------------

def _bq_client():  # pragma: no cover - thin wrapper
    from google.cloud import bigquery

    return bigquery.Client()


def _write_ledger_row(cfg: dict, row: dict) -> None:
    client = _bq_client()
    table = f"{cfg['project_id']}.{cfg['audit_dataset']}.{cfg['ledger_table']}"
    errors = client.insert_rows_json(table, [row])
    if errors:
        raise RuntimeError(f"ledger write failed: {errors}")


# --- Orchestration -----------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso_from_epoch(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def process(payload: dict, cfg: dict | None = None) -> dict:
    """Full request path. Returns a response dict and writes exactly one ledger row."""
    cfg = cfg or _config()
    request_id = str(uuid.uuid4())
    base = {
        "request_id": request_id,
        "event_time": _now_iso(),
        "requested_by": (payload.get("requested_by") or "").strip().lower() or None,
        "approved_by": (payload.get("approved_by") or "").strip().lower() or None,
        "application_id": (payload.get("application_id") or "").strip() or None,
    }

    try:
        auth_time = verify_mfa_freshness(payload, cfg["max_auth_age_seconds"])
        req = validate_request(payload, cfg)
    except RequestRejected as rejected:
        _write_ledger_row(cfg, {**base, "action_type": "DENY", "decision_reason": rejected.reason})
        return {"status": "denied", "request_id": request_id, "reason": rejected.reason}

    entitlement_name = (
        f"projects/{cfg['project_id']}/locations/{cfg['location']}/"
        f"entitlements/{cfg['entitlement_prefix']}{req['application_id'].lower()}"
    )
    resource_path = (
        f"projects/_/buckets/{cfg['credit_bucket']}/objects/{req['application_id']}/"
    )

    # A REQUEST row, not a GRANT row. This broker never observes a grant being created,
    # so it must not claim one exists (ADR-006). The underwriter requests the grant
    # themselves against `entitlement_name`; PAM's admin-activity audit logs, exported to
    # bankvault_platform_logs, are the record that a grant was actually issued.
    _write_ledger_row(cfg, {
        **base,
        "action_type": "REQUEST",
        "approved_by": req["approved_by"],
        "application_id": req["application_id"],
        "resource_path": resource_path,
        "justification": req["justification"],
        "duration_seconds": req["duration_seconds"],
        "mfa_auth_time": _iso_from_epoch(auth_time),
        "entitlement_name": entitlement_name,
    })

    return {
        "status": "cleared_to_request",
        "request_id": request_id,
        "entitlement_name": entitlement_name,
        "resource_path": resource_path,
        "requested_duration_seconds": req["duration_seconds"],
        "note": (
            "Pre-flight checks passed and the request is recorded. Request the grant "
            "yourself against entitlement_name; PAM grants privileges to the caller."
        ),
    }


@functions_framework.http
def handle_request(request):
    payload = request.get_json(silent=True) or {}
    result = process(payload)
    code = 200 if result["status"] == "cleared_to_request" else 403
    return (json.dumps(result), code, {"Content-Type": "application/json"})
