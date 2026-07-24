"""BankVault request broker.

One HTTP entry point. It is a pre-flight gate and an audit record. It is **not** a
chokepoint, and it does not create grants (ADR-006).

PAM attaches a grant's privileges to the calling principal, and there is no grantee
parameter on `CreateGrant`. A broker that called PAM would therefore elevate its own
service account, not the underwriter, which is the standing access this project exists
to remove. So the underwriter requests their own grant directly against the entitlement
this broker names back to them.

What it does:
  - verifies the caller's OIDC id_token (RS256 signature against the IdP JWKS, plus
    issuer, audience, and expiry) and binds the request to the authenticated identity,
    fail-closed -- the request body cannot assert who it is (ADR-002)
  - refuses unverified-identity, stale-login, and malformed requests before they reach
    PAM, with a reason
  - writes the verified `auth_time` that gated each request into the append-only ledger

Enforced recency is an Access Context Manager reauth binding at the platform's one-hour
minimum. The 15-minute check here is early rejection and evidence, not enforcement; an
underwriter who skips this endpoint reaches PAM anyway (ADR-006). Identity verification
is likewise pre-flight: it makes the ledger's identity and `auth_time` trustworthy, but
the platform (Workforce Identity Federation + ACM) remains the enforcement boundary.

PAM owns approval and expiry (ADR-001); nothing here revokes anything. The BigQuery call
sits behind a seam (`_bq_client`) so validation and freshness logic is unit-tested without
touching the network.
"""

from __future__ import annotations

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
        # OIDC identity verification (ADR-002/004). Unset -> verify_identity fails
        # closed and every request is denied; wire these to the Workforce Identity
        # Federation / IdP that fronts the broker before deploying.
        "oidc_issuer": os.environ.get("OIDC_ISSUER", ""),
        "oidc_audience": os.environ.get("OIDC_AUDIENCE", ""),
        "oidc_jwks_uri": os.environ.get("OIDC_JWKS_URI", ""),
        "oidc_identity_claim": os.environ.get("OIDC_IDENTITY_CLAIM", "email"),
        "oidc_leeway_seconds": int(os.environ.get("OIDC_LEEWAY_SECONDS", "60")),
    }


class RequestRejected(Exception):
    """Raised when a request fails a check. Carries the reason for the ledger."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# --- Identity & MFA freshness (ADR-002, ADR-004) -----------------------------

def _fetch_signing_key(jwks_uri: str, id_token: str):  # pragma: no cover - network seam
    """Resolve the RSA signing key for an id_token from the IdP JWKS endpoint.

    Isolated behind a seam so signature verification is unit-tested without a live JWKS
    endpoint: tests patch this (or _verify_id_token) instead of reaching the network.
    """
    from jwt import PyJWKClient

    return PyJWKClient(jwks_uri).get_signing_key_from_jwt(id_token).key


def _verify_id_token(id_token: str, cfg: dict, now: int) -> dict:
    """Verify an OIDC id_token and return its claims, or raise RequestRejected.

    Fail-closed on every axis: an unconfigured verifier, an unreachable IdP, a bad
    signature, a wrong issuer/audience, or an expired token all reject. Verification
    never falls back to trusting unverified claims -- that fallback is the bypass this
    function exists to remove.
    """
    issuer = cfg.get("oidc_issuer")
    audience = cfg.get("oidc_audience")
    jwks_uri = cfg.get("oidc_jwks_uri")
    if not (issuer and audience and jwks_uri):
        raise RequestRejected(
            "identity verification is not configured (OIDC issuer/audience/JWKS unset); "
            "refusing to trust an unverified token"
        )

    try:
        import jwt

        signing_key = _fetch_signing_key(jwks_uri, id_token)
        claims = jwt.decode(
            id_token,
            signing_key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer,
            leeway=cfg.get("oidc_leeway_seconds", 60),
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except RequestRejected:
        raise
    except ImportError as exc:  # pragma: no cover - deploy dependency, not a runtime path
        raise RequestRejected(f"identity verifier unavailable: {exc}")
    except Exception as exc:  # PyJWTError, JWKS fetch failure, IdP down -> fail closed
        raise RequestRejected(f"id_token verification failed: {exc}")

    if not isinstance(claims, dict):
        raise RequestRejected("verified token did not decode to a claims object")
    return claims


def _check_freshness(auth_time: int, max_auth_age_seconds: int, now: int) -> int:
    """Return auth_time if the login is fresh, else raise RequestRejected. Fail-closed."""
    age = now - auth_time
    if age < 0:
        raise RequestRejected("auth_time is in the future; rejecting")
    if age > max_auth_age_seconds:
        raise RequestRejected(
            f"login is stale: {age}s old, limit is {max_auth_age_seconds}s"
        )
    return auth_time


def verify_identity(payload: dict, cfg: dict, now: int | None = None) -> dict:
    """Authenticate the caller from their OIDC id_token and gate on login freshness.

    Returns {"identity": <verified email>, "auth_time": <int>}. The identity is taken
    from the *verified* token, never from the request body -- a request cannot assert
    who it is. Fail-closed: a missing token, an unverifiable token, a missing identity
    claim, or a missing/unreadable auth_time is a rejection, never a pass.
    """
    now = int(time.time()) if now is None else now

    id_token = payload.get("id_token")
    if not isinstance(id_token, str) or not id_token:
        raise RequestRejected("id_token is required; identity cannot be verified without one")

    claims = _verify_id_token(id_token, cfg, now)

    identity_claim = cfg.get("oidc_identity_claim", "email")
    identity = str(claims.get(identity_claim) or "").strip().lower()
    if not identity:
        raise RequestRejected(f"verified token has no {identity_claim} claim; cannot bind identity")

    auth_time = claims.get("auth_time")
    if not isinstance(auth_time, (int, float)):
        raise RequestRejected("no readable auth_time in verified token; cannot confirm login freshness")

    auth_time = _check_freshness(int(auth_time), cfg["max_auth_age_seconds"], now)
    return {"identity": identity, "auth_time": auth_time}


# --- Validation (ADR-003) ----------------------------------------------------

def validate_request(payload: dict, cfg: dict, identity: str) -> dict:
    """Check identity binding, domain, segregation of duties, duration cap, application id.

    `identity` is the caller authenticated by verify_identity and is authoritative. A
    requested_by in the body that disagrees with it is an impersonation attempt and is
    rejected (the DENY reason records it). Returns a normalized request dict, or raises
    RequestRejected.
    """
    requested_by = identity
    approved_by = (payload.get("approved_by") or "").strip().lower()
    application_id = (payload.get("application_id") or "").strip()
    justification = (payload.get("justification") or "").strip()

    claimed_by = (payload.get("requested_by") or "").strip().lower()
    if claimed_by and claimed_by != requested_by:
        raise RequestRejected(
            f"requested_by {claimed_by!r} does not match the authenticated identity {requested_by!r}"
        )

    if not approved_by:
        raise RequestRejected("approved_by is required")

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
        ident = verify_identity(payload, cfg)
        req = validate_request(payload, cfg, ident["identity"])
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
        "mfa_auth_time": _iso_from_epoch(ident["auth_time"]),
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
