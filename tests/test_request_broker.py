"""Tests for the request broker: identity verification, MFA freshness, validation, path.

The caller is authenticated from a verified OIDC id_token, not from the request body.
Signature verification sits behind the `_verify_id_token` / `_fetch_signing_key` seams,
so most tests inject verified claims without crypto or network; one test exercises real
RS256 verification end to end. A fresh, valid request produces a REQUEST row naming the
entitlement to request against; every rejection produces a DENY row. The broker has no
grant-creation path at all (ADR-006).
"""

import time

import pytest

GOOD_IDENTITY = "sam@lender.example.com"


def _patch_verify(broker, monkeypatch, *, email=GOOD_IDENTITY, auth_time=None, drop=None):
    """Patch the signature-verification seam to return controlled verified claims."""
    now = int(time.time())
    claims = {
        "email": email,
        "auth_time": now - 30 if auth_time is None else auth_time,
        "iss": "https://idp.test/",
        "aud": "bankvault-broker",
        "exp": now + 300,
        "iat": now - 30,
    }
    for key in drop or ():
        claims.pop(key, None)
    monkeypatch.setattr(broker, "_verify_id_token", lambda tok, cfg, now_: dict(claims))


def _good_payload():
    return {
        "id_token": "header.payload.signature",
        "requested_by": GOOD_IDENTITY,
        "approved_by": "lead@lender.example.com",
        "application_id": "APP-1001",
        "justification": "manual QC review of DTI",
        "duration_minutes": 30,
    }


# --- Identity verification (ADR-002) -----------------------------------------

def test_missing_id_token_is_rejected(broker, cfg):
    with pytest.raises(broker.RequestRejected, match="id_token is required"):
        broker.verify_identity({}, cfg)


def test_unconfigured_verifier_fails_closed(broker, cfg):
    unconfigured = {**cfg, "oidc_issuer": "", "oidc_audience": "", "oidc_jwks_uri": ""}
    with pytest.raises(broker.RequestRejected, match="not configured"):
        broker.verify_identity({"id_token": "h.p.s"}, unconfigured)


def test_verified_identity_returns_email_and_auth_time(broker, cfg, monkeypatch):
    now = int(time.time())
    _patch_verify(broker, monkeypatch, auth_time=now - 60)
    result = broker.verify_identity(_good_payload(), cfg, now=now)
    assert result == {"identity": GOOD_IDENTITY, "auth_time": now - 60}


def test_identity_is_lowercased_from_token(broker, cfg, monkeypatch):
    _patch_verify(broker, monkeypatch, email="Sam@Lender.Example.com")
    assert broker.verify_identity(_good_payload(), cfg)["identity"] == GOOD_IDENTITY


def test_missing_email_claim_is_rejected(broker, cfg, monkeypatch):
    _patch_verify(broker, monkeypatch, drop=("email",))
    with pytest.raises(broker.RequestRejected, match="no email claim"):
        broker.verify_identity(_good_payload(), cfg)


def test_missing_auth_time_in_verified_token_is_rejected(broker, cfg, monkeypatch):
    _patch_verify(broker, monkeypatch, drop=("auth_time",))
    with pytest.raises(broker.RequestRejected, match="cannot confirm login freshness"):
        broker.verify_identity(_good_payload(), cfg)


# --- MFA freshness (ADR-004) -------------------------------------------------

def test_check_freshness_pure_helper(broker):
    now = 1_000_000
    assert broker._check_freshness(now - 60, 300, now) == now - 60
    with pytest.raises(broker.RequestRejected, match="stale"):
        broker._check_freshness(now - 3600, 300, now)
    with pytest.raises(broker.RequestRejected, match="future"):
        broker._check_freshness(now + 120, 300, now)


def test_stale_login_rejected(broker, cfg, monkeypatch):
    now = int(time.time())
    _patch_verify(broker, monkeypatch, auth_time=now - 3600)
    with pytest.raises(broker.RequestRejected, match="stale"):
        broker.verify_identity(_good_payload(), cfg, now=now)


def test_future_auth_time_rejected(broker, cfg, monkeypatch):
    now = int(time.time())
    _patch_verify(broker, monkeypatch, auth_time=now + 120)
    with pytest.raises(broker.RequestRejected, match="future"):
        broker.verify_identity(_good_payload(), cfg, now=now)


# --- Real RS256 signature verification ---------------------------------------

def test_real_rs256_signature_is_verified_and_tampering_rejected(broker, cfg, monkeypatch):
    jwt = pytest.importorskip("jwt")
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa

    now = int(time.time())
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(
        {
            "email": GOOD_IDENTITY,
            "auth_time": now - 10,
            "iss": "https://idp.test/",
            "aud": "bankvault-broker",
            "exp": now + 300,
            "iat": now - 10,
        },
        signing_key,
        algorithm="RS256",
    )

    # Correct public key -> verifies.
    monkeypatch.setattr(broker, "_fetch_signing_key", lambda uri, tok: signing_key.public_key())
    claims = broker._verify_id_token(token, cfg, now)
    assert claims["email"] == GOOD_IDENTITY

    # Wrong signing key -> fail closed.
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(broker, "_fetch_signing_key", lambda uri, tok: wrong_key.public_key())
    with pytest.raises(broker.RequestRejected, match="verification failed"):
        broker._verify_id_token(token, cfg, now)


# --- Validation & identity binding (ADR-003) ---------------------------------

def test_valid_request_binds_authenticated_identity(broker, cfg):
    payload = _good_payload()
    payload.pop("requested_by")  # body need not assert it
    req = broker.validate_request(payload, cfg, GOOD_IDENTITY)
    assert req["requested_by"] == GOOD_IDENTITY
    assert req["duration_seconds"] == 1800
    assert req["application_id"] == "APP-1001"


def test_requested_by_mismatch_is_rejected(broker, cfg):
    payload = _good_payload()
    payload["requested_by"] = "eve@lender.example.com"
    with pytest.raises(broker.RequestRejected, match="does not match the authenticated identity"):
        broker.validate_request(payload, cfg, GOOD_IDENTITY)


def test_segregation_of_duties_blocks_self_approval(broker, cfg):
    payload = _good_payload()
    payload["approved_by"] = GOOD_IDENTITY
    with pytest.raises(broker.RequestRejected, match="segregation of duties"):
        broker.validate_request(payload, cfg, GOOD_IDENTITY)


def test_domain_enforced(broker, cfg):
    payload = _good_payload()
    payload["approved_by"] = "lead@attacker.example.org"
    with pytest.raises(broker.RequestRejected, match="must be in"):
        broker.validate_request(payload, cfg, GOOD_IDENTITY)


def test_duration_cap_enforced(broker, cfg):
    payload = _good_payload()
    payload["duration_minutes"] = 999
    with pytest.raises(broker.RequestRejected, match="1..30"):
        broker.validate_request(payload, cfg, GOOD_IDENTITY)


def test_unknown_application_id_rejected(broker, cfg):
    payload = _good_payload()
    payload["application_id"] = "'; DROP TABLE access_grants; --"
    with pytest.raises(broker.RequestRejected, match="unrecognized"):
        broker.validate_request(payload, cfg, GOOD_IDENTITY)


def test_missing_justification_rejected(broker, cfg):
    payload = _good_payload()
    payload["justification"] = ""
    with pytest.raises(broker.RequestRejected, match="justification"):
        broker.validate_request(payload, cfg, GOOD_IDENTITY)


def test_missing_approved_by_rejected(broker, cfg):
    payload = _good_payload()
    payload.pop("approved_by")
    with pytest.raises(broker.RequestRejected, match="approved_by is required"):
        broker.validate_request(payload, cfg, GOOD_IDENTITY)


# --- Full path ---------------------------------------------------------------

def test_happy_path_clears_request_and_writes_request_row(broker, cfg, monkeypatch):
    rows = []
    monkeypatch.setattr(broker, "_write_ledger_row", lambda c, r: rows.append(r))
    _patch_verify(broker, monkeypatch)

    result = broker.process(_good_payload(), cfg)

    assert result["status"] == "cleared_to_request"
    assert len(rows) == 1 and rows[0]["action_type"] == "REQUEST"
    assert rows[0]["requested_by"] == GOOD_IDENTITY
    assert rows[0]["mfa_auth_time"] is not None
    assert rows[0]["resource_path"].endswith("/objects/APP-1001/")
    assert rows[0]["entitlement_name"].endswith("bankvault-credit-report-app-1001")
    # The broker never observes a grant, so it must not claim one exists (ADR-006).
    assert "pam_grant_name" not in rows[0]
    assert rows[0]["action_type"] != "GRANT"


def test_broker_has_no_grant_creation_path(broker):
    """ADR-006 invariant: PAM elevates the caller, so a broker-side grant call would
    elevate the broker's service account. Removing it is the decision, not an omission.

    Mirrors tests/test_reconcile.py::test_reconcile_has_no_revoke_path.
    """
    import inspect

    assert not hasattr(broker, "_create_pam_grant")
    source = inspect.getsource(broker)
    assert "create_grant" not in source
    assert "privilegedaccessmanager" not in source


def test_stale_login_denies(broker, cfg, monkeypatch):
    rows = []
    monkeypatch.setattr(broker, "_write_ledger_row", lambda c, r: rows.append(r))
    _patch_verify(broker, monkeypatch, auth_time=int(time.time()) - 5000)

    result = broker.process(_good_payload(), cfg)

    assert result["status"] == "denied"
    assert rows[0]["action_type"] == "DENY"
    assert "stale" in rows[0]["decision_reason"]


def test_impersonation_denies_with_deny_row(broker, cfg, monkeypatch):
    rows = []
    monkeypatch.setattr(broker, "_write_ledger_row", lambda c, r: rows.append(r))
    _patch_verify(broker, monkeypatch)  # verified identity is sam@...

    payload = _good_payload()
    payload["requested_by"] = "eve@lender.example.com"  # lies about who is asking
    result = broker.process(payload, cfg)

    assert result["status"] == "denied"
    assert rows[0]["action_type"] == "DENY"
    assert "does not match the authenticated identity" in rows[0]["decision_reason"]


def test_self_approval_denies_with_deny_row(broker, cfg, monkeypatch):
    rows = []
    monkeypatch.setattr(broker, "_write_ledger_row", lambda c, r: rows.append(r))
    _patch_verify(broker, monkeypatch)

    payload = _good_payload()
    payload["approved_by"] = GOOD_IDENTITY
    result = broker.process(payload, cfg)

    assert result["status"] == "denied"
    assert rows[0]["action_type"] == "DENY"
    assert "segregation" in rows[0]["decision_reason"]


def test_unverified_identity_denies_when_verifier_unconfigured(broker, cfg, monkeypatch):
    rows = []
    monkeypatch.setattr(broker, "_write_ledger_row", lambda c, r: rows.append(r))
    unconfigured = {**cfg, "oidc_issuer": "", "oidc_audience": "", "oidc_jwks_uri": ""}

    result = broker.process(_good_payload(), unconfigured)

    assert result["status"] == "denied"
    assert rows[0]["action_type"] == "DENY"
    assert "not configured" in rows[0]["decision_reason"]
