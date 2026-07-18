"""Tests for the request broker: MFA freshness, validation, and the full path.

Every GCP call is patched. A fresh, valid request must produce a GRANT row; every
rejection must produce a DENY row and never call PAM.
"""

import time

import pytest


# --- MFA freshness (ADR-004) -------------------------------------------------

def test_fresh_login_returns_auth_time(broker):
    now = 1_000_000
    auth_time = broker.verify_mfa_freshness({"auth_time": now - 60}, 300, now=now)
    assert auth_time == now - 60


def test_stale_login_rejected(broker):
    now = 1_000_000
    with pytest.raises(broker.RequestRejected, match="stale"):
        broker.verify_mfa_freshness({"auth_time": now - 3600}, 300, now=now)


def test_missing_auth_time_is_rejected_not_allowed(broker):
    # Fail-closed: no auth_time means reject, not pass.
    with pytest.raises(broker.RequestRejected, match="cannot confirm"):
        broker.verify_mfa_freshness({}, 300)


def test_future_auth_time_rejected(broker):
    now = 1_000_000
    with pytest.raises(broker.RequestRejected, match="future"):
        broker.verify_mfa_freshness({"auth_time": now + 120}, 300, now=now)


def test_auth_time_read_from_jwt(broker):
    import base64
    import json

    now = int(time.time())
    claims = base64.urlsafe_b64encode(json.dumps({"auth_time": now - 30}).encode()).decode().rstrip("=")
    token = f"header.{claims}.sig"
    auth_time = broker.verify_mfa_freshness({"id_token": token}, 300, now=now)
    assert auth_time == now - 30


# --- Validation (ADR-003) ----------------------------------------------------

def _good_payload():
    return {
        "requested_by": "sam@lender.example.com",
        "approved_by": "lead@lender.example.com",
        "application_id": "APP-1001",
        "justification": "manual QC review of DTI",
        "duration_minutes": 30,
    }


def test_valid_request_normalizes(broker, cfg):
    req = broker.validate_request(_good_payload(), cfg)
    assert req["duration_seconds"] == 1800
    assert req["application_id"] == "APP-1001"


def test_segregation_of_duties_blocks_self_approval(broker, cfg):
    payload = _good_payload()
    payload["approved_by"] = payload["requested_by"]
    with pytest.raises(broker.RequestRejected, match="segregation of duties"):
        broker.validate_request(payload, cfg)


def test_domain_enforced(broker, cfg):
    payload = _good_payload()
    payload["approved_by"] = "lead@attacker.example.org"
    with pytest.raises(broker.RequestRejected, match="must be in"):
        broker.validate_request(payload, cfg)


def test_duration_cap_enforced(broker, cfg):
    payload = _good_payload()
    payload["duration_minutes"] = 999
    with pytest.raises(broker.RequestRejected, match="1..30"):
        broker.validate_request(payload, cfg)


def test_unknown_application_id_rejected(broker, cfg):
    payload = _good_payload()
    payload["application_id"] = "'; DROP TABLE access_grants; --"
    with pytest.raises(broker.RequestRejected, match="unrecognized"):
        broker.validate_request(payload, cfg)


def test_missing_justification_rejected(broker, cfg):
    payload = _good_payload()
    payload["justification"] = ""
    with pytest.raises(broker.RequestRejected, match="justification"):
        broker.validate_request(payload, cfg)


# --- Full path ---------------------------------------------------------------

def test_happy_path_grants_and_writes_grant_row(broker, cfg, monkeypatch):
    rows = []
    pam_calls = []

    def fake_grant(entitlement_name, justification, duration_seconds):
        pam_calls.append((entitlement_name, duration_seconds))
        return f"{entitlement_name}/grants/g-123"

    monkeypatch.setattr(broker, "_create_pam_grant", fake_grant)
    monkeypatch.setattr(broker, "_write_ledger_row", lambda c, r: rows.append(r))

    payload = _good_payload()
    payload["auth_time"] = int(time.time()) - 30
    result = broker.process(payload, cfg)

    assert result["status"] == "granted"
    assert len(rows) == 1 and rows[0]["action_type"] == "GRANT"
    assert rows[0]["mfa_auth_time"] is not None
    assert rows[0]["resource_path"].endswith("/objects/APP-1001/")
    assert rows[0]["pam_grant_name"].endswith("g-123")
    assert len(pam_calls) == 1
    assert pam_calls[0][0].endswith("bankvault-credit-report-app-1001")


def test_stale_login_denies_without_calling_pam(broker, cfg, monkeypatch):
    rows = []

    def must_not_run(*a, **k):
        raise AssertionError("PAM must not be called on a denied request")

    monkeypatch.setattr(broker, "_create_pam_grant", must_not_run)
    monkeypatch.setattr(broker, "_write_ledger_row", lambda c, r: rows.append(r))

    payload = _good_payload()
    payload["auth_time"] = int(time.time()) - 5000
    result = broker.process(payload, cfg)

    assert result["status"] == "denied"
    assert rows[0]["action_type"] == "DENY"
    assert "stale" in rows[0]["decision_reason"]


def test_self_approval_denies_with_deny_row(broker, cfg, monkeypatch):
    rows = []
    monkeypatch.setattr(broker, "_create_pam_grant", lambda *a, **k: pytest.fail("no grant"))
    monkeypatch.setattr(broker, "_write_ledger_row", lambda c, r: rows.append(r))

    payload = _good_payload()
    payload["auth_time"] = int(time.time()) - 10
    payload["approved_by"] = payload["requested_by"]
    result = broker.process(payload, cfg)

    assert result["status"] == "denied"
    assert rows[0]["action_type"] == "DENY"
    assert "segregation" in rows[0]["decision_reason"]
