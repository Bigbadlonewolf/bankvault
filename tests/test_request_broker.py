"""Tests for the request broker: MFA freshness, validation, and the full path.

Every GCP call is patched. A fresh, valid request must produce a REQUEST row naming the
entitlement the underwriter should request against; every rejection must produce a DENY
row. The broker has no grant-creation path at all (ADR-006).
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

def test_happy_path_clears_request_and_writes_request_row(broker, cfg, monkeypatch):
    rows = []
    monkeypatch.setattr(broker, "_write_ledger_row", lambda c, r: rows.append(r))

    payload = _good_payload()
    payload["auth_time"] = int(time.time()) - 30
    result = broker.process(payload, cfg)

    assert result["status"] == "cleared_to_request"
    assert len(rows) == 1 and rows[0]["action_type"] == "REQUEST"
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

    payload = _good_payload()
    payload["auth_time"] = int(time.time()) - 5000
    result = broker.process(payload, cfg)

    assert result["status"] == "denied"
    assert rows[0]["action_type"] == "DENY"
    assert "stale" in rows[0]["decision_reason"]


def test_self_approval_denies_with_deny_row(broker, cfg, monkeypatch):
    rows = []
    monkeypatch.setattr(broker, "_write_ledger_row", lambda c, r: rows.append(r))

    payload = _good_payload()
    payload["auth_time"] = int(time.time()) - 10
    payload["approved_by"] = payload["requested_by"]
    result = broker.process(payload, cfg)

    assert result["status"] == "denied"
    assert rows[0]["action_type"] == "DENY"
    assert "segregation" in rows[0]["decision_reason"]
