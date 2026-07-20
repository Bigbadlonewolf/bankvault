"""Tests for the detect-only reconcile sweep (ADR-005).

The job must flag overruns and never revoke. There is no revoke seam to patch,
because there is no revoke path; that absence is the design.

Post-ADR-006 the sweep reconstructs grants from PAM CreateGrant audit events (the
broker writes no GRANT rows), so most of these tests exercise that reconstruction.
"""

from datetime import datetime, timedelta, timezone


def _dt(offset_seconds: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)


def _pam_event(app_id: str, create_offset: int, duration_seconds: int = 1800) -> dict:
    entitlement = f"projects/p/locations/global/entitlements/bankvault-credit-report-{app_id.lower()}"
    return {
        "requester": "sam@lender.example.com",
        "entitlement_name": entitlement,
        "pam_grant_name": f"{entitlement}/grants/{app_id.lower()}-1",
        "create_time": _dt(create_offset),
        "duration_seconds": duration_seconds,
    }


def test_find_overruns_picks_past_window(reconcile_mod):
    now = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
    rows = [
        {"request_id": "a", "window_end": now - timedelta(minutes=5)},   # expired
        {"request_id": "b", "window_end": now + timedelta(minutes=5)},   # still open
        {"request_id": "c", "window_end": now - timedelta(seconds=1)},   # just expired
    ]
    overruns = reconcile_mod.find_overruns(rows, now=now)
    assert {r["request_id"] for r in overruns} == {"a", "c"}


def test_find_overruns_ignores_missing_window(reconcile_mod):
    now = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
    rows = [{"request_id": "x", "window_end": None}]
    assert reconcile_mod.find_overruns(rows, now=now) == []


def test_find_overruns_parses_iso_strings(reconcile_mod):
    now = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
    rows = [{"request_id": "s", "window_end": (now - timedelta(minutes=1)).isoformat()}]
    assert len(reconcile_mod.find_overruns(rows, now=now)) == 1


def test_classify_active_grant_is_overrun(reconcile_mod):
    reason = reconcile_mod.classify({"request_id": "a"}, pam_active=True)
    assert reason.startswith("OVERRUN")


def test_classify_expired_grant_is_ledger_gap(reconcile_mod):
    reason = reconcile_mod.classify({"request_id": "a"}, pam_active=False)
    assert reason.startswith("LEDGER_GAP")


# --- Reconstruction from PAM audit events (ADR-006) ---------------------------

def test_application_from_entitlement(reconcile_mod):
    prefix = "bankvault-credit-report-"
    base = "projects/p/locations/global/entitlements/"
    assert reconcile_mod._application_from_entitlement(base + "bankvault-credit-report-app-1001", prefix) == "APP-1001"
    assert reconcile_mod._application_from_entitlement(base + "unrelated-thing", prefix) is None
    assert reconcile_mod._application_from_entitlement(None, prefix) is None


def test_reconstruct_grants_computes_window_and_scope(reconcile_mod, cfg):
    event = _pam_event("APP-1001", create_offset=-3600, duration_seconds=1800)
    event["create_time"] = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
    grants = reconcile_mod._reconstruct_grants([event], cfg)
    assert len(grants) == 1
    g = grants[0]
    assert g["request_id"] == event["pam_grant_name"]
    assert g["application_id"] == "APP-1001"
    assert g["resource_path"] == "projects/_/buckets/test-credit-reports/objects/APP-1001/"
    assert g["window_end"] == datetime(2026, 7, 17, 12, 30, tzinfo=timezone.utc)
    assert g["pam_grant_name"] == event["pam_grant_name"]


def test_reconstruct_grants_skips_events_without_grant_name(reconcile_mod, cfg):
    events = [{"pam_grant_name": None, "entitlement_name": "x"}, {"entitlement_name": "y"}]
    assert reconcile_mod._reconstruct_grants(events, cfg) == []


def test_reconstruct_grants_missing_window_inputs_gives_no_window(reconcile_mod, cfg):
    event = {"pam_grant_name": "g/1", "entitlement_name": "bankvault-credit-report-app-1001"}
    grants = reconcile_mod._reconstruct_grants([event], cfg)
    assert grants[0]["window_end"] is None


def test_exclude_flagged(reconcile_mod):
    grants = [{"request_id": "a"}, {"request_id": "b"}]
    assert reconcile_mod._exclude_flagged(grants, {"a"}) == [{"request_id": "b"}]


# --- Full sweep ---------------------------------------------------------------

def test_reconcile_flags_overruns_only(reconcile_mod, monkeypatch, cfg):
    flags = []
    open_grants = [
        {"request_id": "old", "application_id": "APP-1001", "window_end": _dt(-600), "pam_grant_name": "g/old"},
        {"request_id": "live", "application_id": "APP-1002", "window_end": _dt(600), "pam_grant_name": "g/live"},
    ]
    monkeypatch.setattr(reconcile_mod, "_query_open_grants", lambda c: open_grants)
    monkeypatch.setattr(reconcile_mod, "_query_pam_grant_events", lambda c: [])
    monkeypatch.setattr(reconcile_mod, "_query_flagged_request_ids", lambda c: set())
    monkeypatch.setattr(reconcile_mod, "_check_pam_grant_active", lambda name: name == "g/old")
    monkeypatch.setattr(reconcile_mod, "_write_flag", lambda c, r, reason: flags.append((r["request_id"], reason)))

    result = reconcile_mod.reconcile(cfg)

    assert result == {"open_grants": 2, "flagged": 1}
    assert flags[0][0] == "old"
    assert flags[0][1].startswith("OVERRUN")


def test_reconcile_flags_reconstructed_pam_grant(reconcile_mod, monkeypatch, cfg):
    """(a) A grant reconstructed from a PAM CreateGrant audit event is swept and
    flagged once its window has passed and PAM still reports it active."""
    flags = []
    event = _pam_event("APP-1001", create_offset=-3600, duration_seconds=1800)
    monkeypatch.setattr(reconcile_mod, "_query_open_grants", lambda c: [])
    monkeypatch.setattr(reconcile_mod, "_query_pam_grant_events", lambda c: [event])
    monkeypatch.setattr(reconcile_mod, "_query_flagged_request_ids", lambda c: set())
    monkeypatch.setattr(reconcile_mod, "_check_pam_grant_active", lambda name: True)
    monkeypatch.setattr(reconcile_mod, "_write_flag", lambda c, r, reason: flags.append((r["request_id"], reason)))

    result = reconcile_mod.reconcile(cfg)

    assert result == {"open_grants": 1, "flagged": 1}
    assert flags[0][0] == event["pam_grant_name"]
    assert flags[0][1].startswith("OVERRUN")


def test_reconcile_requires_no_broker_grant_rows(reconcile_mod, monkeypatch, cfg):
    """(b) The sweep must not depend on broker-written GRANT rows. With an empty
    ledger, a grant reconstructed purely from the PAM audit log is still flagged."""
    flags = []
    event = _pam_event("APP-1002", create_offset=-7200, duration_seconds=1800)
    monkeypatch.setattr(reconcile_mod, "_query_open_grants", lambda c: [])  # no broker GRANT rows
    monkeypatch.setattr(reconcile_mod, "_query_pam_grant_events", lambda c: [event])
    monkeypatch.setattr(reconcile_mod, "_query_flagged_request_ids", lambda c: set())
    monkeypatch.setattr(reconcile_mod, "_check_pam_grant_active", lambda name: False)
    monkeypatch.setattr(reconcile_mod, "_write_flag", lambda c, r, reason: flags.append((r["request_id"], reason)))

    result = reconcile_mod.reconcile(cfg)

    assert result["flagged"] == 1
    assert flags[0][0] == event["pam_grant_name"]
    assert flags[0][1].startswith("LEDGER_GAP")


def test_reconcile_does_not_reflag_a_closed_out_grant(reconcile_mod, monkeypatch, cfg):
    """A reconstructed grant that already has an EXPIRE_FLAG is not flagged again,
    so the 15-minute cron does not emit duplicate flags."""
    flags = []
    event = _pam_event("APP-1001", create_offset=-3600, duration_seconds=1800)
    monkeypatch.setattr(reconcile_mod, "_query_open_grants", lambda c: [])
    monkeypatch.setattr(reconcile_mod, "_query_pam_grant_events", lambda c: [event])
    monkeypatch.setattr(reconcile_mod, "_query_flagged_request_ids", lambda c: {event["pam_grant_name"]})
    monkeypatch.setattr(reconcile_mod, "_write_flag", lambda c, r, reason: flags.append(r))

    result = reconcile_mod.reconcile(cfg)

    assert result == {"open_grants": 0, "flagged": 0}
    assert flags == []


def test_reconcile_has_no_revoke_path(reconcile_mod):
    # The design guarantee: detection only. If a revoke seam ever appears, this
    # test should be replaced by an ADR that argues for containment (ADR-005).
    assert not hasattr(reconcile_mod, "_revoke_grant")
    assert not hasattr(reconcile_mod, "revoke")
