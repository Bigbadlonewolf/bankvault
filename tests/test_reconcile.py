"""Tests for the detect-only reconcile sweep (ADR-005).

The job must flag overruns and never revoke. There is no revoke seam to patch,
because there is no revoke path; that absence is the design.
"""

from datetime import datetime, timedelta, timezone


def _dt(offset_seconds: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)


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


def test_reconcile_flags_overruns_only(reconcile_mod, monkeypatch, cfg):
    flags = []
    open_grants = [
        {"request_id": "old", "application_id": "APP-1001", "window_end": _dt(-600), "pam_grant_name": "g/old"},
        {"request_id": "live", "application_id": "APP-1002", "window_end": _dt(600), "pam_grant_name": "g/live"},
    ]
    monkeypatch.setattr(reconcile_mod, "_query_open_grants", lambda c: open_grants)
    monkeypatch.setattr(reconcile_mod, "_check_pam_grant_active", lambda name: name == "g/old")
    monkeypatch.setattr(reconcile_mod, "_write_flag", lambda c, r, reason: flags.append((r["request_id"], reason)))

    result = reconcile_mod.reconcile(cfg)

    assert result == {"open_grants": 2, "flagged": 1}
    assert flags[0][0] == "old"
    assert flags[0][1].startswith("OVERRUN")


def test_reconcile_has_no_revoke_path(reconcile_mod):
    # The design guarantee: detection only. If a revoke seam ever appears, this
    # test should be replaced by an ADR that argues for containment (ADR-005).
    assert not hasattr(reconcile_mod, "_revoke_grant")
    assert not hasattr(reconcile_mod, "revoke")
