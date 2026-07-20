"""BankVault reconcile sweep (detect-only, ADR-005).

PAM owns expiry. This job does not revoke. It confirms every grant whose window has
passed is accounted for, and it flags a grant that PAM still reports active past its
window. It writes EXPIRE_FLAG rows and emits a structured alert log. It does not, and
must not, revoke a grant: that would be a second enforcement path that can disagree
with PAM.

Where grants come from (ADR-006): the broker no longer creates grants, so the ledger
has no GRANT rows. The underwriter requests the grant from PAM directly, and the
record that a grant was actually issued is PAM's admin-activity audit log, exported to
the bankvault_platform_logs dataset by the log sink (terraform/logging.tf). This job
reconstructs grant windows from those CreateGrant audit events and sweeps them, so the
sweep does not depend on a GRANT row that is never written. It also still reads any
ledger GRANT rows, which keeps it correct for the pre-ADR-006 shape too.

The BigQuery and PAM calls sit behind seams so the detection logic is unit-tested.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import functions_framework


def _config() -> dict:
    return {
        "project_id": os.environ.get("PROJECT_ID", "local-dev"),
        "location": os.environ.get("LOCATION", "global"),
        "audit_dataset": os.environ.get("AUDIT_DATASET", "bankvault_audit"),
        "ledger_table": os.environ.get("LEDGER_TABLE", "access_grants"),
        "platform_dataset": os.environ.get("PLATFORM_DATASET", "bankvault_platform_logs"),
        "credit_bucket": os.environ.get("CREDIT_BUCKET", "local-credit-reports"),
        "entitlement_prefix": os.environ.get("ENTITLEMENT_PREFIX", "bankvault-credit-report-"),
    }


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


# --- Detection logic (pure, unit-tested) -------------------------------------

def find_overruns(open_grants: list[dict], now: datetime | None = None) -> list[dict]:
    """From grants that have no close-out, return those past window_end.

    `open_grants` is expected to already exclude grants that were closed out; this
    function applies only the time check, so both halves are testable in isolation.
    """
    now = now or _now()
    overruns = []
    for row in open_grants:
        window_end = row.get("window_end")
        if window_end is None:
            continue
        if _parse_ts(window_end) < now:
            overruns.append(row)
    return overruns


def classify(row: dict, pam_active: bool) -> str:
    """Reason string for the flag. A grant PAM still reports active is the loud case."""
    if pam_active:
        return "OVERRUN: grant past window_end and PAM still reports it active"
    return "LEDGER_GAP: grant past window_end, PAM expired it, no close-out row recorded"


def _application_from_entitlement(entitlement_name: str | None, prefix: str) -> str | None:
    """Recover the application id an entitlement was minted for.

    Entitlements are named `<prefix><app-id-lowercase>` (terraform/pam.tf, ADR-003), so
    the id is the entitlement's last path segment with the prefix stripped, uppercased.
    Returns None when the entitlement does not carry the prefix.
    """
    if not entitlement_name:
        return None
    slug = entitlement_name.rsplit("/", 1)[-1]
    if not slug.startswith(prefix):
        return None
    return slug[len(prefix):].upper()


def _grant_window_end(event: dict) -> datetime | None:
    """create_time + requested duration, or None when either is missing."""
    create_time = event.get("create_time")
    duration = event.get("duration_seconds")
    if create_time is None or duration is None:
        return None
    return _parse_ts(create_time) + timedelta(seconds=int(duration))


def _reconstruct_grants(pam_events: list[dict], cfg: dict) -> list[dict]:
    """Turn raw PAM CreateGrant audit events into the grant shape the sweep uses.

    The grant name doubles as request_id: it is the stable identity the EXPIRE_FLAG
    close-out correlates on, because PAM never sees the broker's request_id. window_end
    is when PAM should have expired the grant, so a grant PAM still reports active past
    it is exactly the anomaly classify() calls OVERRUN.
    """
    prefix = cfg["entitlement_prefix"]
    grants = []
    for event in pam_events:
        grant_name = event.get("pam_grant_name")
        if not grant_name:
            continue
        application_id = _application_from_entitlement(event.get("entitlement_name"), prefix)
        grants.append({
            "request_id": grant_name,
            "application_id": application_id,
            "resource_path": (
                f"projects/_/buckets/{cfg['credit_bucket']}/objects/{application_id}/"
                if application_id
                else None
            ),
            "window_end": _grant_window_end(event),
            "pam_grant_name": grant_name,
        })
    return grants


def _exclude_flagged(grants: list[dict], flagged_request_ids: set) -> list[dict]:
    """Drop grants that already have an EXPIRE_FLAG close-out row."""
    return [g for g in grants if g.get("request_id") not in flagged_request_ids]


# --- Seams (patched in tests) ------------------------------------------------

def _bq_client():  # pragma: no cover - thin wrapper
    from google.cloud import bigquery

    return bigquery.Client()


def _query_open_grants(cfg: dict) -> list[dict]:  # pragma: no cover - real query
    """GRANT rows with no EXPIRE_FLAG for the same request_id.

    Post-ADR-006 the broker writes no GRANT rows, so this returns empty in the normal
    case. It stays so the sweep still covers any ledger GRANT rows that do exist.
    """
    client = _bq_client()
    table = f"{cfg['project_id']}.{cfg['audit_dataset']}.{cfg['ledger_table']}"
    sql = f"""
        SELECT g.request_id, g.application_id, g.resource_path, g.window_end, g.pam_grant_name
        FROM `{table}` g
        WHERE g.action_type = 'GRANT'
          AND NOT EXISTS (
            SELECT 1 FROM `{table}` f
            WHERE f.request_id = g.request_id AND f.action_type = 'EXPIRE_FLAG'
          )
    """
    return [dict(r) for r in client.query(sql).result()]


def _query_pam_grant_events(cfg: dict) -> list[dict]:  # pragma: no cover - real query
    """CreateGrant audit events from the platform-log export (terraform/logging.tf).

    This is the ADR-006 reconstruction source: PAM's admin-activity audit log is the
    independent record that a grant was issued, now that the broker writes no GRANT row.
    The sink routes it into the platform dataset's admin-activity table. Field paths
    follow the Cloud Audit Logs / PAM export schema; verify against the live export.
    """
    client = _bq_client()
    table = f"{cfg['project_id']}.{cfg['platform_dataset']}.cloudaudit_googleapis_com_activity"
    sql = f"""
        SELECT
          protoPayload.authenticationInfo.principalEmail AS requester,
          protoPayload.request.entitlement AS entitlement_name,
          protoPayload.response.name AS pam_grant_name,
          timestamp AS create_time,
          CAST(TRIM(protoPayload.response.requestedDuration, 's') AS INT64) AS duration_seconds
        FROM `{table}`
        WHERE protoPayload.serviceName = "privilegedaccessmanager.googleapis.com"
          AND protoPayload.methodName = "google.cloud.privilegedaccessmanager.v1.PrivilegedAccessManager.CreateGrant"
    """
    return [dict(r) for r in client.query(sql).result()]


def _query_flagged_request_ids(cfg: dict) -> set:  # pragma: no cover - real query
    """request_ids that already have an EXPIRE_FLAG close-out row."""
    client = _bq_client()
    table = f"{cfg['project_id']}.{cfg['audit_dataset']}.{cfg['ledger_table']}"
    sql = f"SELECT DISTINCT request_id FROM `{table}` WHERE action_type = 'EXPIRE_FLAG'"
    return {r["request_id"] for r in client.query(sql).result()}


def _check_pam_grant_active(grant_name: str | None) -> bool:  # pragma: no cover - real API
    """Whether PAM still reports the grant active. VERIFY API semantics (ADR-001)."""
    if not grant_name:
        return False
    from google.cloud import privilegedaccessmanager_v1

    client = privilegedaccessmanager_v1.PrivilegedAccessManagerClient()
    grant = client.get_grant(name=grant_name)
    state = getattr(grant.state, "name", str(grant.state))
    return state in {"ACTIVE", "APPROVED_AND_ASSIGNED", "APPROVED"}


def _write_flag(cfg: dict, row: dict, reason: str) -> None:  # pragma: no cover - real write
    client = _bq_client()
    table = f"{cfg['project_id']}.{cfg['audit_dataset']}.{cfg['ledger_table']}"
    flag = {
        "request_id": row["request_id"],
        "event_time": _now().isoformat(),
        "action_type": "EXPIRE_FLAG",
        "application_id": row.get("application_id"),
        "resource_path": row.get("resource_path"),
        "window_end": row.get("window_end").isoformat() if isinstance(row.get("window_end"), datetime) else row.get("window_end"),
        "decision_reason": reason,
        "pam_grant_name": row.get("pam_grant_name"),
    }
    errors = client.insert_rows_json(table, [flag])
    if errors:
        raise RuntimeError(f"flag write failed: {errors}")


def _alert(reason: str, row: dict) -> None:
    """Structured log line. Cloud Logging reads the JSON; severity routes it."""
    print(json.dumps({
        "severity": "WARNING",
        "message": "bankvault.reconcile.flag",
        "reason": reason,
        "request_id": row.get("request_id"),
        "application_id": row.get("application_id"),
        "pam_grant_name": row.get("pam_grant_name"),
    }))


# --- Orchestration -----------------------------------------------------------

def reconcile(cfg: dict | None = None) -> dict:
    cfg = cfg or _config()
    ledger_grants = _query_open_grants(cfg)
    pam_grants = _exclude_flagged(
        _reconstruct_grants(_query_pam_grant_events(cfg), cfg),
        _query_flagged_request_ids(cfg),
    )
    open_grants = ledger_grants + pam_grants
    overruns = find_overruns(open_grants)
    flagged = 0
    for row in overruns:
        pam_active = _check_pam_grant_active(row.get("pam_grant_name"))
        reason = classify(row, pam_active)
        _write_flag(cfg, row, reason)
        _alert(reason, row)
        flagged += 1
    return {"open_grants": len(open_grants), "flagged": flagged}


@functions_framework.cloud_event
def handle_event(cloud_event):
    result = reconcile()
    print(json.dumps({"severity": "INFO", "message": "bankvault.reconcile.done", **result}))
    return result
