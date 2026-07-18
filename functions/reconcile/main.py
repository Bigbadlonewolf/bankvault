"""BankVault reconcile sweep (detect-only, ADR-005).

PAM owns expiry. This job does not revoke. It confirms the append-only ledger has a
close-out for every grant whose window has passed, and it flags a grant that PAM still
reports active past its window. It writes EXPIRE_FLAG rows and emits a structured alert
log. It does not, and must not, revoke a grant: that would be a second enforcement path
that can disagree with PAM.

The BigQuery and PAM calls sit behind seams so the detection logic is unit-tested.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import functions_framework


def _config() -> dict:
    return {
        "project_id": os.environ.get("PROJECT_ID", "local-dev"),
        "location": os.environ.get("LOCATION", "global"),
        "audit_dataset": os.environ.get("AUDIT_DATASET", "bankvault_audit"),
        "ledger_table": os.environ.get("LEDGER_TABLE", "access_grants"),
    }


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


# --- Detection logic (pure, unit-tested) -------------------------------------

def find_overruns(open_grants: list[dict], now: datetime | None = None) -> list[dict]:
    """From GRANT rows that have no matching EXPIRE_FLAG, return those past window_end.

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


# --- Seams (patched in tests) ------------------------------------------------

def _bq_client():  # pragma: no cover - thin wrapper
    from google.cloud import bigquery

    return bigquery.Client()


def _query_open_grants(cfg: dict) -> list[dict]:  # pragma: no cover - real query
    """GRANT rows with no EXPIRE_FLAG for the same request_id."""
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
    open_grants = _query_open_grants(cfg)
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
