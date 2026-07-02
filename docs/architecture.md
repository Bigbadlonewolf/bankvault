# Architecture

```
Loan officer / caller
        │  POST { requested_by, approved_by, justification, duration_minutes, loan_application_id }
        ▼
  grant_access (Cloud Function v2, HTTP, Python 3.12)
        ├── validate_request()        — domain check, segregation of duties, duration cap
        ├── apply_iam_binding()       — conditional google_storage_bucket_iam_member via IAM API
        │                               CEL: request.time < timestamp(...) [&& resource.name.startsWith(...)]
        ├── create_session_secret()   — short-lived token → Secret Manager (bankvault-session-<request_id>)
        └── write_audit_row()         — INSERT into BigQuery access_grants (action_type=GRANT|DENY)
        │
        ▼
  loan-origination-pii bucket (GCS, uniform access, versioned, public access blocked)
        │  access denied automatically once request.time crosses window_end — no code involved
        │
        ▼
  Cloud Scheduler (*/5 * * * *) ──▶ Pub/Sub: bankvault-revocation-trigger
        │
        ▼
  revoke_access (Cloud Function v2, Pub/Sub-triggered, Python 3.12)
        ├── find_expired_unrevoked_grants() — SQL: GRANT rows past window_end with no REVOKE row
        ├── remove_iam_binding()             — strips the now-inert conditional binding
        ├── delete_session_secret()          — destroys the Secret Manager secret
        └── write_revoke_row()                — INSERT into BigQuery access_grants (action_type=REVOKE)

  Cloud Logging (both functions' execution logs)
        │
        ▼  google_logging_project_sink
  BigQuery: bankvault_platform_logs   — independent record, survives an application-code bug
```

## Why Enforcement Doesn't Depend on the Scheduler

The CEL expression `request.time < timestamp(<window_end>)` is evaluated by GCP's IAM policy engine at the moment a request against the bucket is made — not by any code in this repo. A loan officer's access is denied the instant the clock crosses `window_end`, whether or not `revoke_access` has run yet.

`revoke_access` exists for two things the CEL condition can't do on its own: removing the now-inert binding from the bucket's IAM policy (so the policy doesn't accumulate stale entries indefinitely), and destroying the session secret plus writing the `REVOKE` row that closes out the audit ledger entry for that request. A delay in the sweep is a hygiene and audit-completeness issue, not an access-control gap.

## Why the Audit Ledger Is Append-Only

`access_grants` never receives an `UPDATE`. Every lifecycle event — a grant, a denial, a revocation — is a new row keyed by `request_id`. Reconstructing "is this grant still active" is a query (`GRANT` row with no matching `REVOKE` row), not a status field someone could quietly edit after the fact. That property is what makes the ledger usable as SOX 404 ITGC evidence: the history can't be rewritten, only appended to.

Two independent layers back this up:

1. **Application-level ledger** (`access_grants`) — written directly by the function code, with the full business context (who, what, when, why, approved by whom).
2. **Platform-level log export** (`bankvault_platform_logs`) — a raw Cloud Logging export of both functions' execution logs, routed by a `google_logging_project_sink`. If the application code has a bug and skips a ledger write, the platform-level invocation record still exists, independently produced by GCP itself.

See [Compliance Coverage](controls-mapping.md) for how each piece maps to a specific PCI DSS, FFIEC, or SOX 404 control.
