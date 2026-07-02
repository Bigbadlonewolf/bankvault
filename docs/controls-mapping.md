# Controls Mapping

This is the document an examiner, auditor, or hiring manager should read first. The Terraform and Python in this repo are the enforcement mechanism; this page is the evidence trail that ties each control citation to a specific resource.

## PCI DSS v4.0 — Requirement 7 (Restrict Access by Business Need to Know)

| Control | What BankVault does | Where |
|---|---|---|
| **7.2.1** — Access control model defined, granting access based on job classification and function | `grant_access` requires `requested_by`, `approved_by`, and `justification` on every request; the domain check (`ALLOWED_REQUESTER_DOMAIN`) and duration cap (`MAX_GRANT_DURATION_MINUTES`) encode the access model in policy, not convention | `functions/grant_access/main.py::validate_request`, `terraform/variables.tf` |
| **7.2.2** — Access assigned based on least privilege necessary | Grants are scoped to `roles/storage.objectViewer` (read-only) and, when a `loan_application_id` is supplied, further scoped to that application's object prefix via a `resource.name.startsWith(...)` CEL clause — not bucket-wide by default | `functions/grant_access/main.py::build_condition_expression` |
| **7.2.4** — Access reviewed periodically to confirm it's still needed | The BigQuery audit ledger (`access_grants`) is queryable SQL — `SELECT * FROM access_grants WHERE action_type = 'GRANT' AND revoked_at IS NULL` gives a live "who currently has access" view for a periodic review, without needing a separate export | `terraform/bigquery.tf` |
| **7.2.5** — Application and system accounts have access limited to least privilege | `grant_sa` and `revoke_sa` each hold `roles/storage.admin` scoped to a single bucket (not project-wide), and `roles/secretmanager.admin` restricted by an IAM condition to the `bankvault-session-` secret prefix — neither SA can touch any other bucket or secret in the project | `terraform/iam.tf` |
| **7.3.1 / 7.3.2** — Access control system in place, enforcing least privilege and covering all system components | GCP IAM Conditions are the enforcement point: `request.time < timestamp(...)` denies access at evaluation time regardless of whether the binding has been cleaned up yet | `functions/grant_access/main.py::apply_iam_binding`, `terraform/iam.tf` |

## FFIEC IT Examination Handbook — Information Security Booklet, Access Control

| Section theme | What BankVault does | Where |
|---|---|---|
| **Access Rights Administration** — access provisioned and deprovisioned through a controlled, auditable process tied to an authoritative identity source | ADR-002 documents why Workforce Identity Federation, not a parallel Cloud Identity directory, is the identity plane feeding grant decisions — deprovisioning a loan officer in the bank's own IdP invalidates their ability to obtain a grant, with no second directory to keep in sync | `docs/adr/002-workforce-identity-federation-vs-iap.md` |
| **Least Privilege / Need-to-Know** — users granted the minimum access required for their role, for the minimum time required | Every grant carries a hard expiry (`window_end`), a configurable ceiling (`max_grant_duration_minutes`, default 240 minutes), and defaults to a 60-minute window if the caller doesn't specify one | `functions/grant_access/main.py`, `terraform/variables.tf` |
| **Segregation of Duties** — the person requesting access should not be the person who approves it | `validate_request` rejects any request where `approved_by == requested_by`, returning a DENY with an explicit `denial_reason` | `functions/grant_access/main.py::validate_request` |
| **Authentication and Credential Management** — avoid long-lived, broadly-scoped credentials for privileged sessions | Session tokens are minted per-request (`secrets.token_urlsafe(32)`), stored only in Secret Manager, never logged or returned in a response body beyond the secret's resource name, and destroyed by the revocation sweep | `functions/grant_access/main.py::create_session_secret`, `functions/revoke_access/main.py::delete_session_secret` |
| **Monitoring and Logging of Access** — privileged access activity logged in a form suitable for review | Two independent logging layers: the application-level BigQuery ledger (`access_grants`) and a raw Cloud Logging export of both functions' execution logs via `google_logging_project_sink`, so a bug in the application code doesn't leave zero record of the invocation | `terraform/bigquery.tf` |

## SOX 404 — IT General Controls (Logical Access & Change Management)

| ITGC domain | What BankVault does | Where |
|---|---|---|
| **Logical access controls exist and operate effectively** | The `access_grants` table is the evidence artifact: every GRANT, DENY, and REVOKE is a row, with `requested_by`, `approved_by`, `window_start`/`window_end`, and `iam_condition_expression` captured verbatim | `terraform/bigquery.tf::google_bigquery_table.access_grants` |
| **Access changes are authorized before they take effect** | `apply_iam_binding` only runs after `validate_request` passes — including the segregation-of-duties check — so no IAM change reaches the bucket policy without a distinct approver on record | `functions/grant_access/main.py::process_grant_request` |
| **Evidence of access changes is retained and tamper-resistant** | The ledger is append-only by design: `write_audit_row` and `write_revoke_row` only ever `INSERT`, never `UPDATE` — a request's full history (GRANT → REVOKE) is reconstructed by querying, not by mutating a status field that could be edited after the fact | `functions/grant_access/main.py::write_audit_row`, `functions/revoke_access/main.py::write_revoke_row` |
| **Access is removed when no longer required (termination/completion)** | The scheduled sweep (`revoke_access`, triggered every 5 minutes by default) finds every GRANT row past its `window_end` with no matching REVOKE row and removes the IAM binding — independent of whether anyone remembers to do it manually | `terraform/scheduler.tf`, `functions/revoke_access/main.py::find_expired_unrevoked_grants` |
| **Change management — infrastructure changes are version-controlled and reviewable** | All IAM bindings, the audit schema, and the function deployment pipeline are Terraform — reviewable as a diff before `apply`, with `terraform plan` output as the change record | `terraform/*.tf` |

---

## What This Repo Doesn't Prove

The CEL condition denies access at evaluation time the instant a window closes — that part doesn't depend on the revocation sweep running. What *does* depend on the sweep is IAM policy hygiene (removing the now-inert binding) and closing out the audit ledger row. A sweep failure (see `terraform/scheduler.tf`'s `retry_config`) delays cleanup, not enforcement — but a sustained outage would leave stale bindings accumulating on the bucket's IAM policy, which is itself worth alerting on in a production deployment (not built here — Week 1 scope).

This system authorizes and audits access to a GCS bucket. It does not inspect what's inside the objects a loan officer reads once granted — it cannot tell you whether a PAN or SSN is present in a given file, only that access to the bucket was time-bound and logged. That's a Cloud DLP problem, out of scope for Week 1.

Passing every check in this table is evidence a QSA, examiner, or SOX auditor can review — it is not a substitute for that review. Control citations here were checked against the general structure and stated intent of PCI DSS v4.0 Requirement 7, the FFIEC IT Examination Handbook's Information Security booklet, and SOX 404 ITGC guidance as understood at the time of writing; verify against the current primary-source publications before relying on this mapping in a real assessment.
