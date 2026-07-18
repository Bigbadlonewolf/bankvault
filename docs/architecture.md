# Architecture

BankVault is one narrow flow done carefully: one actor, one resource, one regulated data class. An underwriter reads one borrower's credit report for 30 minutes, gated on a fresh login, and never holds that access outside the window.

## The request path, field by field

```
Underwriter
    │  POST /request
    │  { requested_by, approved_by, application_id, justification, id_token }
    ▼
request_broker (Cloud Function v2, HTTP, Python 3.12)
    ├── verify_mfa_freshness(id_token)
    │       decode the OIDC token, read auth_time, reject if
    │       now - auth_time > max_auth_age_seconds (default 300).
    │       This is a broker-side check against the identity provider,
    │       NOT an IAM Condition. GCP IAM has no "how recently did this
    │       principal MFA" attribute. See ADR-004.
    │
    ├── validate_request()
    │       requested_by and approved_by share the allowed domain,
    │       requested_by != approved_by (segregation of duties),
    │       duration_minutes <= max_grant_minutes,
    │       application_id matches the known-application pattern.
    │       Any failure writes a DENY row and returns before any PAM call.
    │
    ├── create_pam_grant()
    │       call PAM grants.create against the entitlement
    │       bankvault-credit-report-read. The entitlement (provisioned by
    │       Terraform, not by this function) already carries:
    │         - role: roles/storage.objectViewer
    │         - the IAM Condition pinning object path + expiry
    │         - the max-duration cap
    │         - the approval requirement
    │       The function passes justification and the resolved object
    │       prefix; PAM handles approval routing and, on approval,
    │       activates the conditioned grant.
    │
    └── write_ledger_row()
            INSERT one row into BigQuery access_grants for every outcome:
            REQUEST (received), GRANT (PAM grant created), or DENY (rejected).
    ▼
credit-reports bucket (GCS)
    uniform bucket-level access, object versioning on,
    public access prevention enforced, no ACLs.
```

## Why enforcement does not depend on any code in this repo

Two mechanisms bound an underwriter's access, and neither is a function in this repo. One handles *time*, the other handles *scope*.

1. **Time: PAM grant expiry.** Privileged Access Manager owns the grant lifecycle. The entitlement's `max_request_duration` caps the grant at 30 minutes, and PAM expires it when the duration elapses, removing the conditional binding it added. That is the capability that let the first version's custom revocation function be deleted (ADR-001). There is deliberately no `request.time < timestamp(...)` CEL clause: a PAM entitlement's condition is static, expiry is PAM's job, and duplicating it in a condition would be two timers that can disagree.

2. **Scope: the IAM Condition.** The granted binding carries `resource.name.startsWith("projects/_/buckets/<bucket>/objects/<application_id>/")`. GCP's IAM policy engine evaluates that at the moment a request hits the bucket. A grant issued for application `APP-1001` cannot read `APP-1002`'s file, because the clause fails on the resource name. The literal `_` in that path is required by GCS's CEL resource-name format; it is not a placeholder to fill in.

Because the condition is static per entitlement, object scope is per-application, not per-request: each application gets its own entitlement (`terraform/pam.tf`, `for_each` over `demo_application_ids`). That is a real limitation, not a hidden one. For a fixed demo set it is clean; for an unbounded set of applications, per-object isolation would move to a per-request grant condition or a separate mechanism (per-object buckets, signed URLs). That is listed under out-of-scope below rather than claimed as done.

## Why there is still a reconcile job

If PAM expires grants on its own, the reconcile job looks redundant. It is not, but it is also honestly limited.

It exists for two things the expiry path does not give you:

- **Ledger completeness.** The `access_grants` ledger is the SOX 404 evidence artifact. The reconcile job confirms every GRANT row whose `window_end` has passed has a corresponding close-out (an EXPIRE row), and writes one if the lifecycle event was never recorded. Without it, a function crash between grant and expiry could leave a grant that looks perpetually open in the ledger even though PAM expired it.

- **Anomaly detection.** It cross-checks the ledger against live PAM grant state and flags a grant that PAM still reports active past its `window_end`, or an IAM binding on the bucket that no ledger row explains.

What it does **not** do is revoke. It writes an `EXPIRE_FLAG` row and emits a structured alert log. So the defensible claim is "an overrun is detected within roughly one reconcile interval (15 minutes)," not "contained within 15 minutes." Those are different sentences and only one of them is true. If you need containment rather than detection, the next step is wiring the flag to an automated PAM grant revocation, and that is a deliberate future decision, not an accident of the current build (ADR-005).

## Why the audit ledger is append-only

`access_grants` never receives an `UPDATE`. Every lifecycle event (a request, a grant, a denial, an expiry flag) is a new row keyed by `request_id`. "Is this grant still active" is a query (a GRANT row with no matching EXPIRE row), not a status column someone could quietly edit after the fact. That property is what makes the ledger usable as SOX 404 ITGC evidence: the history can be appended to, not rewritten.

Two independent layers back this up:

1. **Application ledger** (`access_grants`) written by the broker with full business context: who, what, when, why, approved by whom, the object path, the MFA `auth_time` that gated the grant.
2. **Platform log export** (`bankvault_platform_logs`), a Cloud Logging sink routing the broker's logs, the reconcile job's logs, and PAM admin-activity audit logs into BigQuery. If the application code has a bug and skips a ledger write, the platform-level record still exists, produced independently by GCP.

See [Compliance coverage](controls-mapping.md) for how each piece maps to a specific GLBA, PCI DSS, FFIEC, or SOX 404 control.

## Identity plane

Underwriters and approvers resolve through Workforce Identity Federation, not a second cloud-local directory. A leaver disabled in the corporate IdP loses BankVault eligibility with them, because there is no parallel Cloud Identity account to forget about. That decision, and the one directory it deliberately rules out, is ADR-002.

The broker does not trust a session token merely because it is unexpired. It reads `auth_time` and requires a login fresh within `max_auth_age_seconds`. Access Context Manager reauthentication session controls are the defense-in-depth layer behind that broker check; the broker check is the one this repo implements. ADR-004 covers why freshness, not mere validity, is the signal that matters for a privileged read.

## Trust boundaries

| Boundary | Who is trusted | What is checked |
|---|---|---|
| Underwriter → broker | Nobody by default | OIDC token shape + `auth_time` freshness, domain, SoD |
| Broker → PAM | Broker SA, narrowly | SA may create grants only on the one entitlement |
| PAM → bucket | The conditioned grant | IAM Condition: object prefix + time window |
| Broker/reconcile → ledger | Broker SA (write), reconcile SA (read) | Reconcile cannot write access_grants except EXPIRE_FLAG rows |

## What is deliberately out of scope for this build

These are next steps, not gaps hidden under the demo:

- **VPC Service Controls** around the bucket and BigQuery, to stop exfiltration to a project outside the perimeter even with a valid grant.
- **CMEK** on the bucket and datasets, so key custody is separable from data custody.
- **DLP content inspection** on reads, to catch a credit report that lands in the wrong object prefix.
- **Automated containment**: wiring the reconcile flag to a real PAM grant revocation (ADR-005 open question).
- **A real JWKS verification path** in `verify_mfa_freshness`, replacing the claims-shape check with signature verification against the live IdP.
- **Alerting**: routing the reconcile job's structured alert log to an on-call channel with a threshold.
