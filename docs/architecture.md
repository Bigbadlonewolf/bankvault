# Architecture

BankVault is one narrow flow done carefully: one actor, one resource, one regulated data class. An underwriter reads one borrower's credit report for 30 minutes, gated on a fresh login, and never holds that access outside the window.

## The request path, field by field

```
Access Context Manager reauth binding on the underwriter group
    session length 1h (platform floor: 0s, or 1h-24h, nothing between).
    THIS is the enforced recency control. It covers the group's whole
    Google Cloud session, because PAM is not independently targetable
    by a scopedAccessSettings binding. See ADR-006.
    │
    ▼
Underwriter
    │
    ├─ (optional) POST /request ─────────────────────────────┐
    │  { requested_by, approved_by, application_id,          │
    │    justification, id_token }                           │
    │                                                        ▼
    │                        request_broker (Cloud Function v2, HTTP, Python 3.12)
    │                            ├── verify_identity(id_token)
    │                            │       verify the OIDC token (RS256 sig vs IdP JWKS, iss/aud/exp),
    │                            │       bind to the verified identity claim, read auth_time, reject
    │                            │       if now - auth_time > max_auth_age_seconds (default 900).
    │                            │       NOT enforcement. The broker is skippable, so this is
    │                            │       early rejection plus the auth_time the ledger records.
    │                            │       Also NOT an IAM Condition: GCP IAM has no "how recently
    │                            │       did this principal MFA" attribute. See ADR-004, ADR-006.
    │                            │
    │                            ├── validate_request()
    │                            │       requested_by and approved_by share the allowed domain,
    │                            │       requested_by != approved_by (segregation of duties),
    │                            │       duration_minutes <= max_grant_minutes,
    │                            │       application_id matches the known-application pattern.
    │                            │
    │                            └── write_ledger_row()
    │                                    REQUEST (cleared pre-flight, entitlement named back
    │                                    to the caller) or DENY (rejected, with reason).
    │                                    Never GRANT: this function does not create grants
    │                                    and never observes one being created.
    │
    ▼
grants.create — called by the UNDERWRITER, as themselves
    PAM attaches a grant's privileges to the calling principal and CreateGrant has
    no grantee parameter, so no intermediary can request on their behalf (ADR-006).
    ▼
PAM entitlement: bankvault-credit-report-<application_id>
    provisioned by Terraform, one per application, already carrying:
      - role: roles/storage.objectViewer
      - the IAM Condition pinning the object prefix (static per entitlement)
      - max_request_duration (the cap PAM expires the grant at)
      - the approval requirement (one approver + justification)
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

- **Ledger completeness.** The `access_grants` ledger is the SOX 404 evidence artifact. The broker writes no GRANT row (ADR-006), so the reconcile job reconstructs each grant from the PAM `CreateGrant` admin-activity audit events exported to `bankvault_platform_logs`, confirms every grant whose `window_end` has passed has a corresponding close-out, and writes an EXPIRE_FLAG row if the lifecycle event was never recorded. Without it, a grant could look perpetually open even though PAM expired it.

- **Anomaly detection.** It cross-checks the reconstructed grants against live PAM grant state and flags a grant that PAM still reports active past its `window_end`, or an IAM binding on the bucket that no ledger row explains.

What it does **not** do is revoke. It writes an `EXPIRE_FLAG` row and emits a structured alert log. So the defensible claim is "an overrun is detected within roughly one reconcile interval (15 minutes)," not "contained within 15 minutes." Those are different sentences and only one of them is true. If you need containment rather than detection, the next step is wiring the flag to an automated PAM grant revocation, and that is a deliberate future decision, not an accident of the current build (ADR-005).

## Why the audit ledger is append-only

`access_grants` never receives an `UPDATE`. Every lifecycle event (a request, a grant, a denial, an expiry flag) is a new row keyed by `request_id`. "Is this grant still active" is a query (a GRANT row with no matching EXPIRE row), not a status column someone could quietly edit after the fact. That property is what makes the ledger usable as SOX 404 ITGC evidence: the history can be appended to, not rewritten.

Two independent layers back this up:

1. **Application ledger** (`access_grants`) written by the broker with full business context: who, what, when, why, approved by whom, the object path, the MFA `auth_time` that gated the grant.
2. **Platform log export** (`bankvault_platform_logs`), a Cloud Logging sink routing the broker's logs, the reconcile job's logs, and PAM admin-activity audit logs into BigQuery. If the application code has a bug and skips a ledger write, the platform-level record still exists, produced independently by GCP.

See [Compliance coverage](controls-mapping.md) for how each piece maps to a specific GLBA, PCI DSS, FFIEC, or SOX 404 control.

## Identity plane

Underwriters and approvers resolve through Workforce Identity Federation, not a second cloud-local directory. A leaver disabled in the corporate IdP loses BankVault eligibility with them, because there is no parallel Cloud Identity account to forget about. That decision, and the one directory it deliberately rules out, is ADR-002.

Recency, not mere session validity, is the signal that matters for a privileged read. ADR-004 covers why. ADR-006 corrects where it is enforced, and the correction matters because the earlier version of this paragraph had the layers the wrong way round.

**Access Context Manager reauthentication session controls are the enforcement.** A binding on the underwriter group sets a session length of one hour, which is the platform's floor rather than a tuned value: `--session-length` accepts `0s` or a duration between 1 hour and 24 hours. Because PAM is not documented as an independently targetable application for `scopedAccessSettings`, that binding covers the group's entire Google Cloud session and not just the credit-report path. Broad blast radius, real enforcement.

**The broker's 900-second check is evidence, not enforcement.** It reads `auth_time` and refuses anything staler than fifteen minutes, which rejects bad requests early and puts a tighter number in the ledger than the platform bound. It cannot be enforcement, because an underwriter who never calls the broker still reaches PAM. Whether a raw REST call to the PAM API is covered by a console-scoped ACM binding is `[verify against current GCP docs]`; the unnarrowed binding sidesteps the question.

## Trust boundaries

| Boundary | Who is trusted | What is checked |
|---|---|---|
| Underwriter → broker | Nobody by default | OIDC token shape + `auth_time` freshness, domain, SoD |
| Broker → PAM | Broker SA, narrowly | SA holds PAM viewer only; it cannot create grants (ADR-006) |
| PAM → bucket | The conditioned grant | IAM Condition: object prefix + time window |
| Broker/reconcile → ledger | Broker SA (write), reconcile SA (read) | Reconcile cannot write access_grants except EXPIRE_FLAG rows |

## What is deliberately out of scope for this build

These are next steps, not gaps hidden under the demo:

- **VPC Service Controls** around the bucket and BigQuery, to stop exfiltration to a project outside the perimeter even with a valid grant.
- **CMEK** on the bucket and datasets, so key custody is separable from data custody.
- **DLP content inspection** on reads, to catch a credit report that lands in the wrong object prefix.
- **Automated containment**: wiring the reconcile flag to a real PAM grant revocation (ADR-005 open question).
- **A live IdP behind the JWKS verification path.** `verify_identity` already verifies the RS256 signature against the JWKS at `OIDC_JWKS_URI` (with issuer/audience/expiry); what remains is pointing those `OIDC_*` env vars at a real Workforce Identity Federation / IdP endpoint. Until then it is fail-closed and denies every request.
- **Alerting**: routing the reconcile job's structured alert log to an on-call channel with a threshold.
