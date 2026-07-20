# Compliance coverage

Every control below maps to a specific resource in this repo, not to an intention. Where a mapping is interpretive rather than explicit in the framework text, it says so. Framework citations are current as of July 2026; verify the exact clause text against the primary source before you put this in front of an auditor. Reading a summary of a control is not the same as reading the control.

## GLBA Safeguards Rule (16 CFR Part 314)

The Safeguards Rule governs how a financial institution protects customer information. A borrower's credit report is squarely customer financial information.

| Requirement | Interpretation | Covered by |
|---|---|---|
| 314.4(c)(1) — access controls that limit access to customer information to authorized users | Explicit | No standing access anywhere in the system. Access exists only as a per-request, per-object PAM grant. `terraform/pam.tf`, `terraform/iam.tf` |
| 314.4(c)(1) — periodic review of access | Interpretive | Standing access that would need periodic review does not exist; every grant is reviewed at request time by an approver and expires within 30 minutes. Review and expiry are PAM's `approval_workflow` and `max_request_duration`, not application code. `terraform/pam.tf` |
| 314.4(b) — risk assessment of foreseeable internal threats | Interpretive | The transferred-or-terminated-employee threat is the documented driver. `docs/adr/003-scope-and-actor-definition.md` |
| 314.4(c)(2) — identify and manage the data you hold | Interpretive | One regulated data class (credit report), one bucket, one object prefix per application. `terraform/storage.tf` |

## PCI DSS v4.0 — Requirement 7 (least privilege / need-to-know)

Credit reports commonly carry cardholder-adjacent PII; Requirement 7 is the least-privilege control family. Requirement numbers are v4.0.

| Requirement | Interpretation | Covered by |
|---|---|---|
| 7.2.1 — access assigned based on job classification and function | Explicit | Eligibility is the underwriter group on the entitlement; no individual bindings. `terraform/pam.tf` |
| 7.2.4 — review user access periodically | Interpretive | Grants are ephemeral; the standing bindings that trigger 7.2.4 reviews are absent by design. |
| 7.2.5 — least privilege for system/application accounts | Explicit | Broker SA holds PAM viewer only and cannot create grants; grant-creation eligibility sits with the underwriter group on the entitlement (ADR-006). Reconcile SA is read-only plus EXPIRE_FLAG writes. `terraform/iam.tf` |
| 7.3.1 / 7.3.2 — access enforced by an access-control system, by need-to-know | Explicit | IAM Condition pins each grant to one object prefix and one time window. `terraform/pam.tf` |

## SOX 404 — ITGC (logical access and change management)

For a public lender, access to systems affecting financial reporting is an IT general control.

| Control area | Interpretation | Covered by |
|---|---|---|
| Logical access — provisioning and de-provisioning | Explicit | Provisioning is the PAM grant, requested by the underwriter themselves; de-provisioning is PAM auto-expiry. Evidence is PAM's admin-activity audit log exported to `bankvault_platform_logs`, not application code. `terraform/pam.tf`, `terraform/logging.tf` |
| Logical access — audit trail | Explicit | Append-only `access_grants` ledger plus an independent platform-log export. `terraform/bigquery.tf`, `terraform/logging.tf` |
| Change management — access-control changes are reviewed | Explicit | The entitlement, its condition, and its eligible principals are Terraform, changed by reviewed commit. `terraform/pam.tf` |
| Segregation of duties | Explicit | Requester cannot approve their own grant. Enforced by PAM's `approval_workflow`, whose approver principals are a different group from `eligible_users`. The broker's `validate_request` also rejects self-approval, but as pre-flight evidence rather than enforcement — it is skippable (ADR-006). `terraform/pam.tf`, `terraform/variables.tf` |

## FFIEC IT Examination Handbook — Information Security (Access Control)

| Booklet topic | Interpretation | Covered by |
|---|---|---|
| Single authoritative identity source | Interpretive | Workforce Identity Federation, no second cloud directory. `docs/adr/002-workforce-identity-federation-vs-iap.md` |
| Authentication strength for privileged access | Interpretive | MFA-freshness gate on every privileged read, not just at session start. `docs/adr/004-mfa-freshness-zero-trust-signal.md` |
| Logging and monitoring | Explicit | Dual-layer logging; application ledger plus platform export. `terraform/logging.tf` |

## What this mapping does not claim

- It does not claim BankVault makes an institution compliant. It demonstrates one control pattern that supports specific requirements in each framework. Compliance is an assessment of a whole program, not a repo.
- It does not claim these are the only controls each requirement needs. Requirement 7, for example, also expects documented approval processes and access-review cadence that live in process, not code.
- Where the column says "Interpretive," a QSA or examiner may map it differently. The explicit mappings are the defensible ones; the interpretive ones are a defensible reading, not the only reading.
