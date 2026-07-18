# BankVault

Just-in-time privilege elevation for a mock mortgage lender's loan-origination pipeline. No underwriter holds standing access to borrower credit reports. Each read is a time-bound, object-scoped grant, gated on a fresh multi-factor login, issued through Google Cloud **Privileged Access Manager (PAM)**, and written to an append-only BigQuery ledger before it goes live.

> **Status:** reference architecture. This repo is Terraform + Python + docs, verified with `terraform validate` and `pytest`. It is not a deployed GCP project. See [What this isn't](#what-this-isnt).

## The problem it solves

Ask a lender who can read a borrower's credit file today and you usually get a list of roles, not a list of people. Standing access is the default almost everywhere, and it survives quarterly review cycles that were never designed to catch a reassignment made in week two. For up to a quarter, a transferred or terminated underwriter can keep read access to income documentation, SSNs, and full credit reports with nobody actively deciding they should have it *today*. That is a GLBA Safeguards Rule access-control gap (16 CFR 314.4(c)(1)) and a PCI DSS v4.0 Requirement 7 finding waiting for an audit.

BankVault removes the standing grant. An underwriter who needs a credit report asks for it, proves the login is fresh, gets 30 minutes scoped to that one object, and loses it automatically when PAM expires the grant. Nobody holds a key while they are not using it, and the whole exchange is a row in a ledger before access is live.

## Architecture

```
Underwriter
    │  POST /request { requested_by, approved_by, application_id, justification, id_token }
    ▼
request_broker  (Cloud Function v2, HTTP, Python 3.12)
    ├── verify_mfa_freshness()   — validate IdP OIDC token; reject if auth_time older than
    │                              max_auth_age (default 300s). Not an IAM condition; a broker
    │                              check against the identity provider. (ADR-004)
    ├── validate_request()       — domain check, segregation of duties (requester != approver),
    │                              duration cap, known application_id
    ├── create_pam_grant()       — PAM grants.create against the pre-provisioned entitlement
    │                              bankvault-credit-report-read. The entitlement carries the
    │                              IAM Condition and the max-duration cap; PAM owns approval
    │                              and auto-expiry.
    └── write_ledger_row()       — INSERT into BigQuery access_grants (REQUEST / GRANT / DENY)
    │
    ▼
Privileged Access Manager entitlement: bankvault-credit-report-<application_id>
    (one entitlement per application; Terraform for_each over demo_application_ids)
    role: roles/storage.objectViewer
    IAM Condition (CEL), static per entitlement (object scope only):
        resource.name.startsWith("projects/_/buckets/<bucket>/objects/<application_id>/")
    time bound: PAM max_request_duration (1800s). PAM expires the grant; there is no
                request.time CEL clause, because PAM owns expiry (ADR-001).
    approval: required (approver group)
    │
    ▼
credit-reports bucket  (GCS, uniform access, versioned, public access prevention enforced)
    While a grant is active, its object-scope condition means it can read only its own
    application's objects. Access ends when PAM expires the grant and removes the
    conditional binding. No code in this repo revokes access.
    │
    ▼
Cloud Scheduler (*/15 * * * *) ──▶ Pub/Sub: bankvault-reconcile-trigger
    │
    ▼
reconcile  (Cloud Function v2, Pub/Sub-triggered, Python 3.12, VIEWER-ONLY)
    ├── find_overrun_grants()  — ledger GRANT rows past window_end with no EXPIRE row,
    │                            cross-checked against PAM grant state
    └── flag()                 — write EXPIRE_FLAG row + emit a structured alert log.
                                 It DETECTS an overrun. It does not revoke one. (ADR-005)

Cloud Logging (broker, reconcile, and PAM admin activity audit logs)
    │
    ▼  google_logging_project_sink
BigQuery: bankvault_platform_logs  — independent record, survives an application-code bug
```

Full field-level walkthrough: [`docs/architecture.md`](docs/architecture.md).

## What changed from the first cut (and why the code is smaller)

The first version of BankVault was a custom broker: one function applied a conditional IAM binding, a second function ran on a schedule to strip it. [ADR-001](docs/adr/001-build-vs-buy-jit-broker.md) named the exact condition under which that build would be wrong: *Google ships a managed grant lifecycle that does this natively.* That condition fired. GCP Privileged Access Manager reached GA with time-bound grants, an approval workflow, and IAM-Condition support on the granted role. The custom `revoke_access` function existed only to undo something PAM now undoes itself, so it was deleted rather than defended. The broker shrank to the one job PAM does not do: refusing access when the login is not fresh.

That reversal is the point of the project, not an embarrassment in it. The ADR is written so the trigger was legible before it fired.

## Repository layout

```
bankvault/
├── terraform/
│   ├── main.tf                    # providers, enabled APIs, common labels
│   ├── variables.tf               # every knob: durations, names, groups, max auth age
│   ├── storage.tf                 # credit-report bucket (uniform, versioned, PAP enforced)
│   ├── pam.tf                     # the PAM entitlement, IAM Condition, approval workflow
│   ├── iam.tf                     # broker + reconcile service accounts, least-privilege roles
│   ├── bigquery.tf                # append-only audit ledger + platform-log dataset
│   ├── functions.tf               # both Cloud Functions v2, zipped from functions/
│   ├── scheduler.tf               # Pub/Sub topic + Cloud Scheduler reconcile sweep
│   ├── logging.tf                 # log sink → BigQuery for PAM + function audit logs
│   ├── outputs.tf
│   └── terraform.tfvars.example
├── functions/
│   ├── request_broker/main.py     # MFA-freshness gate + validation + PAM grant + ledger write
│   └── reconcile/main.py          # detect-only overrun sweep
├── tests/                         # pytest, all GCP + IdP clients mocked, no network
├── scripts/run-local.sh           # serve either function via functions-framework
├── docs/
│   ├── index.md
│   ├── architecture.md
│   ├── controls-mapping.md        # GLBA / PCI DSS v4.0 / SOX 404 / FFIEC → specific resources
│   └── adr/001..005
└── mkdocs.yml
```

## Setup

### 1. Configure Terraform
```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars: set project_id, underwriter_group, approver_group
```

### 2. Validate (no GCP credentials needed for this)
```bash
terraform init -backend=false
terraform fmt -check -recursive
terraform validate
```

### 3. Plan and apply against your own project (needs credentials and a provider that ships the PAM resource)
```bash
terraform init
terraform plan  -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```

> The `google_privileged_access_manager_entitlement` resource requires a recent `hashicorp/google` provider. Pin and verify the version before you apply. See [`terraform/pam.tf`](terraform/pam.tf) for the version note.

### 4. Run the tests
```bash
python -m venv .venv
source .venv/Scripts/activate       # .venv/bin/activate on macOS/Linux
pip install -r tests/requirements-test.txt
pytest tests/ -v
```

### 5. Try the broker locally (boots without real GCP)
```bash
scripts/run-local.sh broker
# A stale-login request is rejected by verify_mfa_freshness before any PAM call:
curl -s localhost:8080 -H "Content-Type: application/json" -d '{
  "requested_by":"underwriter@lender.example.com",
  "approved_by":"lead@lender.example.com",
  "application_id":"APP-1001",
  "justification":"manual QC review",
  "auth_time": 0
}' | python -m json.tool
```

## Compliance coverage

Full citations and resource-level mapping: [`docs/controls-mapping.md`](docs/controls-mapping.md).

| Framework | Covered by |
|---|---|
| GLBA Safeguards Rule (16 CFR 314.4(c)(1)) | No standing access to customer financial data; per-request, per-object grants |
| PCI DSS v4.0 Req. 7 (least privilege / need-to-know) | Object-scoped + time-bound IAM Condition, max-duration cap, approval workflow |
| SOX 404 ITGC (logical access, change management) | Append-only BigQuery ledger, Terraform-reviewed entitlement, PAM-owned expiry |
| FFIEC IT Handbook (Information Security, Access Control) | Single identity source (ADR-002), segregation of duties, dual-layer logging |

## Honest limits

Two claims in this repo are narrower than they look, and both are stated on purpose.

**Availability is bounded by the identity provider.** The broker denies access when the IdP is unreachable, because it cannot confirm the login is fresh. A loan decision with an SLA does not stop having one because the IdP is down. That trade is deliberate: an identity control that keeps granting when it cannot verify who is asking has a bypass, and the bypass opens under exactly the conditions an attacker wants. (ADR-004.)

**Reconciliation detects an overrun. It does not contain one.** The honest sentence is "detected within roughly one reconcile interval," not "contained within." PAM owns the actual expiry; the reconcile job is a completeness and anomaly check, not a second enforcement path. (ADR-005.)

## What this isn't

- **Not a real lender.** No core system, no real borrower data, no real underwriting workflow. It is a portfolio-grade demonstration of the JIT-access pattern on a plausible lending use case.
- **Not wired to a real IdP.** Workforce Identity Federation is the documented identity plane (ADR-002), but no live SAML/OIDC provider is connected. `verify_mfa_freshness` validates a token's claims shape and `auth_time`; it does not perform full signature verification against a live JWKS endpoint in this repo.
- **Not deployed.** Verified with `fmt` / `validate` / `pytest`. `terraform apply` is left to whoever has credentials.
- **Not production-hardened.** No VPC Service Controls, no CMEK by default, no DLP content inspection, no alerting pipeline beyond the structured log the reconcile job emits. These are reasonable next steps, listed in [`docs/architecture.md`](docs/architecture.md), not gaps hidden under the demo.
