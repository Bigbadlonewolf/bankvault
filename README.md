# BankVault

Just-in-time privilege elevation for a mock retail bank's loan origination pipeline. No loan officer holds standing access to customer PII — every read is a time-bound, resource-bound grant, applied and revoked by two Cloud Functions, with every request, grant, denial, and revocation logged to an append-only BigQuery ledger.

## The Problem It Solves

The default pattern at most banks is that loan officers get a standing IAM role — `storage.objectViewer` on the applications bucket, granted once during onboarding and reviewed (if at all) on a quarterly cycle. That's a PCI DSS 7.2 violation waiting for an audit: for up to a quarter, a transferred or terminated employee can retain read access to Social Security numbers and income documentation with nobody actively deciding they should have it *today*. BankVault replaces the standing grant with a request: a loan officer asks for access to one application, a distinct approver signs off, GCP enforces the expiry natively via an IAM Condition, and the whole exchange is a row in a table before the grant is even live.

## Architecture

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

## Repository Layout

```
bankvault/
├── terraform/                    # All infra as code
│   ├── main.tf                   # Providers, enabled APIs, common labels
│   ├── variables.tf              # Every knob — durations, names, ingress, demo toggle
│   ├── iam.tf                    # PII bucket, both SAs, scoped IAM bindings + CEL conditions
│   ├── bigquery.tf               # Audit ledger table (explicit schema) + platform log sink
│   ├── functions.tf              # Both Cloud Functions v2, zipped from functions/
│   ├── scheduler.tf              # Pub/Sub topic + Cloud Scheduler revocation sweep
│   ├── outputs.tf
│   └── terraform.tfvars.example  # Copy to terraform.tfvars, fill in project_id
├── functions/
│   ├── grant_access/main.py      # HTTP-triggered approval workflow engine
│   └── revoke_access/main.py     # Pub/Sub-triggered revocation sweep
├── tests/                        # pytest, all GCP clients mocked — no network calls
├── scripts/run-local.sh          # Serve either function locally via functions-framework
├── docs/
│   ├── adr/001-build-vs-buy-jit-access.md
│   ├── adr/002-workforce-identity-federation-vs-iap.md
│   └── controls-mapping.md       # PCI DSS 7 / FFIEC / SOX 404 → specific resources
└── mkdocs.yml                    # GitHub Pages docs site (see CI)
```

## Setup

### 1. Configure Terraform
```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars — at minimum, set project_id
```

### 2. Validate and plan (no GCP credentials required for this repo's CI; you'll need them to actually apply)
```bash
terraform init
terraform fmt -check -recursive
terraform validate
terraform plan -var-file=terraform.tfvars
```

### 3. Apply against your own GCP project
```bash
terraform apply -var-file=terraform.tfvars
```

### 4. Run the tests
```bash
python -m venv .venv
source .venv/Scripts/activate    # Windows Git Bash; use .venv/bin/activate on macOS/Linux
pip install -r tests/requirements-test.txt
pytest tests/ -v
```

### 5. Try the functions locally
```bash
# Terminal 1
scripts/run-local.sh grant

# Terminal 2 — will validate and return a DENY without touching real GCP
# (self-approval is rejected by validate_request before any IAM call happens)
curl -s localhost:8080 -H "Content-Type: application/json" \
  -d '{"requested_by":"officer@bank.example.com","approved_by":"officer@bank.example.com","justification":"test","duration_minutes":30}' \
  | python3 -m json.tool

# A request with a distinct approver passes validation and will attempt the
# real IAM/Secret Manager/BigQuery calls — it needs `gcloud auth application-default
# login` and a real project in PII_BUCKET_NAME to succeed past validation.
```

### 6. Manually test the revocation sweep against a real deployment
```bash
gcloud pubsub topics publish bankvault-revocation-trigger --message='{"trigger":"manual-test"}'
gcloud functions logs read bankvault-revoke-access --gen2 --region=us-central1
```

## Terraform State

> **Note**: State is local (`terraform.tfstate`) for Week 1. Migrate to a GCS backend before more than one person touches this:
> ```hcl
> terraform {
>   backend "gcs" {
>     bucket = "your-tfstate-bucket"
>     prefix = "bankvault"
>   }
> }
> ```

## Compliance Coverage

Full citations and resource-level mapping: [`docs/controls-mapping.md`](docs/controls-mapping.md).

| Framework | Covered by |
|---|---|
| PCI DSS v4.0 Req. 7 (least privilege / need-to-know) | Time-bound + resource-bound CEL conditions, bucket-scoped SA roles, duration cap |
| FFIEC IT Handbook — Information Security, Access Control | ADR-002 (identity source of truth), segregation-of-duties check, dual-layer logging |
| SOX 404 ITGC — logical access & change management | Append-only BigQuery ledger, Terraform-reviewed IAM changes, scheduled auto-revocation |

## ADRs

- [ADR-001: Build vs. Buy — Custom JIT Broker vs. Off-the-Shelf PAM](docs/adr/001-build-vs-buy-jit-access.md)
- [ADR-002: Workforce Identity Federation vs. Cloud Identity-Aware Proxy](docs/adr/002-workforce-identity-federation-vs-iap.md)

## CI

Two workflows, both run with **no GCP credentials** — they validate structure and logic, they never deploy:

- `.github/workflows/terraform-validate.yml` — `terraform fmt -check`, `terraform init -backend=false`, `terraform validate`
- `.github/workflows/pytest.yml` — installs `tests/requirements-test.txt`, runs `pytest tests/ -v` against the fully-mocked function code
- `.github/workflows/docs.yml` — builds the MkDocs site and deploys to `gh-pages` on push to `main`

## What This Isn't

- **Not a real bank.** There is no core banking system, no actual customer data, no real loan-origination workflow behind this — it's a portfolio-grade demonstration of the JIT access pattern applied to a plausible banking use case.
- **Not connected to a real IdP.** Workforce Identity Federation is documented as the intended identity plane (ADR-002), but no actual SAML/OIDC provider is wired up — `requested_by` is a plain string checked against a domain suffix.
- **Week 1 scope only.** One resource (one GCS bucket), one grant function, one revoke function, one audit table. No approval UI, no multi-resource support, no per-officer rate limiting, no DLP content inspection.
- **Not production-hardened.** No VPC Service Controls, no CMEK, no dead-letter handling beyond Pub/Sub's default retry, no alerting on sweep failures. These are reasonable next steps, not gaps in the Week 1 build target.
- **Not deployed.** This repo is Terraform + Python + docs, verified with `fmt`/`validate`/`pytest` — not a live GCP project. `terraform apply` is left to whoever has credentials and wants to run it.
