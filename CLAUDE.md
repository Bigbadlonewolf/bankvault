# CLAUDE.md

Guidance for working in this repo. BankVault is a portfolio reference architecture: a just-in-time privilege elevation broker for a mock mortgage lender's loan-origination pipeline, built on Google Cloud Privileged Access Manager (PAM). Read this before touching Terraform or the two Cloud Functions.

## What this is

No underwriter holds standing access to a borrower's credit report. Each read is a time-bound, object-scoped PAM grant, gated on a fresh login by the request broker, and written to an append-only BigQuery ledger. PAM owns approval and expiry; nothing in this repo revokes anything.

```
Underwriter ──POST──▶ request_broker
                          ├─ verify_mfa_freshness   (reject stale login, ADR-004)
                          ├─ validate_request       (domain, SoD, duration cap, app id)
                          ├─ create_pam_grant        (PAM grants.create on the entitlement)
                          └─ write_ledger_row        (BigQuery access_grants: REQUEST/GRANT/DENY)

PAM entitlement (per application) ─▶ conditional roles/storage.objectViewer on the
                                     credit-report object prefix. PAM auto-expires the grant.

Cloud Scheduler ─▶ Pub/Sub ─▶ reconcile   (detect-only: flags overruns, ADR-005)

Cloud Logging (broker, reconcile, PAM audit) ─▶ sink ─▶ BigQuery platform_logs
```

Full diagram and field detail: `docs/architecture.md`.

## Commands

### Terraform
```bash
cd terraform
terraform fmt -check -recursive
terraform init -backend=false     # CI uses this; no state, no credentials needed
terraform validate
terraform plan -var-file=terraform.tfvars   # needs terraform.tfvars + real GCP creds
```

### Tests
```bash
python -m venv .venv
source .venv/Scripts/activate      # .venv/bin/activate on macOS/Linux
pip install -r tests/requirements-test.txt
pytest tests/ -v
```
Tests need only `functions-framework` and `pytest`. The GCP and PAM calls are lazy imports behind seams the tests patch, so no `google-cloud-*` library is required to run them.

### Local function invocation
```bash
scripts/run-local.sh broker      # HTTP :8080, entry handle_request
scripts/run-local.sh reconcile   # CloudEvent :8081, entry handle_event
```

## Conventions and gotchas

### PAM entitlements
- The entitlement's `condition_expression` is **static per entitlement**, so object scope is per-application, not per-request. That is why there is one entitlement per application (`terraform/pam.tf`, `for_each` over `demo_application_ids`). Do not try to make the condition vary per request; PAM does not support it. If you need unbounded applications, that is the documented limitation in `docs/architecture.md`, not a bug to patch away.
- **Time-bounding is PAM's `max_request_duration`, not a `request.time` CEL clause.** PAM expires the grant. Do not add a timestamp condition and call it the expiry; that duplicates PAM and drifts.
- The literal `_` in `projects/_/buckets/<bucket>/objects/<app>/` is required by GCS's CEL resource-name format. It is not a placeholder.
- `create_pam_grant` and `_check_pam_grant_active` carry a VERIFY-BEFORE-DEPLOY note (ADR-001): the grant-request caller/grantee semantics must be confirmed against the live PAM API. Keep that note until it is verified against a real project.

### MFA freshness (ADR-004)
- Freshness is enforced in the broker, not by an IAM Condition. GCP IAM has no authentication-recency attribute. Do not "move it into a CEL condition"; that capability does not exist.
- Fail-closed: a missing or unreadable `auth_time` is a rejection, never a pass. Keep it that way.
- `verify_mfa_freshness` decodes the JWT claims segment only; it does not verify the signature. That stub boundary is stated in the README. If you add real JWKS verification, update the README's "What this isn't".

### Audit ledger
- `access_grants` is append-only. Never write an `UPDATE`. A request's lifecycle is reconstructed by querying `request_id`, not by mutating a status column. This is what makes it SOX 404 evidence.
- `reconcile` only ever writes `EXPIRE_FLAG` rows. This is a code-level invariant with a test behind it (`tests/test_reconcile.py::test_reconcile_has_no_revoke_path`), not an IAM boundary. Do not add a revoke path without an ADR that argues for containment over detection (ADR-005).

### Naming
- Terraform: `snake_case`, grouped by concern into `storage.tf` / `pam.tf` / `iam.tf` / `bigquery.tf` / `functions.tf` / `scheduler.tf` / `logging.tf`. Don't add a cross-cutting file without a reason.
- Function source dirs mirror function names: `functions/request_broker/`, `functions/reconcile/`. Each is a self-contained `main.py` + `requirements.txt`, zipped independently by `terraform/functions.tf`.
- Python: standard `snake_case`.

## The one thing not to undo

ADR-001 records a reversal: the first version's custom revoke function was deleted when GCP PAM made it redundant. If you find yourself reintroducing a custom grant/revoke lifecycle, stop and read ADR-001 first. The absence of that code is the decision, not an omission.
