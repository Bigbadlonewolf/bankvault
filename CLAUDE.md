# CLAUDE.md

Guidance for working in this repo. BankVault is a portfolio reference architecture: a just-in-time privilege elevation broker for a mock mortgage lender's loan-origination pipeline, built on Google Cloud Privileged Access Manager (PAM). Read this before touching Terraform or the two Cloud Functions.

## What this is

No underwriter holds standing access to a borrower's credit report. Each read is a time-bound, object-scoped PAM grant, approval-gated, and written to an append-only BigQuery ledger. PAM owns approval and expiry; nothing in this repo revokes anything.

**The broker is not in the privilege path.** PAM elevates the calling principal and `CreateGrant` has no grantee parameter, so the underwriter requests their own grant. The broker is a skippable pre-flight gate and the per-request audit record (ADR-006).

```
Underwriter ──POST──▶ request_broker          (optional pre-flight; NOT a chokepoint)
                          ├─ verify_identity        (OIDC sig/iss/aud/exp + 900s freshness; ADR-002/004/006)
                          ├─ validate_request       (domain, SoD, duration cap, app id)
                          └─ write_ledger_row        (BigQuery access_grants: REQUEST/DENY)

Underwriter ──grants.create AS THEMSELVES──▶ PAM entitlement (per application)
                                     ─▶ conditional roles/storage.objectViewer on the
                                        credit-report object prefix. PAM auto-expires the grant.

Access Context Manager reauth binding ─▶ the actual enforced recency control (1h floor)

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
- The grantee question that `create_pam_grant` carried a VERIFY-BEFORE-DEPLOY note about **has been verified** and it closed the design off: PAM elevates the calling principal, and `CreateGrant` has no grantee or on-behalf-of parameter. That is why no code here creates grants (ADR-006). `_check_pam_grant_active` in `reconcile` is read-only and unaffected.

### MFA freshness (ADR-004, amended by ADR-006)
- Freshness is **not** enforced by an IAM Condition. GCP IAM has no authentication-recency attribute. Do not "move it into a CEL condition"; that capability does not exist.
- Freshness is **not** enforced by the broker either, despite the check living there. The broker is skippable, so its 900s check is early rejection plus the ledger's `mfa_auth_time` evidence. Enforcement is an Access Context Manager reauth binding whose floor is **1 hour** (`--session-length` accepts `0s` or 1h–24h, nothing between). Do not write "the broker enforces freshness" back into the docs; it is the claim ADR-006 exists to retract.
- ACM bindings cannot target PAM specifically, so the reauth requirement covers the group's whole GCP session. That operational cost is stated in the README on purpose. Don't quietly drop it.
- Fail-closed: a missing token, an unverifiable token, or a missing/unreadable `auth_time` is a rejection, never a pass. Keep it that way.
- `verify_identity` (in `request_broker/main.py`) does full OIDC verification: it verifies the id_token's RS256 signature against the IdP JWKS at `OIDC_JWKS_URI` plus issuer/audience/expiry, then binds the request to the verified identity claim — a body `requested_by` that disagrees is rejected. It is fail-closed: with `OIDC_ISSUER`/`OIDC_AUDIENCE`/`OIDC_JWKS_URI` unset it denies every request. The signature check sits behind the `_verify_id_token` / `_fetch_signing_key` seams so tests inject claims without crypto; one test exercises real RS256. Do not reintroduce an unverified `auth_time`-from-body path — that was the bypass this removed.

### Audit ledger
- `access_grants` is append-only. Never write an `UPDATE`. A request's lifecycle is reconstructed by querying `request_id`, not by mutating a status column. This is what makes it SOX 404 evidence.
- `reconcile` only ever writes `EXPIRE_FLAG` rows. This is a code-level invariant with a test behind it (`tests/test_reconcile.py::test_reconcile_has_no_revoke_path`), not an IAM boundary. Do not add a revoke path without an ADR that argues for containment over detection (ADR-005).

### Naming
- Terraform: `snake_case`, grouped by concern into `storage.tf` / `pam.tf` / `iam.tf` / `bigquery.tf` / `functions.tf` / `scheduler.tf` / `logging.tf`. Don't add a cross-cutting file without a reason.
- Function source dirs mirror function names: `functions/request_broker/`, `functions/reconcile/`. Each is a self-contained `main.py` + `requirements.txt`, zipped independently by `terraform/functions.tf`.
- Python: standard `snake_case`.

## The two things not to undo

Both are absences. Absent code looks like missing code, which is exactly why they get "helpfully" restored.

**No custom revoke lifecycle (ADR-001).** The first version's `revoke_access` was deleted when PAM made it redundant. PAM owns expiry. A second thing that revokes access is a second thing that can revoke it wrongly.

**No grant creation anywhere in this repo (ADR-006).** If you are about to add `create_grant` to the broker so it can "actually do something," stop. PAM elevates the caller, so that code would elevate the broker's service account to read borrower credit reports, permanently, with nobody reviewing it. `tests/test_request_broker.py::test_broker_has_no_grant_creation_path` fails if it comes back. That test is the guardrail, not an obstacle to route around.

In both cases the absence is the decision. Read the ADR before you fill the gap.
