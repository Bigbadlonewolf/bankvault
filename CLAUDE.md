# CLAUDE.md

Guidance for working in this repo. BankVault is a Week 1 portfolio build — a JIT privilege elevation broker for a mock bank's loan origination pipeline. Read this before touching Terraform or the two Cloud Functions.

## What This Is
Two Cloud Functions (`grant_access`, `revoke_access`) that apply and remove time-bound, resource-bound IAM Conditions on a GCS bucket standing in for a loan-origination PII store. Every action — grant, denial, revocation — is an append-only row in a BigQuery audit ledger. No standing access exists anywhere in this system.

## Architecture
```
Loan officer ──POST──▶ grant_access ──▶ conditional IAM binding on PII bucket
                            │               (request.time < timestamp(...))
                            ├──▶ Secret Manager (session token)
                            └──▶ BigQuery access_grants (GRANT/DENY row)

Cloud Scheduler ──▶ Pub/Sub ──▶ revoke_access ──▶ removes expired bindings,
                                                    destroys secrets,
                                                    writes REVOKE row

Cloud Logging (both functions) ──▶ log sink ──▶ BigQuery platform_logs
```
Full diagram with field-level detail: `README.md`.

## Commands

### Terraform
```bash
cd terraform
terraform fmt -check -recursive
terraform init -backend=false     # CI uses this; no state, no credentials needed
terraform validate
terraform plan -var-file=terraform.tfvars    # needs terraform.tfvars + real GCP creds
```

### Tests
```bash
python -m venv .venv
source .venv/Scripts/activate      # .venv/bin/activate on macOS/Linux
pip install -r tests/requirements-test.txt
pytest tests/ -v
```

### Local function invocation (functions-framework, no real GCP required to boot)
```bash
scripts/run-local.sh grant     # serves grant_access on :8080
scripts/run-local.sh revoke    # serves revoke_access on :8081 (cloudevent signature)
```

## Conventions

### Secrets
- Session tokens live in Secret Manager only, under the `bankvault-session-<request_id>` naming prefix — never logged, never returned in a response body beyond the secret's resource name.
- `grant_sa` and `revoke_sa` hold `roles/secretmanager.admin` scoped by an IAM condition to that prefix (`resource.name.startsWith(...)`) — neither SA can read or create any other secret in the project. Don't widen this without a specific reason; it's the resource-bound-grant pattern applied a second time, not an oversight.

### IAM condition (CEL) gotchas
- Conditional bindings require **IAM policy version 3** — always call `get_iam_policy(requested_policy_version=3)` and set `policy.version = 3` before appending a binding, or the condition silently fails to attach.
- `request.time` compares against the timestamp on the *evaluation* request, not the binding's creation time — this is what makes the CEL expiry self-enforcing without `revoke_access` running.
- The resource-bound clause uses `resource.name.startsWith("projects/_/buckets/<bucket>/objects/<prefix>")` — the literal `_` is required by GCS's CEL resource-name format, it is not a placeholder to fill in.
- `remove_iam_binding` matches on `(role, member, condition.expression)` exactly — two grants for the same loan officer with different expiries produce different `condition.expression` strings and won't collide during revocation. Don't "simplify" the match to `(role, member)` only; that would revoke unrelated active grants for the same user.

### Audit ledger
- `access_grants` is append-only. Never write an `UPDATE` against it — a request's lifecycle (GRANT → REVOKE, or just DENY) is reconstructed by querying `request_id`, not by mutating a status column. This is what makes the ledger useful as SOX 404 evidence.
- `revoke_access` finds work via `NOT EXISTS` against the same table (grant rows past `window_end` with no matching revoke row) — this is intentional; there's no separate "active grants" state table to fall out of sync.

### Naming
- Terraform resources: `snake_case`, grouped by concern into `iam.tf` / `bigquery.tf` / `functions.tf` / `scheduler.tf` — don't add a fifth cross-cutting file without a reason.
- Cloud Function source dirs mirror function names: `functions/grant_access/`, `functions/revoke_access/`. Each is a self-contained `main.py` + `requirements.txt`, zipped independently by `terraform/functions.tf`.
- Python: kebab-case is not used here — standard `snake_case` for functions/variables, matching the rest of the workspace's Python conventions.
