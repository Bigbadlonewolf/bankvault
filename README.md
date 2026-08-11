# BankVault

Just-in-time privilege elevation for a mock mortgage lender's loan-origination pipeline. No underwriter holds standing access to borrower credit reports. Each approved request yields a time-bound grant scoped to one application's prefix, gated on a fresh multi-factor login, issued through Google Cloud **Privileged Access Manager (PAM)**, and recorded in an append-only BigQuery ledger.

> **Status:** reference architecture. Verified with `terraform validate` and `pytest`. `terraform plan` requires authenticated provider credentials and live API reads against PAM and GCS — not run. `terraform apply` is left to whoever has credentials.

## The problem it solves

Ask a lender who can read a borrower's credit file today and you usually get a list of roles, not a list of people. Standing access is the default almost everywhere, and it survives quarterly review cycles that were never designed to catch a reassignment made in week two. For up to a quarter, a transferred or terminated underwriter can keep read access to income documentation, SSNs, and full credit reports with nobody actively deciding they should have it *today*. That is a GLBA Safeguards Rule access-control gap (16 CFR 314.4(c)(1)) and a PCI DSS v4.0 Requirement 7 finding waiting for an audit.

BankVault removes the standing grant. An underwriter who needs a credit report asks for it, proves the login is fresh, gets 30 minutes scoped to that one object, and loses it automatically when PAM expires the grant. Nobody holds a key while they are not using it, and the whole exchange is a row in a ledger before access is live.

## Architecture

**Solid lines are enforcement. Dashed lines are advisory or detection.** The distinction matters here: the privilege path does not run through this repo's code. PAM grants privileges to the calling principal, so the underwriter requests their own grant, and the broker sits beside that path rather than in front of it ([ADR-006](docs/adr/006-who-requests-the-grant.md)).

```mermaid
flowchart TD
    UW["<b>Underwriter</b><br/>no standing access"]

    subgraph IDENTITY["Identity plane — enforced by the platform"]
        ACM["<b>Access Context Manager</b><br/>reauth binding on underwriter group<br/><b>session length 1h</b> — platform minimum<br/>covers the whole GCP session;<br/>PAM is not independently targetable<br/><i>documented, NOT in terraform/ — see What this isn't</i>"]
    end

    subgraph PREFLIGHT["request_broker — pre-flight gate, NOT a chokepoint"]
        BR["<b>request_broker</b><br/>Cloud Function v2 · HTTP · Python 3.12"]
        MFA["verify_identity()<br/>verify OIDC token (sig/iss/aud/exp), bind identity;<br/>reject if now − auth_time > <b>900s</b><br/>evidence + early rejection, not enforcement"]
        VAL["validate_request()<br/>domain · SoD requester ≠ approver<br/>duration cap · known application_id"]
        LW["write_ledger_row()<br/><b>REQUEST</b> or <b>DENY</b> — never GRANT"]
    end

    subgraph PAM["GCP Privileged Access Manager — one entitlement per application"]
        ENT["<b>bankvault-credit-report-{app-id}</b><br/>eligible_users = underwriter group<br/>approval: 1 approver + justification"]
        COND["roles/storage.objectViewer<br/>+ IAM Condition (CEL), static per entitlement<br/>resource.name.startsWith(…/objects/APP_ID/)<br/><b>max_request_duration 1800s</b> — PAM expires it"]
    end

    BKT["<b>credit-reports</b> — GCS<br/>uniform access · versioned<br/>public access prevention enforced"]

    subgraph AUDIT["Audit and reconciliation — detection only"]
        SCH["Cloud Scheduler<br/>*/15 * * * *"]
        REC["<b>reconcile</b> — Cloud Function v2<br/>viewer-only · detects overruns<br/><b>never revokes</b> · ADR-005"]
        BQ["BigQuery <b>access_grants</b><br/>append-only ledger"]
        PLOG["BigQuery <b>bankvault_platform_logs</b><br/>independent log-sink export<br/>survives an application-code bug"]
    end

    UW -->|"1 · authenticate"| ACM
    ACM -->|"2 · session gated at 1h"| UW
    UW -.->|"3 · POST /request (optional pre-flight)"| BR
    BR --> MFA --> VAL --> LW
    LW -.->|"4 · REQUEST row + entitlement name returned"| UW
    UW ==>|"5 · grants.create — AS THEMSELVES"| ENT
    ENT ==>|"6 · on approval"| COND
    COND ==>|"7 · time-bound conditional binding"| BKT
    COND -.->|"auto-expires at 1800s, binding removed<br/>no revoke code in this repo · ADR-001"| BKT

    SCH --> REC
    REC -.->|"cross-check ledger vs live PAM state"| ENT
    REC -.->|"EXPIRE_FLAG / BYPASS_FLAG row + structured alert"| BQ
    LW --> BQ
    ENT -.->|"PAM admin-activity audit logs"| PLOG
    BR -.-> PLOG

    classDef enforce fill:#e8f0fe,stroke:#4285f4,color:#111
    classDef detect fill:#fce8e6,stroke:#ea4335,color:#111
    classDef store fill:#e6f4ea,stroke:#34a853,color:#111
    classDef idp fill:#f3e8fd,stroke:#9334e6,color:#111
    classDef pam fill:#fef7e0,stroke:#f9ab00,color:#111
    class UW,ACM idp
    class BR,MFA,VAL,LW enforce
    class ENT,COND pam
    class SCH,REC detect
    class BKT,BQ,PLOG store
```

Read edge 5 carefully — it is the whole point. The underwriter calls PAM directly, because PAM elevates the caller and there is no on-behalf-of parameter. A broker in that path would elevate its own service account and create exactly the standing access this project removes.

**Two freshness numbers, and only one of them is enforcement.** ACM enforces a one-hour session bound, which is the platform floor. The broker rejects anything staler than fifteen minutes and records the gating `auth_time` in the ledger. So the evidence is tighter than the enforcement, and an underwriter who skips the broker still faces the one-hour bound. Claiming fifteen-minute enforcement would be claiming a control that does not exist.

Full field-level walkthrough: [`docs/architecture.md`](docs/architecture.md).

## What changed from the first cut (and why the code is smaller)

The code is smaller than it was because the project reversed itself twice. Both reversals are recorded, and in both cases the trigger was written down before it fired.

**Reversal 1 — build vs. buy ([ADR-001](docs/adr/001-build-vs-buy-jit-broker.md)).** The first version was a custom broker: one function applied a conditional IAM binding, a second ran on a schedule to strip it. ADR-001 named the exact condition that would make that wrong: *Google ships a managed grant lifecycle that does this natively.* That condition fired. PAM reached GA with time-bound grants, an approval workflow, and IAM-Condition support on the granted role. The custom `revoke_access` function existed only to undo something PAM now undoes itself, so it was deleted rather than defended.

**Reversal 2 — who requests the grant ([ADR-006](docs/adr/006-who-requests-the-grant.md)).** What survived Reversal 1 was a broker that verified login freshness and then called `grants.create` on the underwriter's behalf. That seam carried a note saying the grantee semantics had to be verified before deploy. Verifying it killed the design: PAM attaches a grant's privileges to the **calling principal**, and `CreateGrant` has no grantee or on-behalf-of parameter. A broker-mediated grant would have elevated the broker's own service account — an always-on, never-reviewed identity holding read access to borrower credit reports. That is worse than the standing access the project exists to remove, because a transferred underwriter at least shows up in a quarterly review and a service account does not.

So the broker stopped creating grants. The underwriter requests their own, and the broker kept the two jobs it can actually do: rejecting bad requests before they reach PAM, and recording the `auth_time` that gated each one. Enforcement of login recency moved to an Access Context Manager reauth binding, where it costs precision — one hour enforced instead of fifteen minutes claimed.

Neither reversal is an embarrassment in the project. They are the project. A design that has never been falsified by contact with a platform's actual semantics has usually not been checked against them.

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
│   ├── request_broker/main.py     # MFA-freshness gate + validation + ledger write (no grant creation, ADR-006)
│   └── reconcile/main.py          # detect-only overrun sweep
├── tests/                         # pytest, all GCP + IdP clients mocked, no network
├── scripts/run-local.sh           # serve either function via functions-framework
├── docs/
│   ├── index.md
│   ├── architecture.md
│   ├── controls-mapping.md        # GLBA / PCI DSS v4.0 / SOX 404 / FFIEC → specific resources
│   ├── BREAK_GLASS.md             # what happens when PAM or the IdP is down; why nothing is implemented
│   ├── SESSION_RECORDING.md       # object-read logging is present; session recording is not
│   └── adr/001..006
├── COST_ESTIMATE.md               # idle floor, per-request cost, and the term that can surprise you
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
# With no IdP configured locally, verify_identity is fail-closed: the request is denied
# before any PAM call. Point OIDC_ISSUER / OIDC_AUDIENCE / OIDC_JWKS_URI at a real
# provider (and pass a genuine id_token) to authenticate for real.
curl -s localhost:8080 -H "Content-Type: application/json" -d '{
  "id_token":"<OIDC id_token from your IdP>",
  "requested_by":"underwriter@lender.example.com",
  "approved_by":"lead@lender.example.com",
  "application_id":"APP-1001",
  "justification":"manual QC review"
}' | python -m json.tool
# -> {"status": "denied", "reason": "identity verification is not configured ..."}
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

Five claims in this repo are narrower than they look, and all five are stated on purpose.

**The broker is not a chokepoint.** It is a pre-flight gate you can skip. The underwriter must be the eligible principal on the PAM entitlement, so the PAM request path is open to them by construction. A control that is bypassed by not calling it is not enforcement, and this repo does not describe it as one (ADR-006). What it does *not* cost you: every check the broker runs is also enforced by the platform on the bypass path — PAM refuses self-approval ("you can't approve your own request"), caps the grant at `max_request_duration`, and restricts eligibility to the entitlement's `eligible_users`; ACM enforces login recency. So skipping the broker forfeits *evidence granularity* — the 900-second `auth_time` row — not a control. The design degrades to weaker evidence, never to weaker enforcement.

**"Append-only" is a discipline, not a BigQuery guarantee.** The `access_grants` ledger is append-only because the broker only inserts rows and no principal is granted delete/update on it — not because BigQuery makes it immutable. BigQuery IAM has no insert-only permission: `bigquery.tables.updateData` covers insert, update, and delete alike, so append-only *cannot* be expressed as an IAM boundary. It is a code-path-and-least-privilege invariant, backed by the independent platform-log export as the tamper-evidence layer. Genuine immutability lives in a WORM store, and [`terraform/logging.tf`](terraform/logging.tf) now defines one — a second sink writes the same log stream to a retention-locked GCS bucket, the immutable copy *alongside* the queryable BigQuery export. Keep the line exact: the BigQuery ledger stays append-only-by-convention; the WORM bucket is where immutability is actually delivered.

**Enforced login recency is one hour, not fifteen minutes.** Access Context Manager's `--session-length` accepts `0s` or 1h–24h and nothing between, so one hour is the platform floor rather than a design choice. The fifteen-minute broker check is early rejection and ledger evidence. It also costs more than it looks: `scopedAccessSettings` targets applications by OAuth `clientId` — "Cloud Console", "Google Cloud SDK" — but PAM has no distinct `clientId` of its own; it is reached *through* the SDK or the REST API. So the reauth binding can be scoped to the SDK (which does gate `gcloud pam grants create`), but not to the credit-report path alone, and the requirement lands on the underwriter group's entire Google Cloud session. Everyone in that group reauthenticates hourly for everything. The only path a console/SDK-scoped binding may not reach is a raw REST call bearing a user token outside the SDK; the unnarrowed binding closes that by covering the whole session.

**Availability is bounded by the identity provider — at the reauth layer, not the broker.** The enforced dependency is ACM: if the IdP is unreachable, the underwriter cannot complete the hourly reauthentication, so no fresh session exists and the PAM request path is closed. The broker's own IdP-denial is the *same* dependency showing up on the skippable pre-flight path, not a second control. A loan decision with an SLA does not stop having one because the IdP is down. That trade is deliberate: an identity control that keeps granting when it cannot verify who is asking has a bypass, and the bypass opens under exactly the conditions an attacker wants. (ADR-004.)

**Reconciliation detects an overrun. It does not contain one.** The honest sentence is "detected within roughly one reconcile interval," not "contained within." PAM owns the actual expiry; the reconcile job is a completeness and anomaly check, not a second enforcement path. (ADR-005.)

## What this isn't

- **Not a real lender.** No core system, no real borrower data, no real underwriting workflow. It is a portfolio-grade demonstration of the JIT-access pattern on a plausible lending use case.
- **Not wired to a real IdP.** Workforce Identity Federation is the documented identity plane (ADR-002), but no live SAML/OIDC provider is connected. `verify_identity` performs full OIDC verification — RS256 signature against the IdP JWKS, plus issuer, audience, and expiry — and binds the request to the verified identity claim rather than a self-asserted `requested_by`. It is **fail-closed**: with the `OIDC_ISSUER` / `OIDC_AUDIENCE` / `OIDC_JWKS_URI` env vars unset (as they are here, with no IdP connected), every request is denied. Wiring the JWKS endpoint to a live IdP is the remaining deployment step, not a code stub.
- **The ACM reauth binding is documented, not provisioned.** The architecture diagram draws it as the enforcement layer because that is where enforcement belongs after ADR-006, but there is no `google_access_context_manager_*` resource in `terraform/`. It is an organization-level control that needs an access policy this project does not own. Until it is applied, the enforced-recency claim is a design position, not a deployed control — and the broker's 900s check is the only freshness logic actually present in this repo.
- **Not deployed.** Verified with `fmt` / `validate` / `pytest`. `terraform apply` is left to whoever has credentials.
- **Not production-hardened.** No VPC Service Controls, no CMEK by default, no DLP content inspection, no alerting pipeline beyond the structured log the reconcile job emits. These are reasonable next steps, listed in [`docs/architecture.md`](docs/architecture.md), not gaps hidden under the demo.
