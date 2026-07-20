# BankVault: technical deep-dive defense pack

**Status gate: cleared 2026-07-20.** ADR-006 is committed, `_create_pam_grant` is gone from `functions/request_broker/main.py`, and `test_broker_has_no_grant_creation_path` fails if it returns. The code and this document now agree.

**One correction since this was drafted.** The original draft said freshness enforcement "lives in" an Access Context Manager reauth policy without naming a number. Checking the docs: `--session-length` accepts `0s` or 1h–24h and nothing between, so **enforced recency is one hour, not fifteen minutes**, and PAM is not independently targetable via `scopedAccessSettings`, so the binding covers the group's whole Google Cloud session. Both facts are in ADR-006. If you say "fifteen-minute enforced freshness" in a room, you are overclaiming a control the platform cannot deliver. The true sentence is: *enforcement is one hour at the platform, evidence is fifteen minutes in the ledger.*

---

## 1. The 90-second opener

Use this when asked "walk me through a project."

> BankVault is a just-in-time access pattern for a mock mortgage lender. The problem: at most lenders, an underwriter's access to borrower credit reports is standing. It's granted by role and reviewed quarterly. That means a transferred or terminated underwriter can keep read access to SSNs, income docs, and full credit files for up to a quarter, with nobody actively deciding they should have it today. That's a GLBA Safeguards Rule access-control gap.
>
> BankVault removes the standing grant. There's no role that carries credit-report read. An underwriter requests access to one specific application's file, a lead approves, and Google Cloud Privileged Access Manager issues a grant scoped by IAM Condition to that one object prefix, capped at thirty minutes, and expires it automatically. Every request, granted or denied, is a row in an append-only BigQuery ledger before access goes live.
>
> What I'd actually want to talk about is the reversals. The project reversed its own architecture twice, and both reversals are documented as ADRs with the trigger condition written down before it fired.

Then stop. Let them pick the thread.

---

## 2. Architecture, component by component

Know why each piece exists, not just what it does. The "why" is where deep dives live.

| Component | What it does | Why it exists / why this and not something else |
|---|---|---|
| **PAM entitlement** (`terraform/pam.tf`), one per demo application | Defines who may request (`eligible_users` = underwriter group), who approves, max duration, and the IAM Condition pinning the granted role to one object prefix | PAM owns the grant lifecycle natively: request, approval, time-bound activation, auto-expiry. Building that was the original design. ADR-001 named the condition under which building would be wrong, and it fired. |
| **IAM Condition** `resource.name.startsWith("projects/_/buckets/<bucket>/objects/<APP-ID>/")` | Object-scope pin | A grant issued for APP-1001 cannot read APP-1002's file. The literal `_` is the required GCS CEL resource-name format, not a placeholder. |
| **Access Context Manager reauth binding**, session length **1h** | Forces reauthentication on the underwriter group's Google Cloud session | This is where MFA-freshness enforcement actually lives, because a grant's privileges attach to the calling identity and no intermediary can sit in the grant path. One hour is the platform floor, not a choice. It covers the group's whole GCP session because PAM is not targetable via `scopedAccessSettings`. (ADR-006.) |
| **`request_broker`** (Cloud Function v2, Python 3.12) | Verifies token freshness, validates the request shape, writes the ledger row. **Does not create grants.** | It is a pre-flight gate and the auditable record of why each request was permitted. It records the `auth_time` that gated the request, something the platform reauth control enforces but does not surface per request. |
| **BigQuery `access_grants` ledger** | Append-only record: REQUEST / GRANT / DENY / EXPIRE_FLAG | Denials matter as much as grants. A denial with a reason is the evidence that the control fired. |
| **Log sink to `bankvault_platform_logs`** | Independent export of function logs and PAM admin-activity audit logs | The application ledger can be wrong if the application has a bug. The platform export cannot be edited by application code. Two independent records is the point. |
| **`reconcile`** (Pub/Sub, `*/15`) | Finds GRANT rows past `window_end` with no close-out row, cross-checks PAM grant state, writes EXPIRE_FLAG and alerts | It **detects** an overrun. It does not contain one. PAM owns expiry, and a second enforcement path would be a second thing that can be wrong. (ADR-005.) |
| **GCS bucket** | Uniform bucket-level access, versioned, public access prevention enforced | Uniform access is required, because object ACLs would let a per-object ACL silently bypass the IAM Condition. |

---

## 3. The two reversals, your strongest material

Most portfolio projects show a design. This one shows judgment under new information. Lead with it.

### Reversal 1: ADR-001, build vs. buy

The first cut was a custom broker: one function applied a conditional IAM binding, a second stripped it on a schedule. ADR-001 wrote down the exact condition that would make that wrong: *Google ships a managed grant lifecycle that does this natively.* PAM reached GA with time-bound grants, an approval workflow, and IAM-Condition support. The custom `revoke_access` function existed only to undo something PAM now undoes itself, so it was deleted rather than defended.

**Say this:** "The ADR was written so the trigger was legible before it fired. That's the part I'd want you to look at. Not that I picked right the first time, but that I wrote down what would make me wrong."

### Reversal 2: ADR-006, who requests the grant

The design assumed the broker could sit in front of PAM: verify freshness, then mint the grant on the underwriter's behalf. Reading the PAM grant model closed that off. Google's documentation is explicit: when a group is a requester on an entitlement, every member can request a grant, but **only the individual account that requests the grant receives the elevated privileges.** There is no grantee or on-behalf-of field on `CreateGrant`. Privileges attach to the caller.

So a broker-mediated design would have granted credit-report read to a shared, always-on service account. That inverts the entire thesis of the project.

**Say this:** "The broker-mediated design would have created exactly the standing access the project exists to remove, held by a service account instead of a person, which is worse, because nobody reviews a service account quarterly. Freshness moved to the platform layer PAM does respect, and the broker kept the job it can actually do: recording why each request was allowed."

This is the answer to "tell me about a time you were wrong." It's also the answer to "how do you validate assumptions?" You read the platform's grant model instead of assuming it works like every other API.

---

## 4. Killer questions, with answers

Rehearse these. The first four are the ones that end interviews if you fumble them.

**Q: What stops the underwriter from bypassing your broker and calling PAM directly?**
Nothing at the application layer, and that's why the freshness control can't live in the broker. The underwriter is the eligible principal on the entitlement. They *have* to be, because PAM grants privileges to the caller. So freshness is enforced by an Access Context Manager reauthentication policy on the access level covering the PAM request path. The broker is a pre-flight gate and the per-request audit record, not a chokepoint. Claiming otherwise would be claiming a control I don't have.

**Q: If PAM does approval, scoping, and expiry, what does your code actually add?**
Three things PAM doesn't do. First, a per-request record of the `auth_time` that gated the request. ACM enforces recency but doesn't write it into a queryable ledger tied to a specific credit-report read. Second, request-shape validation: domain, justification-required, duration cap, application-id membership. Third, denials. PAM logs grants. The ledger logs the requests that never became grants, which is the evidence an examiner asks for when they want to know whether the control ever fired.

**Q: Why MFA freshness instead of session validity?**
A valid session says this person authenticated at some point in the allowed window. It doesn't say they're at the keyboard now. Between a morning login and an afternoon credit-report read sits an unlocked laptop, a hijacked session, a token lifted off a compromised host. For a normal read, session validity is a reasonable bar. For a privileged read of consumer financial data, recency is the more useful signal.

**Q: Why isn't freshness just an IAM Condition on the entitlement?**
Because IAM Conditions have no authentication-recency attribute. They expose request time, resource attributes, and similar, but not "how recently did this principal complete MFA." Asserting a CEL clause for it would be fabricating a capability. That's why the enforcement has to sit at a layer that can see the authentication event.

**Q: One entitlement per loan application doesn't scale. What happens at 10,000 applications?**
Correct, and it's a documented limitation, not something I'd defend. It's a consequence of the IAM Condition being static per entitlement. The condition string is fixed at entitlement creation, so per-object scope forces per-object entitlements. Two paths out: check whether `CreateGrant`'s optional requested-resource scoping reaches object granularity, which would collapse this to one entitlement; or move the scope boundary up from per-application to per-portfolio or per-branch and accept coarser blast radius in exchange for a manageable entitlement count. I'd want production access patterns before picking.

**Q: How do you know `approved_by` in your ledger is real?**
In the current build, I don't. It's a field in the request body, so the ledger column is a *claimed* approver. The real approval evidence is PAM's approval workflow and its admin-activity audit logs, which are exported to the platform-log dataset. That's what the SOX mapping should point at, not the application ledger field. It's the kind of thing that looks fine until an auditor asks "who attests to this column."

**Q: What's the blast radius if the broker service account is compromised?**
Small, by design and by accident of ADR-006. The broker has PAM viewer and BigQuery jobUser. It cannot create a grant, cannot read the credit-reports bucket, and cannot delete ledger rows. The worst case is falsified or suppressed ledger entries, which is exactly why the platform log export exists as an independent record that application code cannot touch.

**Q: Your ledger is "append-only." Enforced how?**
By the write path and the SA's permissions, not by a BigQuery feature. BigQuery tables aren't immutable by default. The honest statement is "append-only by convention and least privilege, with an independent platform-log export as the tamper-evidence layer." If you needed genuine immutability you'd add a table-level retention policy or write to a WORM-backed sink. I'd flag that as the next hardening step rather than claim it's already there.

**Q: What happens when the identity provider is down?**
Access is denied. That's deliberate and it has a real cost. A loan decision with an SLA doesn't stop having one because Okta is down. I took the trade because an identity control that keeps granting when it can't verify who's asking has a bypass, and the bypass opens under exactly the conditions an attacker wants: the IdP degraded, checks failing open, nobody watching. If a specific SLA can't tolerate it, the answer is a documented, alerted break-glass path, not a control that quietly fails open.

**Q: Why does reconcile only detect and not revoke?**
Because PAM owns expiry, and a second thing that revokes access is a second thing that can revoke it wrongly. Reconcile is a completeness check: if a grant is past its window and PAM still reports it active, that's a platform-level anomaly worth an alert, not something my code should race to fix. The precise claim is "detected within roughly one reconcile interval," not "contained within." Those are different sentences and I only get to say the first one.

**Q: Why GCS objects rather than a database row?**
Because object-prefix scoping is where the IAM Condition actually has purchase. A row-level equivalent would need the database's own authorization layer, and then IAM is no longer the enforcement point. Choosing the resource where the platform's native control is strongest was deliberate (ADR-003).

**Q: How is this different from short-lived credentials or `gcloud auth print-access-token`?**
Short-lived credentials shorten the window on privileges you already hold. This removes the privilege until it's requested, approved, and scoped to one object. Different control: one bounds exposure time on standing access, the other eliminates the standing access.

**Q: How did you test any of this without deploying?**
`terraform fmt`, `init -backend=false`, and `validate` for the configuration; pytest with every GCP client mocked for the Python. That verifies logic and syntax, not behavior against live GCP. I've been explicit in the README that this is a reference architecture, not a deployed system, and the untested boundary is the PAM API call itself. I'd rather say that than let someone assume I've run it in production.

**Q: What's the weakest part?**
Two things. The signature-verification stub: the broker reads a token's `auth_time` claim without verifying the signature against a live JWKS endpoint, so in this build the freshness claim is only as trustworthy as the caller. And the entitlement-per-application scaling ceiling. Both are in the README under "What this isn't," because a reviewer finding them there thinks differently about me than a reviewer finding them in the code.

---

## 5. Compliance mapping: where to be careful

The mapping is strong because it separates explicit from interpretive claims. Three specific exposures.

PCI DSS is your weakest framework claim. PCI scope is cardholder data and sensitive authentication data in the cardholder data environment. A borrower credit report is not cardholder data. The phrase "cardholder-adjacent PII" isn't a PCI concept and a QSA will say so. Reframe the claim at the pattern level: *"Requirement 7 defines the least-privilege access-control model; BankVault implements that model, and it would satisfy 7.2/7.3 if the protected object were in a CDE. The regulated data here is GLBA-scoped, not PCI-scoped."* That's a stronger position than the current one because you're the one naming the limit.

SOX 404 needs a scope sentence. SOX ITGCs apply where access affects financial reporting. Loan-origination read access isn't automatically in scope. Say "for a public lender where this data feeds financial reporting" rather than asserting it flatly.

GLBA is your solid ground. 16 CFR 314.4(c)(1) requires access controls limiting customer information to authorized users. A credit report is customer financial information. Lead with GLBA and treat the others as pattern applicability.

Also: after ADR-006 the mapping rows citing `request_broker/main.py` for provisioning and segregation of duties are stale. Provisioning is `pam.tf`. SoD evidence is the PAM approval workflow and its audit logs. Fix before anyone reads it.

---

## 6. Sentences you must not say

- "It's deployed." It isn't. `terraform validate` and pytest are not deployment.
- "It's production-ready." No VPC Service Controls, no CMEK, no DLP, no alerting pipeline.
- "It verifies the token." It decodes claims. Signature verification is a stub.
- "Reconcile contains overruns." It detects them.
- "The bank has zero-trust access." One flow, one actor, one data class. ADR-003 exists precisely so you say the narrow thing.
- "I built a PAM broker." After ADR-006 you built a pre-flight gate and an audit ledger. The smaller claim is the true one and it survives follow-up questions.

---

## 7. Pre-interview checklist

Do not schedule the deep dive until these are true:

- [x] `_create_pam_grant` removed from `request_broker`; ADR-006 committed
- [x] README corrected: stale `300s` gone, mermaid diagram drawn from the actual Terraform, enforcement/evidence split stated
- [x] Controls mapping updated for ADR-006 (periodic-review, provisioning, SoD rows repointed at `pam.tf` and the PAM audit-log export)
- [x] Project `CLAUDE.md` updated so a future agent does not "helpfully" restore grant creation
- [ ] `auth_time` body branch deleted from `_extract_auth_time`; `id_token` required
- [ ] `requested_by` derived from token claims
- [ ] `_verify_signature()` present as an explicit `NotImplementedError` seam
- [ ] demo curl in README uses `id_token` rather than a raw `auth_time`
- [ ] `approved_by` renamed `claimed_approver`; SOX mapping repointed to PAM audit logs
- [ ] ACM reauth binding expressed in Terraform (currently documented only, not provisioned)
- [ ] PCI section reframed at pattern level
- [ ] Terraform `validation` block enforcing `approver_group != underwriter_group`
- [ ] Invoker IAM binding present in Terraform
- [ ] `checkov` and `gitleaks` in CI

The last three are ten minutes each. The first six are the interview.
