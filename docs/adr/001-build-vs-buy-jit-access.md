# ADR-001: Build vs. Buy — Custom JIT Broker vs. Off-the-Shelf PAM

**Date:** 2026-07-01
**Status:** Superseded in part by ADR-005 (2026-07-08)
**Authors:** Lanre Oluokun
**Implementation:** Grant-issuance mechanism superseded; audit-ledger and enforcement-primitive decisions still in force

---

## Supersession Note (2026-07-08)

**What still stands.** The build-vs-buy conclusion in this ADR holds: an off-the-shelf PAM platform (CyberArk, Delinea, BeyondTrust) remains the wrong mechanism for fine-grained, CEL-conditioned, resource-scoped GCP IAM grants, and BankVault's audit ledger should feed the bank's existing PAM/SIEM rather than attempt to replace it.

**What does not stand.** The *grant-issuance mechanism* chosen here is superseded. This ADR selected a custom Cloud Functions broker applying IAM Conditions directly, and listed GCP's native Privileged Access Manager under Alternatives Considered as Preview-stage, with the explicit note that "a real production decision should re-evaluate against GCP PAM once it's GA."

That condition was met. GCP PAM reached GA, and [ADR-005](005-pam-grant-revocation-lifecycle.md) re-evaluates against it and adopts it: PAM now issues the grant via a project-level entitlement (`maxRequestDuration = 1800s`), and the custom Cloud Function grant/revoke layer this ADR selected is rejected there on the grounds that it reimplements a lifecycle GCP now manages natively.

**Trade-off accepted in reversing.** Reversing a decision one week after making it costs credibility if the reversal is unprincipled. It is not unprincipled here: this ADR named the exact trigger condition ("once it's GA") and that condition fired. The alternative — holding to a custom lifecycle out of consistency with a decision made under different product availability — would have meant maintaining code whose only remaining justification was that it had already been written. That is a worse failure than a documented reversal.

**The cost of the reversal, stated plainly.** Adopting GA PAM trades control for maintenance burden. The custom broker would have given full control over revocation triggers, including revocation paths PAM does not expose. GCP PAM's behavior on a missed auto-expiry is undocumented — a gap ADR-005 mitigates with a detective-only reconciliation job, not a preventive control. Building custom would have avoided that specific unknown at the cost of owning the entire grant lifecycle. That trade was made deliberately, and the residual detection-vs-containment gap is documented in ADR-005's Residual Risk section rather than being absorbed silently.

**Precise boundary of what is superseded:**

| Section of this ADR | Status |
|---|---|
| Decision — "build a custom Cloud Functions broker" | **Superseded** by ADR-005 (PAM entitlement issues the grant) |
| Decision — "recommend the audit ledger feed the bank's existing PAM/SIEM" | **In force** |
| Rationale — IAM Conditions as the enforcement primitive | **In force** (static CEL binding in ADR-005 scopes access to the single credit-report object) |
| Rationale — vendor PAM is a poor fit for resource-scoped cloud IAM grants | **In force** |
| Consequences — "no vendor support contract" / "custom code carries custom risk" | **Narrowed.** Now applies only to the broker's request-validation layer (`main.py`), not to the grant lifecycle |
| Consequences — audit ledger in plain BigQuery | **In force** |
| Alternatives — GCP-native PAM "Preview, re-evaluate at GA" | **Resolved.** Re-evaluated at GA; adopted in ADR-005 |

Read this ADR as the record of *why not enterprise PAM*. Read ADR-005 as the record of *how the grant lifecycle is actually issued*.

---

## Context

The loan origination pipeline needs just-in-time privilege elevation: a loan officer should never hold standing read access to the customer PII bucket, only a time-bound grant scoped to the application they're processing. Two paths exist to deliver this on GCP:

- **Build** — a custom broker (the Cloud Functions in this repo) that applies and revokes native GCP IAM conditions directly.
- **Buy** — an established Privileged Access Management (PAM) platform (CyberArk, Delinea/Thycotic, BeyondTrust) configured with a GCP connector to broker the same grants.

Banks default to buying PAM for a reason: it's the category regulators expect to see, and most already have an enterprise PAM deployment covering on-prem AD and jump-host access. The question is whether that same platform is the right mechanism for cloud-native, resource-level IAM grants, or whether it's solving a different problem.

---

## Decision

Build a custom Cloud Functions broker for GCP resource-level JIT grants, using native IAM Conditions as the enforcement primitive. Recommend that BankVault's audit ledger be fed into whatever enterprise PAM/SIEM the bank already runs, rather than positioning this as a PAM replacement.

> **Superseded in part.** The grant-issuance half of this decision was replaced by ADR-005 when GCP PAM reached GA. IAM Conditions remain the enforcement primitive; the audit-ledger recommendation is unchanged. See the Supersession Note above.

---

## Rationale

| Dimension | Custom Cloud Function (build) | Off-the-shelf PAM (buy) |
|---|---|---|
| **Cost model** | Pay-per-invocation serverless — the Week 1 scope runs comfortably inside GCP's free tier | Per-seat or per-vaulted-account licensing; CyberArk/Delinea enterprise tiers commonly run five to six figures annually before implementation services |
| **GCP IAM Conditions support** | First-class — CEL expressions are the native GCP primitive, applied directly via the Storage/IAM API | Bolt-on — most PAM platforms broker *credentials* (vault a service account key, check it out, check it back in); native support for GCP's CEL-based conditional bindings is immature or absent in several major platforms as of this writing |
| **Time-to-value** | Days — one Terraform apply plus two functions, as built in this repo | Weeks to months — PAM onboarding typically includes vault architecture, connector configuration, and a change-management cycle before the first policy goes live |
| **On-prem dependency** | None — fully serverless, no vault appliance, no jump host | Many PAM deployments still route through an on-prem or self-hosted vault cluster for session brokering, even when the target resource is cloud-native |
| **Cloud-native fit** | Grants map 1:1 onto GCP's own access-control model (IAM bindings, conditions, service accounts) — nothing to keep in sync with a separate PAM data model | PAM's core abstraction (vaulted credential + checkout session) fits infrastructure and OS-level access better than fine-grained, resource-scoped cloud IAM bindings |
| **Audit trail ownership** | Ledger lives in BigQuery, queryable with SQL, exportable anywhere | Audit lives inside the PAM platform's proprietary reporting layer; extracting it into a bank's existing SIEM/GRC tooling is a separate integration project |
| **Operational surface** | Two functions, one bucket, one topic, one scheduled job — small enough for one team to own end-to-end | A PAM platform is infrastructure in its own right: HA vault cluster, connector fleet, its own patching and DR posture |

### Why buy still matters here

This isn't an argument that PAM platforms are wrong for banks — they're the correct tool for what they're built for: broker of shared/service credentials, session recording for privileged interactive access (RDP/SSH to servers), and a single control plane across heterogeneous on-prem and multi-cloud estates.

A bank that already owns CyberArk for its Windows admin accounts and on-prem database credentials should not stand up a second, disconnected access-governance system for GCP. The realistic Week 1+ path is: keep the broker for what native cloud IAM does better (fine-grained, resource-scoped, CEL-conditioned grants), and route this repo's BigQuery audit ledger into the existing PAM/SIEM as a downstream sink, so examiners see one consolidated access story rather than two.

> This recommendation survives supersession unchanged. Under ADR-005, the grant is issued by GCP PAM rather than a custom function — but it is still a *second* access-governance surface from the bank's point of view, and the ledger-unification recommendation applies with equal force.

---

## Consequences

### Positive

- Zero licensing cost; infrastructure cost stays inside GCP's serverless free tiers at the volumes a single loan-origination team would generate.
- Every grant is a native GCP IAM binding — nothing to reconcile against a second system's idea of "who has access."
- The audit ledger is plain BigQuery, so it's queryable by any tool the bank already uses for GRC reporting, with no proprietary export format.
- Fast to extend: adding a second protected resource is a Terraform module plus one more resource field in the request payload, not a PAM policy change ticket.

### Negative

- **No vendor support contract** — bugs in the broker are the team's problem, not a vendor's SLA. *(Narrowed by ADR-005: the grant lifecycle is now GCP-managed. This consequence now applies only to the broker's request-validation layer.)*
- **No built-in session recording, keystroke logging, or interactive session brokering** — this system grants API/data access, not shell/RDP sessions, and would not replace PAM for infrastructure admin access. *(Unchanged by supersession.)*
- **Duplicate governance surface risk** — if the bank already runs enterprise PAM, a second, disconnected access system is itself an audit finding unless the ledgers are unified. *(Unchanged by supersession.)*
- **Custom code carries custom risk** — every validation rule (segregation of duties, duration caps) is something this team wrote and must maintain correctly, versus inheriting a vendor's already-audited policy engine. *(Narrowed by ADR-005: duration caps are now enforced by PAM's `maxRequestDuration`, not by custom code. Identity and freshness validation in `main.py` remain custom, and remain this team's risk — see ADR-004.)*

---

## Alternatives Considered

### CyberArk / Delinea PAM with GCP connector

**Rejected for this scope.** Realistic for infrastructure-level access (VM SSH, Cloud SQL admin credentials) but a poor fit for fine-grained, per-object GCS grants scoped to a single loan application — the CEL condition model this repo relies on isn't something these platforms broker natively.

*Trade-off acknowledged:* this rejection forgoes a vendor-audited policy engine, vendor support, and the regulatory familiarity examiners have with the category. Those are real losses. They are accepted because the mechanism mismatch is fundamental, not a configuration problem — a credential-vaulting abstraction cannot express "read this one object for the next 30 minutes."

### GCP-native Privileged Access Manager (PAM)

**Originally deferred; subsequently adopted.** Google's own IAM-integrated PAM product (Preview at time of writing) solves a similar problem — time-bound entitlement grants with an approval workflow — and would likely obsolete parts of this repo's `grant_access` function if adopted. Not used at the time of this ADR because Week 1 scope was explicitly about demonstrating the underlying IAM Conditions mechanism directly; the ADR recorded that a real production decision should re-evaluate against GCP PAM once it reached GA.

> **Resolved 2026-07-08.** PAM reached GA. ADR-005 re-evaluated and adopted it. The custom grant/revoke layer is no longer the mechanism. See the Supersession Note.

### Do nothing — standing IAM roles with periodic access reviews

**Rejected.** The status quo at many banks. It fails the Safeguards Rule's access-limitation requirement between review cycles: [16 CFR 314.4(c)(1)(ii)](https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-314) requires limiting authorized users' access to only the customer information they need to perform their duties, which a quarterly review cycle cannot satisfy. A departed or reassigned loan officer can retain read access to NPI for up to three months — the exact anti-pattern this system exists to close.

> *Citation note (2026-07-08):* this rejection originally cited PCI DSS 7.2. That was the wrong regime. [ADR-003](003-scope-and-actor-definition.md) fixes the institution type as a **non-bank mortgage lender under FTC jurisdiction**, making the GLBA Safeguards Rule the applicable instrument. PCI DSS applicability to this flow was never verified and is not claimed. The underlying argument is unchanged; only the citation is corrected.

---

## Related

- [ADR-003: Scope and Actor Definition](003-scope-and-actor-definition.md) — fixes the actor/resource pair and the GLBA basis
- [ADR-004: MFA Freshness as the Zero Trust Signal](004-mfa-freshness-zero-trust-signal.md) — gates the grant request
- [ADR-005: PAM Grant/Revocation Lifecycle](005-pam-grant-revocation-lifecycle.md) — **supersedes the grant-issuance decision in this ADR**
