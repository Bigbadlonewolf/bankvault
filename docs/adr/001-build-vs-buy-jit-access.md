# ADR-001: Build vs. Buy — Custom JIT Broker vs. Off-the-Shelf PAM

**Date**: 2026-07-01
**Status**: Accepted
**Authors**: Lanre Oluokun

## Context

The loan origination pipeline needs just-in-time privilege elevation: a loan officer should never hold standing read access to the customer PII bucket, only a time-bound grant scoped to the application they're processing. Two paths exist to deliver this on GCP:

1. **Build** — a custom broker (the Cloud Functions in this repo) that applies and revokes native GCP IAM conditions directly.
2. **Buy** — an established Privileged Access Management (PAM) platform (CyberArk, Delinea/Thycotic, BeyondTrust) configured with a GCP connector to broker the same grants.

Banks default to buying PAM for a reason: it's the category regulators expect to see, and most already have an enterprise PAM deployment covering on-prem AD and jump-host access. The question is whether that same platform is the right mechanism for *cloud-native, resource-level* IAM grants, or whether it's solving a different problem.

## Decision

**Build a custom Cloud Functions broker for GCP resource-level JIT grants**, using native IAM Conditions as the enforcement primitive. Recommend that BankVault's audit ledger be fed into whatever enterprise PAM/SIEM the bank already runs, rather than positioning this as a PAM replacement.

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

This isn't an argument that PAM platforms are wrong for banks — they're the correct tool for what they're built for: broker of shared/service credentials, session recording for privileged interactive access (RDP/SSH to servers), and a single control plane across heterogeneous on-prem and multi-cloud estates. A bank that already owns CyberArk for its Windows admin accounts and on-prem database credentials should not stand up a second, disconnected access-governance system for GCP. The realistic Week 1+ path is: keep the custom broker for what native cloud IAM does better (fine-grained, resource-scoped, CEL-conditioned grants), and route this repo's BigQuery audit ledger into the existing PAM/SIEM as a downstream sink, so examiners see one consolidated access story rather than two.

## Consequences

### Positive
- Zero licensing cost; infrastructure cost stays inside GCP's serverless free tiers at the volumes a single loan-origination team would generate.
- Every grant is a native GCP IAM binding — nothing to reconcile against a second system's idea of "who has access."
- The audit ledger is plain BigQuery, so it's queryable by any tool the bank already uses for GRC reporting, no proprietary export format.
- Fast to extend: adding a second protected resource is a Terraform module + one more `resource` field in the request payload, not a PAM policy change ticket.

### Negative
- No vendor support contract — bugs in the broker are the team's problem, not a vendor's SLA.
- No built-in session recording, keystroke logging, or interactive session brokering — this system grants API/data access, not shell/RDP sessions, and would not replace PAM for infrastructure admin access.
- Duplicate governance surface risk: if the bank already runs enterprise PAM, a second, disconnected access system is itself an audit finding unless the ledgers are unified (see recommendation above).
- Custom code carries custom risk: every validation rule (segregation of duties, duration caps) is something this team wrote and must maintain correctly, versus inheriting a vendor's already-audited policy engine.

## Alternatives Considered

### CyberArk / Delinea PAM with GCP connector
Rejected for this scope. Realistic for infrastructure-level access (VM SSH, Cloud SQL admin credentials) but a poor fit for fine-grained, per-object GCS grants scoped to a single loan application — the CEL condition model this repo relies on isn't something these platforms broker natively.

### GCP-native Privileged Access Manager (PAM)
Google's own IAM-integrated PAM product (Preview at time of writing) solves a similar problem — time-bound entitlement grants with an approval workflow — and would likely obsolete parts of this repo's grant_access function if adopted. Not used here because Week 1 scope is explicitly about demonstrating the underlying IAM Conditions mechanism directly; a real production decision should re-evaluate against GCP PAM once it's GA.

### Do nothing — standing IAM roles with periodic access reviews
The status quo at many banks. Rejected because it fails PCI DSS 7.2's need-to-know requirement between review cycles — a quarterly access review means a departed or reassigned loan officer can retain read access to PII for up to three months, which is the exact anti-pattern this system exists to close.
