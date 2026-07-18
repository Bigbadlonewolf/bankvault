# ADR-002: Two directories is one too many

- **Status:** Accepted
- **Date:** 2026-07-08
- **Deciders:** Lanre
- **Related:** ADR-004

## Context

BankVault needs to know who an underwriter is and which group they belong to, so PAM can decide whether they are eligible for the credit-report entitlement. The underwriters already exist in the lender's corporate identity provider (assume Okta or Entra ID). The question is how GCP learns about them.

Two paths:

1. **Workforce Identity Federation**: GCP trusts the corporate IdP directly through a workforce identity pool. Underwriters sign in with their existing corporate credentials; no Google account is created for them.
2. **Cloud Identity / Google Workspace accounts** fronted by Cloud Identity-Aware Proxy (IAP): each underwriter gets a Google identity, provisioned and de-provisioned to mirror the corporate directory.

## Decision

Use Workforce Identity Federation. Underwriters and approvers resolve through a workforce pool federated to the corporate IdP. Do not create a parallel Cloud Identity directory for them.

## Rationale

The failure mode that matters here is the leaver who does not fully leave. When an underwriter is terminated or transferred, someone disables their corporate IdP account. That is the one action the offboarding process is built around and audited against.

With federation, that single action removes their GCP eligibility too, because there is no separate Google account to forget. With a mirrored Cloud Identity directory, offboarding now depends on a *second* de-provisioning step firing correctly and on time. Every sync has a lag and a failure mode, and the failure mode here is a terminated underwriter who can still read credit reports because the mirror did not update. That is the precise gap this whole project exists to close, reintroduced one layer down.

One directory has one place to disable an account. Two directories have two, and the second one is the one nobody remembers during an incident.

## Consequences

**Positive**
- Offboarding is a single action in the system of record. No sync job sits between "fired" and "cannot read credit reports."
- No per-user Google account lifecycle to license, manage, or audit.
- Group membership (underwriter, approver) stays authoritative in the corporate IdP, where HR-driven changes already land.

**Negative**
- BankVault's availability is coupled to the IdP being reachable for federation. This is the same coupling ADR-004 accepts deliberately, so it is a consistent trade, not a new one.
- Federation configuration (attribute mapping, the workforce pool provider) is fiddlier to set up correctly than creating Google accounts, and a wrong attribute mapping fails in confusing ways.
- Some GCP surfaces have historically had gaps in workforce-identity support. Confirm PAM eligibility and the console/API request flow work with workforce identities in the target org before committing operationally.

## Alternatives considered

- **Cloud Identity mirror + IAP (option 2).** Rejected. It reintroduces the second directory and makes offboarding depend on a sync. IAP also solves a different problem (context-aware access to apps), not "who is eligible for a PAM entitlement."
- **Individual Google accounts, manually managed.** Rejected outright. Manual provisioning of privileged identities is the anti-pattern; it does not survive any headcount.

## Assumptions to verify

- Workforce Identity Federation principals can be named as eligible on a PAM entitlement in the target organization, and can complete the grant-request flow. Confirm against current PAM documentation and a test in the target org before relying on it.
