# ADR-001: Build vs. Buy, and the week I reversed it

- **Status:** Accepted, then partially reversed (see Reversal). Current: Buy the grant lifecycle (GCP PAM), build only the MFA-freshness gate.
- **Date:** 2026-07-08 (original), 2026-07-14 (reversal recorded)
- **Deciders:** Lanre
- **Supersedes:** none
- **Related:** ADR-004, ADR-005

## Context

BankVault needs to grant an underwriter time-bound, object-scoped read access to a credit report and take it away when the window closes. When this project started, three ways to get that existed:

1. A custom broker: our own code applies a conditional IAM binding, and a scheduled job strips it.
2. An off-the-shelf enterprise PAM product (CyberArk, BeyondTrust, Delinea).
3. A cloud-native managed service, if one existed that could grant a *resource-scoped, conditioned* IAM role for a bounded time.

At the start, option 3 was not a safe bet. Google Privileged Access Manager existed but the resource-scoping and IAM-Condition support I needed were not something I was ready to build a project's core on. So the original decision was option 1: build the broker.

## Decision (original)

Build a custom JIT broker: `grant_access` applies a conditional `roles/storage.objectViewer` binding with a CEL expiry, `revoke_access` runs on a schedule to remove expired bindings. Explicitly reject enterprise PAM (option 2).

The original ADR named the condition under which this decision would become wrong, in one sentence: *if GCP ships a managed grant lifecycle that supports resource-scoped, IAM-conditioned, time-bound grants with an approval workflow, the custom build loses its only advantage and should be retired.*

## Rationale (original)

Enterprise PAM (option 2) is built for a different problem: brokering SSH/RDP/database sessions to servers, with credential vaulting and session recording. Pointing it at a single GCS object's IAM policy is using a session broker as an IAM-policy editor. It carries per-seat licensing, an agent footprint, and its own directory to keep in sync (the exact second-directory problem ADR-002 rejects). For a resource-scoped cloud IAM grant, it is the wrong mechanism at the wrong price.

Between build and the immature managed option, build won because it kept the enforcement semantics legible: the CEL condition and the revocation logic were both in this repo, both testable with mocked clients, both reviewable in a diff.

## Reversal

One week later, the trigger condition fired. GCP Privileged Access Manager reached the maturity the original ADR was waiting on: time-bound grants, an approval workflow, a max-duration cap, and IAM-Condition support on the granted role, scoped to a project, folder, or organization, with all allow-policy condition attributes available on the entitlement.

That is exactly the managed grant lifecycle the original ADR said would make the custom build wrong. The IAM Condition I was applying by hand, PAM now applies. The revocation `revoke_access` performed on a schedule, PAM now performs itself on grant expiry.

So I deleted `revoke_access` rather than defend it. Its only remaining justification was that it already existed, and "we already wrote it" is not an architecture reason. The broker shrank to the one job PAM does not do: refusing to create a grant when the underwriter's login is not fresh (ADR-004).

**Verify before you rely on this:** PAM's IAM-Condition support and resource scoping are confirmed against Google's PAM and IAM-Conditions documentation as of July 2026. The exact grant-request API semantics (who the grantee is when a broker service account calls `grants.create` on behalf of a requester, and whether justification and a per-request condition can be supplied at request time or must be fixed on the entitlement) must be confirmed against the current PAM API before deployment. This repo fixes the condition on the entitlement, which is the safer assumption.

## Consequences

**Positive**
- Less code to own. The revocation path, its scheduler, and its failure modes are Google's problem now, not this repo's.
- Approval workflow, grant history, and expiry are managed features with their own audit logs, feeding the platform-log layer for free.
- The reversal itself is the project's strongest evidence: the decision was written so its own expiry was legible before it happened.

**Negative**
- BankVault now depends on a PAM feature set. If Google changes the entitlement or condition model, this design moves with it.
- The provider resource (`google_privileged_access_manager_entitlement`) must be present and stable in the pinned Terraform provider version. That is a new external dependency to track.
- "Buy" here means depending on a first-party managed service, which is lower-risk than a third-party PAM vendor but is still not "build."

## Alternatives considered

- **Keep the custom broker anyway.** Rejected. Maintaining a revocation path that duplicates a managed one is pure liability: two code paths that can disagree, and only one of them is Google's problem to keep working.
- **Enterprise PAM (option 2).** Rejected at both decision points. Wrong mechanism (session broker used as IAM editor), wrong cost model, and it reintroduces a second directory.
- **Do nothing, use standing IAM with quarterly review.** Rejected. That is the exact control gap the project exists to close (ADR-003).
