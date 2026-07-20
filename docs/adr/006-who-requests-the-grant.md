# ADR-006: The broker cannot request the grant

- **Status:** Accepted
- **Date:** 2026-07-20
- **Deciders:** Lanre
- **Supersedes:** none
- **Amends:** ADR-004 (where freshness is enforced), ADR-001 (what the broker is for)
- **Related:** ADR-001, ADR-003, ADR-004, ADR-005

## Context

Through ADR-001 and ADR-004 the design assumed the broker could sit in front of PAM: verify the login is fresh, then call `grants.create` on the underwriter's behalf. `request_broker` did exactly that, at `functions/request_broker/main.py`. The seam carried a VERIFY-BEFORE-DEPLOY note saying the grantee semantics had to be confirmed against the live PAM API before anyone deployed it.

That note was the right instinct and it was never cashed. Verifying it closed the design off.

Google's Privileged Access Manager documentation is explicit about who receives the privileges: if a group is added as a requester on an entitlement, every member of that group can request a grant, but **only the individual account that requests the grant receives the elevated privileges**. There is no grantee field and no on-behalf-of parameter on `CreateGrant`. Privileges attach to the calling principal.

The broker calls PAM with its own service-account credentials. So the broker-mediated design does not grant credit-report read to the underwriter who asked. It grants it to `bankvault-request-broker@…`, a service account that is always running, holds the binding for the full window, and is never reviewed by anyone.

That is standing access to borrower credit reports, held by a non-human identity, created by the control that exists to eliminate standing access. It is worse than the problem in the README, because a transferred underwriter at least shows up in a quarterly access review and a service account does not.

## Decision

**The broker does not create grants.** `_create_pam_grant` is removed from `request_broker`. The underwriter requests their own grant directly against the PAM entitlement, as the eligible principal PAM requires them to be.

The broker keeps the two jobs it can actually do:

1. **Pre-flight rejection.** It refuses requests that fail domain, segregation-of-duties, duration-cap, application-id, and MFA-freshness checks, and records the denial with a reason.
2. **The per-request audit record.** It writes the `auth_time` that gated the request into the ledger, tied to a specific application and justification.

**Freshness enforcement moves to the platform, and the claim gets smaller.** Enforced recency is an Access Context Manager reauthentication binding on the underwriter group. The honest numbers:

| Layer | Window | What it is |
|---|---|---|
| Access Context Manager reauth binding | **1 hour** | Enforced. Platform minimum; `--session-length` accepts `0s` or 1h–24h and nothing between. |
| `request_broker` freshness check | **15 min** (`max_auth_age_seconds`, 900) | Not enforced. Early rejection plus the recorded `auth_time`. |

ADR-004's decision stands — recency is the right signal, not session validity. What changes is the sentence about *where it is enforced*. ADR-004 says the broker enforces it. After this ADR the broker cannot, because an underwriter who skips the broker and calls PAM directly is doing the thing PAM is designed for.

## Rationale

The broker was never a chokepoint and calling it one was the error. The underwriter has to be the eligible principal on the entitlement, so the PAM request path is open to them by construction. A control that can be bypassed by not using it is not enforcement, and describing it as enforcement is the kind of claim that collapses the first time someone asks "what stops them calling PAM directly?"

Moving freshness to ACM buys real enforcement at the cost of precision. One hour is looser than fifteen minutes. Two things make that acceptable. The grant itself is still capped at thirty minutes, approval-gated, and object-scoped, so recency is one signal among several rather than the only thing standing between a stale session and a credit report. And the ledger still records the fifteen-minute-fresh `auth_time` on every request that came through the broker, so the evidence available to an examiner is tighter than the enforced bound.

Say it as two sentences that are both true, rather than one that is convenient: enforcement is one hour, at the platform. Evidence is fifteen minutes, in the ledger.

## Consequences

**The reauth binding is broader than this project.** ACM bindings apply to all applications for the bound principals unless narrowed with `scopedAccessSettings`, which targets applications by OAuth `clientId` or by name ("Cloud Console", "Google Cloud SDK"). **PAM is not documented as an independently targetable application.** So the binding covers the underwriter group's whole Google Cloud session, not the credit-report request path. Every underwriter reauthenticates hourly for everything they do in GCP. That is a real operational cost imposed on people who are not the subject of this control, and it belongs in the trade-off column, not in a footnote.

**A direct REST call to the PAM API may not be covered by a console-scoped binding.** If the binding is narrowed to Cloud Console and Google Cloud SDK, whether a raw API call from another client is still gated is not something I can establish from the documentation. `[verify against current GCP docs]` before relying on the narrowed form. The unnarrowed binding avoids the question and is the safer default.

**The broker's blast radius shrinks.** It no longer needs permission to create grants. Its service account holds PAM viewer and BigQuery jobUser. It cannot create a grant, cannot read the credit-reports bucket, and cannot delete ledger rows. Worst case on compromise is falsified or suppressed ledger rows, which is precisely why the platform log export exists as an independent record application code cannot touch.

**`approved_by` is a claim, not evidence.** It arrives in the request body. Real approval evidence is PAM's approval workflow and its admin-activity audit logs. The compliance mapping should point at those, not at the ledger column.

**The GRANT ledger row changes meaning.** The broker no longer observes a grant being created, so it cannot write `pam_grant_name`. It writes a `REQUEST` row recording that a request passed pre-flight. Grant creation and expiry are reconstructed from the PAM audit logs in `bankvault_platform_logs`, joined on requester and application. `reconcile` already cross-checks live PAM grant state and is unaffected.

## Alternatives considered

**Keep the broker in the grant path and accept a service-account grantee.** Rejected. It inverts the project's thesis. If the service account holds the access, there is no just-in-time property left to demonstrate.

**Give each underwriter a dedicated service account the broker impersonates.** Rejected. It reintroduces per-user standing identity, doubles the identity surface, and still separates the human from the privilege. ADR-002 rejected a second directory for the same reason.

**Enforce freshness with an IAM Condition instead.** Not possible, and worth restating because it looks plausible. IAM Conditions expose request-time and resource attributes; there is no authentication-recency attribute. Writing a CEL clause for it would be inventing a capability. This is unchanged from ADR-004.

**Drop the broker's freshness check now that ACM enforces recency.** Rejected. The fifteen-minute check is the only thing producing a per-request `auth_time` in the ledger, and it rejects stale requests before they reach PAM. Redundant as enforcement, useful as evidence.

## Reversal condition

If PAM gains a grantee or on-behalf-of parameter on `CreateGrant`, allowing a broker to request a grant whose privileges attach to a named human, the broker-mediated design becomes viable again and the chokepoint argument returns with it. If ACM gains sub-hour session lengths or PAM becomes independently targetable via `scopedAccessSettings`, the enforcement and evidence windows collapse back together and the two-number framing above stops being necessary.
