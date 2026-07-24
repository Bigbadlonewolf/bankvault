# ADR-004: MFA freshness as the signal, not session validity

- **Status:** Accepted
- **Date:** 2026-07-11
- **Deciders:** Lanre
- **Related:** ADR-002, ADR-005

## Context

An underwriter requests a credit report. Their corporate session is valid: they logged in this morning, the token has not expired. Is a valid session enough to gate a privileged read of consumer financial data?

A valid session says "this person authenticated at some point in the allowed window." It does not say "this person is at the keyboard right now." Between the morning login and this afternoon's request sits a laptop left unlocked, a hijacked session, a token lifted from a compromised host. For a normal read, session validity is a reasonable bar. For a privileged read of a credit report, the more useful signal is *recency*: did this person prove who they are within the last few minutes.

## Decision

The broker gates each grant on **MFA freshness**, not session validity. It reads the OIDC token's `auth_time` claim and refuses to create a PAM grant if `now - auth_time` exceeds `max_auth_age_seconds` (default 900, fifteen minutes). A stale login is denied with a reason, and the underwriter must re-authenticate before the request will pass.

This check runs in `request_broker` (`verify_identity`), before any PAM call. It is a broker-side check against a fully verified identity-provider token: the OIDC id_token's RS256 signature is verified against the IdP JWKS (issuer, audience, and expiry too) before `auth_time` is trusted, and the request is bound to the verified identity claim rather than a self-asserted `requested_by`.

## Rationale, including where the check runs and why

The important and easily-fabricated detail: **GCP IAM has no "how recently did this principal complete MFA" condition attribute.** IAM Conditions support request-time, resource, and similar attributes; they do not expose authentication recency. So freshness cannot be a CEL clause on the entitlement the way the object-scope and time-window clauses are. It has to be enforced at a layer that can see the authentication event.

There are two such layers, and this repo uses the first:

1. **Broker check (implemented here).** The broker receives the IdP-issued OIDC token, reads `auth_time`, and enforces the freshness bound itself before requesting the grant. This is explicit, testable with a mocked token, and lives in the code path that already exists to enforce segregation of duties.
2. **Access Context Manager reauthentication session controls (defense-in-depth, not implemented here).** ACM can require reauthentication after a configured interval for access to protected resources. That is the platform-level backstop behind the broker check. It is named here as the intended second layer, not wired up in this build.

Enforcing freshness at the broker, in front of PAM, means a stale login never becomes a grant in the first place. The ledger records the `auth_time` that gated each grant, so the freshness decision is auditable after the fact, not just enforced in the moment.

## The cost, taken knowingly

Access is denied when the identity provider is unreachable, because the broker cannot confirm freshness without it. That means BankVault's availability is bounded by the IdP's. A loan decision with an SLA does not stop having one because Okta is down.

I took that trade deliberately. An identity control that keeps granting access when it cannot verify who is asking has a bypass, and the bypass opens under exactly the conditions an attacker wants: the IdP degraded, checks failing open, nobody watching. Fail-closed is the correct default for a privileged read of regulated data, and the availability cost is the price of not having a fail-open bypass. If a specific SLA cannot tolerate that, the answer is a documented, alerted break-glass path, not a control that quietly fails open.

## Consequences

**Positive**
- The signal that gates access is presence, not a possibly-stale session.
- The gating `auth_time` is recorded per grant, so freshness is auditable, not just enforced.
- Fail-closed by default; no silent fail-open bypass under IdP degradation.

**Negative**
- Availability is coupled to the IdP (consistent with ADR-002, but real).
- Fifteen minutes is a chosen number. Too short and underwriters re-authenticate constantly; too long and "fresh" stops meaning present. It is a tunable (`max_auth_age_seconds`), not a proven value.
- `verify_identity` performs full OIDC verification (RS256 signature against the IdP JWKS, issuer, audience, expiry) and is fail-closed when the `OIDC_*` env vars are unset. The remaining boundary is deployment, not code: no live IdP/JWKS endpoint is wired in this repo, so verification denies every request until those vars point at a real provider. Called out in the README under "What this isn't".

## Alternatives considered

- **Session validity only.** Rejected. It is the weaker signal and the whole point of the control is to be stronger than the default.
- **A CEL "MFA freshness" condition on the entitlement.** Rejected because it does not exist. IAM Conditions have no authentication-recency attribute; asserting one would be a fabricated capability.
- **ACM reauthentication alone, no broker check.** Deferred, not rejected. It is the right defense-in-depth layer, but leaving freshness entirely to a platform setting removes the per-grant `auth_time` record that makes the decision auditable.
