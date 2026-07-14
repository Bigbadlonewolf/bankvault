# ADR-004: MFA Freshness as the Zero Trust Signal

**Date:** 2026-07-03
**Status:** Accepted
**Authors:** Lanre Oluokun
**Implementation:** `main.py` — freshness check implemented; identity-validation stub not yet replaced (see ADR-005 Known Gaps)

---

## Context

BankVault must enforce Zero Trust at the point of JIT grant. Identity alone (assigned underwriter + valid loan application) is insufficient. The broker must verify trust of the *specific session*, not just authorization of the user.

The distinction matters because every other control in this system assumes the session presenting the request is the session the underwriter actually holds. Without a freshness signal, a stolen or replayed session token satisfies every downstream check — the entitlement is valid, the CEL condition matches, the audit log records a legitimate-looking grant. Authorization succeeds and the control set produces no signal that anything is wrong.

---

## Decision

**MFA freshness check via a `max_age=0` OIDC constraint.**

The underwriter-facing tool must explicitly request `max_age=0` at the point of the JIT request. Forwarding an existing session token instead of forcing re-authentication would make this check a no-op.

The broker validates the returned ID token's `auth_time` claim against a **15-minute window**. Hard deny if stale or missing. The check runs on every JIT request. **No session caching.**

### IdP unavailability: fail closed

If the identity provider is unreachable, returns an error, or times out, **the broker denies the JIT request**. There is no fallback path, no cached-`auth_time` acceptance, and no degraded mode.

A grant issued without a verifiable fresh authentication event is a grant issued without the Zero Trust signal this ADR exists to establish. The correct behavior on loss of that signal is denial, not assumption.

### Circuit breaker

Rather than retrying a failing IdP on every request, the broker **opens a circuit after 3 consecutive IdP failures** and denies immediately for a **60-second cooldown** without issuing further calls, then allows a single probe request through. This bounds retry amplification against an IdP that is already degraded.

Denials during an open circuit are logged distinctly as `IDP_UNAVAILABLE`, separate from `MFA_STALE`, so that an availability incident is not misread in the audit trail as a stream of failed authentication attempts. Conflating the two would make an outage indistinguishable from an attack in post-incident review — which is precisely the moment the distinction matters most.

---

## Trade-offs Accepted

Each of the following is a known cost of the decision above, not an unresolved question. They are stated so that a reader does not have to discover them.

### 1. BankVault's availability is bounded by the IdP's

**The cost.** Fail-closed means an IdP outage blocks *all* JIT grants. Underwriters cannot obtain access to credit reports while the bank's IdP is down. A loan decision with an SLA does not stop having an SLA because Okta is having a bad afternoon.

**Why it is accepted anyway.** The alternative is granting access to GLBA-regulated NPI on the basis of an unverified session. That inverts the control: a system designed to deny access without fresh trust would, under precisely the conditions most favorable to an attacker (identity infrastructure degraded, monitoring noisy, operators distracted), begin granting it. Fail-open on an identity control is not a graceful degradation; it is a control that switches itself off under stress.

**What this obligates.** The bank's incident response plan must include a documented, audited, manually-approved break-glass path *outside this broker* for the case where a loan decision cannot wait out the outage. **That path is out of scope for this ADR and is not built.** Naming it here is not the same as having it. A production deployment cannot ship this decision without also shipping that path.

### 2. The 15-minute `auth_time` window is a policy choice, not an empirical one

**The cost.** Fifteen minutes is defensible but arbitrary. A shorter window forces re-authentication friction on underwriters mid-workflow; a longer one widens the replay window a stolen token can exploit. No measurement in this project justifies 15 over 10 or 20.

**Why it is accepted anyway.** The alternative to an unvalidated number is either no window at all (which defeats the control) or a fabricated justification for a specific figure (which is worse than admitting the figure is a policy choice). It is documented as risk-based policy, and a real deployment would set it from the underwriter's actual task duration and the IdP's observed session behavior.

### 3. `max_age=0` enforcement depends on correct client-tool implementation

**The cost.** The broker validates `auth_time`, but it cannot force the client to have *requested* re-authentication. A client tool that forwards an existing session token and receives an `auth_time` that happens to fall within the window will pass this check without a fresh MFA event ever occurring. The control has a dependency on code the broker does not own.

**Why it is accepted anyway.** There is no server-side signal that distinguishes "the IdP re-authenticated this user 3 minutes ago because we asked" from "the IdP re-authenticated this user 3 minutes ago for an unrelated reason." OIDC does not expose one. The mitigation is not architectural — it is a client-integration requirement that must be verified during onboarding of the underwriter-facing tool, and re-verified whenever that tool changes. This is a stated assumption below, not a solved problem.

### 4. Circuit-breaker thresholds are untuned

**The cost.** Three failures and a 60-second cooldown are placeholder values. Too sensitive and a transient network blip locks out underwriters for a minute; too tolerant and the broker hammers a degraded IdP.

**Why it is accepted anyway.** The threshold values are far less important than the *presence* of the breaker — the failure mode being prevented (unbounded retry against a degraded IdP) is prevented at any reasonable threshold. Tuning requires the IdP's own SLO and observed error-rate distribution, which are bank-specific and not available at portfolio scope.

### 5. Freshness gates the grant request, not the access window

**The cost.** This ADR establishes trust at the moment of grant issuance. It does not re-check freshness during the 30-minute window that ADR-005 opens. A session compromised *after* a valid grant is active inherits that access for the remainder of the window.

**Why it is accepted anyway.** Closing this would require session-bound revocation, which depends on OIDC back-channel logout support from the bank's IdP — unverified as available. ADR-005 records that as **Deferred**, not rejected, with an explicit revisit condition. The boundary between "freshness at request" and "freshness during window" is stated in both ADRs rather than left for a reader to infer.

---

## Consequences

### Positive

- Defensible Zero Trust signal, **request-scoped rather than session-scoped**.
- **Fails safe** — deny by default, including when the identity plane itself is unavailable.
- Audit log distinguishes `MFA_STALE` (a stale or missing `auth_time`) from `IDP_UNAVAILABLE` (an outage), so authentication failures and availability failures are not conflated in incident review.
- Circuit breaker bounds retry amplification against a degraded IdP, so BankVault does not contribute to the outage it is reacting to.

### Negative

- **Availability coupling.** Fail-closed on IdP unavailability means BankVault's availability is bounded by the IdP's. An IdP outage blocks all JIT grants, and the manually-approved break-glass path this implies is **not built**.
- **The 15-minute window is unvalidated policy.** Documented as a risk-based choice, not presented as an empirically optimized figure.
- **Client-side dependency.** `max_age=0` enforcement depends on the underwriter-facing tool implementing it correctly. The broker cannot detect a client that forwards a stale session whose `auth_time` happens to fall inside the window.
- **Circuit-breaker thresholds untuned** against real IdP behavior.
- **No in-window re-check.** Freshness gates issuance only; ADR-005's 30-minute window runs without further freshness validation.

---

## Alternatives Considered

| Alternative | Pros | Cons | Verdict |
|---|---|---|---|
| **Device compliance posture** (BeyondCorp / agent-based) | Stronger Zero Trust signal — covers device health *and* identity, and would partially close the stolen-session gap this ADR leaves open | Cannot currently defend the GCP implementation mechanism without fabricating integration details | **Rejected** |
| **Static session token validation** (no re-auth force) | Simpler client integration, no IdP re-auth latency, no availability coupling | Validates a *standing* session, not *fresh* trust — which is the thing Zero Trust exists to distinguish | **Rejected** |
| **Risk-based scoring** (anomaly detection, geo-IP) | More sophisticated trust signal; degrades gracefully rather than failing closed | Requires data and models not available; over-engineered for this scope | **Rejected** |
| **Fail open on IdP unavailability** (cache last-known-good `auth_time`) | Preserves BankVault availability during an IdP outage; no break-glass path needed | The control switches itself off under exactly the conditions most favorable to an attacker. An identity control that fails open is not a control | **Rejected** |

---

## Rationale

MFA freshness is the Zero Trust signal that can be drawn, defended, and implemented honestly in the available time. Device posture is the architecturally stronger answer, but the GCP integration details for it aren't known well enough to defend without fabricating them. **A narrow, defensible mechanism beats a broad, hand-waved one.**

The fail-closed decision follows from the same principle. A system whose availability depends on its identity provider is an honest, statable architecture with a known operational cost. A system that grants access to NPI when it cannot verify who is asking is not a weaker version of the same architecture — it is a different architecture, one whose primary control has a documented bypass.

---

## Assumptions Requiring Verification

1. The underwriter-facing tool correctly implements `max_age=0` on **every** JIT request. Not verifiable server-side; must be confirmed at client-tool onboarding and re-confirmed on every client change.
2. The IdP returns the `auth_time` claim in the ID token. Standard OIDC, but bank IdP configurations vary and some suppress it.
3. The 15-minute window is documented as risk-based policy, **not** presented as an empirically optimized figure.
4. The circuit-breaker thresholds (3 failures, 60-second cooldown) are not tuned against observed IdP behavior. A real deployment would set them from the IdP's own SLO and error-rate distribution.
5. A manually-approved, audited break-glass path exists outside this broker for IdP-outage scenarios. **Assumed by this decision; not built by this project.**

---

## Related

- [ADR-001: Build vs. Buy — Custom JIT Broker vs. Off-the-Shelf PAM](001-build-vs-buy-jit-access.md)
- [ADR-003: Scope and Actor Definition](003-scope-and-actor-definition.md) — fixes the actor and the GLBA basis
- [ADR-005: PAM Grant/Revocation Lifecycle](005-pam-grant-revocation-lifecycle.md) — consumes this check; opens the 30-minute window this ADR does not re-validate
