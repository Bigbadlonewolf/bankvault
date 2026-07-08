# ADR-004: MFA Freshness as the Zero Trust Signal

**Date**: 2026-07-03
**Status**: Drafted (one flagged gap not confirmed resolved, see Consequences)
**Authors**: Lanre Oluokun
**Implementation**: `main.py`

## Context

BankVault must enforce Zero Trust at the point of JIT grant. Identity alone (assigned underwriter + valid loan application) is insufficient. The broker must verify trust of the specific session, not just authorization of the user.

## Decision

MFA freshness check via a `max_age=0` OIDC constraint. The underwriter-facing tool must explicitly request `max_age=0` at the point of the JIT request. Forwarding an existing session token instead of forcing re-authentication would make this check a no-op. The broker validates the returned ID token's `auth_time` claim against a 15-minute window. Hard deny if stale or missing. Check runs on every JIT request. No session caching.

## Consequences

**Positive:** Defensible Zero Trust signal, request-scoped rather than session-scoped. Fails safe (deny by default). Audit log captures `MFA_STALE` denials.

**Negative:** The 15-minute window is a policy choice, not empirically validated. `max_age=0` enforcement depends on correct client-tool implementation. **Unresolved as a stated Decision:** behavior when the IdP itself is unavailable was flagged in review as needing an explicit fail-closed decision with circuit-breaker behavior. Not confirmed as written into this ADR as a Decision line rather than left as an open negative.

## Alternatives Considered

| Alternative | Pros | Cons | Verdict |
|---|---|---|---|
| Device compliance posture (BeyondCorp/agent-based) | Stronger Zero Trust signal, covers device health + identity | Cannot currently defend the GCP implementation mechanism | Rejected |
| Static session token validation (no re-auth force) | Simpler client integration, no IdP re-auth latency | Validates a standing session, not fresh trust, which defeats Zero Trust | Rejected |
| Risk-based scoring (anomaly detection, geo-IP) | More sophisticated trust signal | Requires data/models not available; over-engineered for this scope | Rejected |

## Rationale

MFA freshness is the Zero Trust signal that can be drawn, defended, and implemented honestly in the available time. Device posture is the architecturally stronger answer, but the GCP integration details for it aren't known well enough to defend without fabricating them. A narrow, defensible mechanism beats a broad, hand-waved one.

## Assumptions Requiring Verification

- Underwriter-facing tool correctly implements `max_age=0` on every JIT request.
- IdP returns the `auth_time` claim in the ID token (standard OIDC, but bank IdP configs vary).
- The 15-minute window is documented as risk-based policy, not presented as an empirically optimized figure.
