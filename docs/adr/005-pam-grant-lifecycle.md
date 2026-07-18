# ADR-005: Grant lifecycle, and why reconciliation detects instead of contains

- **Status:** Accepted
- **Date:** 2026-07-14
- **Deciders:** Lanre
- **Related:** ADR-001, ADR-004

## Context

Once ADR-001 handed the grant lifecycle to PAM, a question remained: who watches the watcher. PAM expires grants on its own, and the IAM Condition denies access the instant `request.time` crosses `window_end`. So what work is left for this repo after the grant is created?

Two things PAM's expiry does not do on its own:

1. Guarantee that the append-only ledger has a close-out row for every grant, even if the broker crashed between creating the grant and recording it.
2. Notice a grant that should have expired but is still visible as active, or an IAM binding on the bucket that no ledger row explains.

## Decision

Add a **detect-only** reconcile job: Cloud Scheduler triggers it every 15 minutes through Pub/Sub. It queries `access_grants` for GRANT rows whose `window_end` has passed with no matching EXPIRE row, cross-checks each against live PAM grant state, writes an `EXPIRE_FLAG` row, and emits a structured alert log.

It does not revoke anything. The reconcile service account is read-only on PAM and the bucket; the only write it can make to the ledger is an EXPIRE_FLAG row.

## Rationale

The honest reason it detects instead of contains: PAM already owns containment. The grant's expiry and the IAM Condition are the two mechanisms that actually end access (see architecture.md), and both are faster and more reliable than a 15-minute sweep. A reconcile job that also revoked would be a *second*, slower enforcement path that can disagree with the first, and two enforcement paths that can disagree is how you get an incident where each thinks the other handled it.

So the sweep's job is completeness and anomaly detection, not enforcement. That produces one claim I can defend and one I refuse to make:

- Defensible: "an overrun or a missing close-out is **detected** within roughly one reconcile interval."
- Not made: "an overrun is **contained** within 15 minutes."

Those are different sentences. Writing the second one when only the first is true is the exact kind of overclaim that fails under questioning, so the design says detected and means it.

## The open question, stated not hidden

If a grant genuinely overruns (PAM reports it active past `window_end`, which should not happen but is the thing worth catching), detection is not containment. The flag lands in a log and a ledger row; nobody is paged, and nothing is revoked automatically.

Wiring the flag to an automated PAM grant revocation is the obvious next step, and it is deliberately not in this build for one reason: automated revocation is an action, and an action needs an alerting and rollback story around it before it runs unattended against a production access-control plane. Detection first, with the escalation path documented, is the honest ordering. Containment automation is a decision to make on purpose, with its own ADR, not a feature to bolt on because the detection was already there.

## Consequences

**Positive**
- One enforcement path (PAM + IAM Condition), so no two-writer disagreement.
- The ledger is guaranteed to close out every grant, which is what makes it SOX 404 evidence rather than a best-effort log.
- The limit is stated in the same breath as the capability: detected, not contained.

**Negative**
- A true overrun is detected, not stopped. If PAM ever failed to expire a grant, there is a detection-to-response gap bounded only by how fast a human acts on the flag.
- The alert is a structured log, not a page. Turning it into an actual notification is unfinished (README lists it under out-of-scope).
- 15 minutes is a chosen cadence; a tighter interval costs more invocations for a faster detection floor.

## Alternatives considered

- **Reconcile job that also revokes.** Rejected for now. It creates a second enforcement path that can disagree with PAM, and it runs an unalerted automated action against the access plane. Revisit under its own ADR once alerting and rollback exist.
- **No reconcile job; trust PAM entirely.** Rejected. It leaves the ledger's completeness to the broker never crashing at the wrong moment, and it catches no anomalies. The ledger is the audit artifact; it cannot be best-effort.
- **A tighter sweep (every minute).** Rejected as the default. It lowers the detection floor at a real cost and does nothing about the fact that detection is not containment. The interval is a tunable if a threat model justifies it.
