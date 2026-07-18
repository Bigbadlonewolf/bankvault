# ADR-003: Scope and actor definition

- **Status:** Accepted
- **Date:** 2026-07-08
- **Deciders:** Lanre
- **Related:** ADR-001, ADR-004

## Context

"Just-in-time access for a bank" can mean almost anything: every employee, every system, every data class. A scope that broad produces a design that is impressive in a diagram and false in every particular, because no single mechanism actually governs all of it. Before any Terraform, the project needed one honest, defensible boundary.

## Decision

One actor, one resource, one regulated data class:

- **Actor:** an underwriter in the loan-origination pipeline.
- **Resource:** a single borrower's credit report, stored as an object under a per-application prefix in one GCS bucket.
- **Data class:** consumer financial information under the GLBA Safeguards Rule.

Everything else (other roles, other data stores, session access to servers, database credentials) is explicitly out of scope for this build. The pattern is meant to generalize; the build does not pretend to have generalized yet.

## Rationale

The underwriter-reading-a-credit-report flow is the smallest thing that still exercises the whole control:

- It is a genuinely privileged read. A credit report is exactly the data GLBA exists to protect, so least-privilege here is not a toy example.
- It has a natural, narrow object scope (one application's file), which makes the IAM Condition's `resource.name.startsWith(...)` clause meaningful rather than decorative.
- It has a real segregation-of-duties story: the underwriter who requests is not the lead who approves.
- It has a clean expiry story: nobody needs to read one credit report for longer than a QC pass, so a 30-minute cap is defensible rather than arbitrary.

Picking the narrow flow is what lets every later claim be specific. "An underwriter gets 30 minutes on one credit report" is checkable. "The bank has zero-trust access" is not.

The GLBA basis is deliberate. 16 CFR 314.4(c)(1) requires access controls limiting customer information to authorized users. A credit report is customer financial information. That gives the whole design a regulatory anchor instead of a general "security is good" motivation, and it is why the controls mapping (`docs/controls-mapping.md`) leads with GLBA.

## Consequences

**Positive**
- Every downstream claim is specific and checkable, because the scope is one flow.
- The IAM Condition, the SoD check, and the expiry cap all have a concrete, defensible justification rather than a generic one.
- The controls mapping is honest: it maps one pattern to specific clauses, not a whole program to a framework.

**Negative**
- The build does not demonstrate multi-resource support, multiple actor roles, or non-GCS data stores. Those are asserted as "the pattern generalizes," which is a claim, not a demonstration.
- A reviewer looking for breadth will find depth on one flow instead. That is the intended trade, but it is a trade.

## Alternatives considered

- **All privileged roles across the pipeline.** Rejected. It would force the design to hand-wave over data stores the mechanism does not actually govern, and every claim would have to be hedged.
- **A non-regulated resource (internal tooling access).** Rejected. It loses the GLBA anchor and makes the compliance mapping generic instead of specific.
