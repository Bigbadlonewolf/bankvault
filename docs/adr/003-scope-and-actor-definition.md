# ADR-003: Scope and Actor Definition

**Date**: 2026-07-08
**Status**: Accepted
**Authors**: Lanre Oluokun
**Implementation**: N/A (scope decision, no code artifact)

## Context

BankVault is a GCP-native Just-In-Time (JIT) access broker. This ADR defines the single actor-resource pair the system is built around, and the reasoning for choosing that pair over other high-risk candidates that exist in a non-bank lender's environment.

## Decision

Bind the architecture to a single, GLBA-governed actor-resource pair (a loan underwriter requesting temporary, read-only access to a credit bureau report) rather than building a general-purpose JIT platform. Compliance-first design for one concrete threat model produces a verifiable architecture; a general-purpose design at this stage would require hand-waving the parts that aren't built.

The credit report (e.g., an Experian or TransUnion pull) is treated as already present in Cloud Storage, placed there by an upstream ingestion process. BankVault's scope begins at the storage layer. It does not integrate with, and makes no claims about, the credit bureau's own API or ingestion pipeline.

**Why this pair, not another:** a non-bank mortgage lender has several plausible high-risk actor-resource pairs: a customer service rep against an account ledger, a compliance officer against an audit trail, an underwriter against a credit report. The underwriter/credit-report pair was chosen because it has the sharpest single regulatory driver (GLBA NPI protections apply directly, not by analogy), the clearest natural time-boundary (access is bounded by one loan decision, not an open-ended job function), and it avoids a harder, different problem: a CSR's ledger access or an auditor's access is typically standing, role-based access, which calls for RBAC hygiene, not JIT elevation. That's a different architecture than the one this project builds.

## Consequences

**Positive:**
- Tight coupling to a real regulated business process (loan origination) with a natural time-box tied to the loan decision SLA.
- A specific regulatory citation applies without interpretation, with FTC enforcement authority matching the entity type described here.
- A specific, defensible actor-resource pair that can be validated end-to-end in a 20-minute technical deep dive.
- The narrow scope forces the architecture to optimize for one threat model rather than abstracting prematurely.

**Negative (real trade-offs, not just exclusions):**
- This proves depth on one flow, not breadth across actor types. It does not demonstrate whether the entitlement-per-resource pattern holds up with multiple concurrent actors or resources without further design work.
- It deliberately does not address standing/role-based access patterns (the CSR/ledger case), which are arguably higher-volume risk surface for a real lender than one underwriter's occasional credit pull. That's a known, accepted gap in coverage, not an oversight.

## Rationale

A narrow, deep, compliance-grounded reference flow can be reasoned about completely: every control decision maps to a specific regulation, a specific actor, and a specific resource, not to a hypothetical range of use cases a broader platform would need to hand-wave at this stage. This principle holds independent of timeline. It also happens to fit the available build time, which is a reason to build this flow first, not a reason the principle is true.

## GLBA Basis

Verified against 16 CFR 314.4, not assumed.

- **314.4(c)(1)(i)–(ii):** requires authenticating and permitting access only to authorized users, and limiting authorized users' access to only the customer information they need to perform their duties. That's the basis for the JIT, need-based access model carried into ADR-004 and ADR-005.
- **314.4(c)(8):** requires monitoring and logging authorized-user activity and detecting unauthorized access. That's the basis for the audit-logging requirement in ADR-005.
- **Scope note:** 16 CFR 314 covers non-bank financial institutions under FTC jurisdiction. Mortgage lenders and brokers are named explicitly among the Rule's own covered-entity examples (314.2(h)). A chartered bank falls under Interagency Guidelines from its own prudential regulator (OCC/FDIC/Federal Reserve) instead, a separate instrument. This project's institution type (non-bank mortgage lender) is written to match the citation actually used.

## Alternatives Considered

| Alternative | Pros | Cons | Verdict |
|---|---|---|---|
| General-purpose, multi-actor/multi-resource JIT platform | Demonstrates broader platform thinking; reusable across more lender workflows | At this stage, requires designing and defending controls for actor and resource types not yet modeled, producing a shallower, harder-to-defend result overall | Rejected |
| Broad "any restricted GCS bucket" scope, no named regulation | Simpler to describe; not tied to one specific rule | Weaker regulatory teeth: doesn't demonstrate GLBA-specific reasoning, which is the actual differentiator for a financial-services role | Rejected |
| Standing/role-based access for the underwriter (no JIT elevation) | Simpler to implement; no grant/revoke lifecycle needed | Defeats the Zero Trust/least-privilege premise the rest of this ADR set is built on | Rejected |

## Assumptions Requiring Verification

- The loan underwriter is an actual human user with a Google Identity account (not a service account, not a shared account).
- The lender's loan origination system has a well-defined "underwriter" role mapping to a single Google Identity group or organizational unit.
- The credit bureau report is already stored in Cloud Storage; BankVault does not pull from Experian/TransUnion APIs. It brokers access to the stored object only.
- The upstream ingestion process that places the credit report into Cloud Storage is out of BankVault's scope and is assumed to enforce its own access controls on the bureau-side pull.
- GLBA is the applicable regulation for this data; FCRA, PCI DSS, or state privacy laws may impose additional constraints on this specific flow. Not verified here, and a real deployment would need to confirm this against counsel, not just this ADR.
- "One loan decision" as the natural time boundary is asserted here as the rationale; the actual grant-window duration enforcing that boundary is a separate decision, made in ADR-005.
