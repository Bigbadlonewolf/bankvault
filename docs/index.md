# BankVault

Just-in-time privilege elevation for a mock retail bank's loan origination pipeline. No loan officer holds standing access to customer PII — every read is a time-bound, resource-bound grant, applied and revoked by two Cloud Functions, with every request, grant, denial, and revocation logged to an append-only BigQuery ledger.

## The Problem It Solves

The default pattern at most banks is that loan officers get a standing IAM role — `storage.objectViewer` on the applications bucket, granted once during onboarding and reviewed, if at all, on a quarterly cycle. That's a PCI DSS 7.2 violation waiting for an audit: for up to a quarter, a transferred or terminated employee can retain read access to Social Security numbers and income documentation with nobody actively deciding they should have it *today*.

BankVault replaces the standing grant with a request: a loan officer asks for access to one application, a distinct approver signs off, GCP enforces the expiry natively via an IAM Condition, and the whole exchange is a row in a table before the grant is even live.

## Where to Go Next

- [Architecture](architecture.md) — the full request/grant/revoke flow, field by field
- [ADR-001: Build vs. Buy](adr/001-build-vs-buy-jit-access.md) — why a custom broker instead of an off-the-shelf PAM platform
- [ADR-002: Workforce Identity Federation vs. IAP](adr/002-workforce-identity-federation-vs-iap.md) — how loan officer identity should feed IAM decisions
- [Compliance Coverage](controls-mapping.md) — PCI DSS 7, FFIEC, and SOX 404 mapped to specific resources in this repo

## What This Isn't

Week 1 scope only — one resource, one grant path, one revoke path, no real IdP integration, not deployed. See the README's "What This Isn't" section in the repository for the full list of honest scope limits.
