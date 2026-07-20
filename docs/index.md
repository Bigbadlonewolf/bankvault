# BankVault

Just-in-time privilege elevation for a mock mortgage lender's loan-origination pipeline. No underwriter holds standing access to borrower credit reports. Each approved request yields a time-bound grant scoped to one application's prefix, gated on a fresh multi-factor login, issued through Google Cloud Privileged Access Manager, and recorded in an append-only BigQuery ledger.

This site documents the architecture and the decisions behind it. The code lives at [github.com/Bigbadlonewolf/bankvault](https://github.com/Bigbadlonewolf/bankvault).

## Start here

- **[Architecture](architecture.md)** — the request path field by field, the two mechanisms that end access, and what is deliberately out of scope.
- **[Compliance coverage](controls-mapping.md)** — each resource mapped to a specific GLBA, PCI DSS v4.0, SOX 404, or FFIEC control.

## Architecture decision records

Each ADR states its trade-offs and its unverified assumptions rather than burying them.

- **[ADR-001: Build vs. Buy, and the week I reversed it](adr/001-build-vs-buy-jit-broker.md)** — why a custom grant lifecycle was the wrong long-term mechanism, and the documented reversal to GCP Privileged Access Manager.
- **[ADR-002: Two directories is one too many](adr/002-workforce-identity-federation-vs-iap.md)** — Workforce Identity Federation over Cloud IAP, so a leaver dies in one directory rather than surviving in a second.
- **[ADR-003: Scope and actor definition](adr/003-scope-and-actor-definition.md)** — one underwriter, one credit report, and the GLBA Safeguards Rule basis for both.
- **[ADR-004: MFA freshness as the signal, not session validity](adr/004-mfa-freshness-zero-trust-signal.md)** — why the broker checks `auth_time`, and where that check actually runs.
- **[ADR-005: Grant lifecycle, and why reconciliation detects instead of contains](adr/005-pam-grant-lifecycle.md)** — PAM owns expiry; the sweep is a completeness check, and the honest claim is "detected," not "contained."
- **[ADR-006: The broker cannot request the grant](adr/006-who-requests-the-grant.md)** — PAM elevates the calling principal, so the broker stopped creating grants; the underwriter requests their own, and reconcile reconstructs the grant record from PAM's audit logs.
