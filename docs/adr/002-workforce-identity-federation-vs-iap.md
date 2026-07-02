# ADR-002: Workforce Identity Federation vs. Cloud Identity-Aware Proxy for Internal Bank Staff

**Date**: 2026-07-01
**Status**: Accepted
**Authors**: Lanre Oluokun

## Context

Loan officers are internal bank employees whose identities already live in the bank's existing directory (Active Directory, Okta, Azure AD, or equivalent) — a directory subject to the bank's own identity-proofing, background-check, and joiner/mover/leaver process. BankVault needs a way to get that identity into a GCP IAM policy decision without creating a second, parallel identity to manage.

GCP offers two commonly-confused mechanisms for bringing external identities into a policy decision:

- **Workforce Identity Federation (WIF)** — exchanges an assertion from an external IdP (SAML or OIDC) for short-lived Google credentials, without provisioning a Cloud Identity account. The resulting principal (`principal://iam.googleapis.com/locations/global/workforcePools/...`) can appear directly as an IAM policy member, including inside a conditional binding's `request.auth` attributes.
- **Cloud Identity-Aware Proxy (IAP)** — a reverse-proxy control that sits in front of HTTP(S) applications (App Engine, Cloud Run, GCE via a load balancer) and enforces a Google-session-based login before traffic reaches the backend. IAP authenticates *browser sessions to an app*, not API callers, and its identity model is Google/Cloud Identity accounts (including those provisioned via Google Workspace or federated SSO into Cloud Identity).

These solve adjacent but different problems, and the FFIEC IT Examination Handbook's Information Security booklet is specific about why the distinction matters for a regulated institution: access rights administration should tie back to an authoritative, auditable system of record for identity, with provisioning and deprovisioning controlled centrally — not duplicated across systems where a leaver in one directory can be missed in another.

## Decision

**Use Workforce Identity Federation as the identity plane that feeds the loan officer's identity into IAM policy decisions** (the `requested_by` principal in grant_access, and ultimately the member string in the conditional IAM binding). Cloud IAP is recommended as a complementary, not competing, control in front of any browser-based approval/admin UI the bank builds around this broker — not as the mechanism that identifies the loan officer to IAM.

## Rationale

| Dimension | Workforce Identity Federation | Cloud Identity-Aware Proxy |
|---|---|---|
| **What it authenticates** | API/programmatic callers presenting a federated assertion — the shape a Cloud Function endpoint or backend service consumes | Browser sessions reaching an HTTP(S) app through Google's edge proxy |
| **System of record for identity** | Stays the bank's existing IdP — WIF exchanges an assertion, it does not create or own a user record in Google's directory | Requires a Cloud Identity (or Google Workspace) account for the session — provisioning a Google-side identity is a prerequisite, even when federated via SSO |
| **Regulatory identity-proofing angle** | The bank's existing joiner/mover/leaver process remains the single point of control; disabling a loan officer in the bank's IdP immediately invalidates their ability to obtain a federated credential — no second deprovisioning step | Introduces a second identity lifecycle: a Cloud Identity account that must be deprovisioned in step with the source-of-truth directory, which is exactly the duplicated-directory risk FFIEC's Access Rights Administration guidance flags |
| **Fit for this system's request shape** | grant_access receives `requested_by` as an authenticated caller attribute; WIF's attribute mapping can inject IdP claims (department, employee ID) directly into IAM condition evaluation via `request.auth.claims` | IAP has no equivalent for API-level, non-browser calls — it would need to front a web form that then calls the function server-side, adding a hop |
| **Standing infrastructure** | No new user directory; attribute mapping and workforce pool are configuration, not an identity store | Needs Cloud Identity provisioning (free tier available, but still a directory to keep in sync) |
| **Session-level access to a browser UI** | Not its job — WIF has no concept of a browser session | This is exactly what IAP is for — a defense-in-depth layer in front of any human-facing admin console this system grows later |

### Why not IAP as the primary identity plane

If BankVault's grant requests were submitted through a web form, IAP would be a reasonable front door — but it would still require provisioning a Cloud Identity account per loan officer (even federated ones), which duplicates the bank's existing identity-proofing investment in its own directory. FFIEC's access control expectations center on a demonstrable, centrally-governed provisioning and deprovisioning process; running that process twice, once in the bank's IdP and once in Cloud Identity, is a control gap examiners specifically look for, not a mitigation.

### Why not both, as equals

They aren't equals — they operate at different layers. This ADR's decision is that WIF is the identity plane feeding the *authorization decision* (who is `requested_by`, is a valid CEL binding member). IAP is a *transport-layer* control for anything with a browser in front of it. A production deployment of this system's future approval-UI would reasonably use both together: IAP gates who can load the approval page at all, and the identity IAP surfaces should itself be the federated WIF/SSO identity, not a Cloud Identity password account.

## Consequences

### Positive
- Single source of truth for loan officer identity remains the bank's existing, already-audited directory — no parallel Cloud Identity lifecycle to keep in sync.
- IAM conditions can reference federated claims directly (e.g., restricting a grant to `request.auth.claims.department == "loan_origination"`), giving a second, attribute-based backstop beyond the domain-suffix check in `grant_access`.
- No standing Google-side user accounts for loan officers who never otherwise touch GCP services — reduces the blast radius of a compromised Google credential, because there isn't one.

### Negative
- WIF setup (workforce pool, provider, attribute mapping) is a one-time configuration cost this repo's Terraform does not include — it depends on the bank's specific IdP (Okta, Azure AD, ADFS) and is genuinely an integration project, not a `terraform apply`.
- Without IAP or an equivalent proxy in front of any future human-facing approval UI, that UI would need its own session-auth story — WIF alone doesn't give you a login page.
- Debugging federated-identity IAM denials is harder than debugging a standard Google account's — CEL condition failures against `request.auth.claims` require the caller's token to actually carry the expected claims, which is one more thing to get wrong during IdP integration.

## Alternatives Considered

### Cloud Identity accounts for every loan officer (no federation)
Rejected outright — this is precisely the duplicated-directory anti-pattern. Every hire, transfer, and termination would need to be manually mirrored into Cloud Identity, with no guarantee the mirror stays current. FFIEC examiners treat unsynchronized secondary directories as an access-control deficiency.

### IAP as the sole identity plane, with grant_access reading the IAP-injected identity header
Considered for a v2 where a browser-based request form exists. Rejected for Week 1 because it still requires the underlying Cloud Identity provisioning problem described above, and this scope has no browser UI yet — grant_access is a direct API call, which is what WIF is built for.

### Service account impersonation only, no end-user identity in the condition
Rejected because it would mean IAM conditions authorize *"this function," not "this loan officer for this loan"* — collapsing the resource-bound, per-officer grant model this repo is built around back into a single shared service identity, which defeats the audit and least-privilege goals entirely.
