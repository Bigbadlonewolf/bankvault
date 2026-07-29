# Session recording

**BankVault does not record sessions, and cannot.** It grants a permission. What the underwriter does inside the thirty minutes that permission is live is observed at the object-read level and nowhere else.

This page exists because "just-in-time privileged access" is a phrase enterprise PAM products use, and those products *do* record sessions. Reading BankVault as if it inherits that capability is an easy mistake to make, so the boundary is drawn here explicitly rather than left as an absence.

---

## What is actually observed

Three layers, each narrower than it sounds.

| Layer | What it records | Where |
| --- | --- | --- |
| Broker ledger | That a request passed pre-flight, and the `auth_time` that gated it | BigQuery `access_grants` — `REQUEST` / `DENY` rows |
| PAM admin-activity audit | That a grant was created, by whom, against which entitlement, with what expiry | Cloud Logging → `bankvault_platform_logs` + the WORM bucket |
| **GCS `DATA_READ` audit** | **Every object read inside the grant window** — principal, object name, timestamp | Same sink, same two destinations |

The third is the one that matters here, and it is provisioned: `google_project_iam_audit_config.storage_data_read` in [`terraform/logging.tf`](../terraform/logging.tf) enables `DATA_READ` for `storage.googleapis.com`. Without it, PAM would log that a grant existed and nothing would log that anything was read under it — a thirty-minute observation hole in the middle of the control.

So the honest claim is **object-level access logging**, not session recording. You can answer "did this underwriter read `APP-1001/credit-report.pdf`, and when." You cannot answer anything about what happened next.

---

## What is not observed

Everything after the bytes leave GCS.

- **The content.** No DLP inspection, no classification, no field-level record of what was in the file.
- **What was done with it.** Downloaded to a laptop, screenshotted, pasted into an email, photographed off the screen — all invisible. The audit trail ends at the read.
- **Bulk reads within scope.** The IAM Condition scopes the grant to one application's object prefix. Reading every object under that prefix is *inside* the grant. `DATA_READ` records each one, so the evidence exists, but nothing alerts on the shape and nothing stops it.
- **The device.** No managed-device requirement, no context-aware access policy. A valid session from an unmanaged machine is a valid session.
- **Anything at all with the broker skipped.** The bypass path (README § Honest limits) still produces PAM audit events and `DATA_READ` records — the platform layers are not skippable — but no `auth_time` row. `reconcile` flags this as `BYPASS_FLAG`.

**This is the capability [ADR-001](adr/001-build-vs-buy-jit-broker.md) gave up.** Enterprise PAM brokers SSH/RDP/database sessions through a proxy, and a proxy can record what crosses it. BankVault deliberately does not proxy anything — it changes an IAM policy and gets out of the way. That is why the grant is cheap, has no agent footprint, and adds no availability dependency to the read path. It is also why there is nothing in the middle to record. You do not get both.

---

## What production would need

Roughly in order of what buys the most per unit of effort.

**1. Stop handing humans raw object access.** The single largest change, and the one that makes the rest easy. If underwriters read credit reports through an application that renders them — rather than through `gsutil` and a browser — then the application is the recording layer. It logs every render, per field, per user, and can watermark on the way out. The PAM grant then elevates the *application's* view of the user, not the user's access to a bucket. Everything below is a consolation prize for not doing this.

**2. VPC Service Controls.** A perimeter around the credit-report project stops the read from being exfiltrated to a bucket outside it. It does not observe the session, but it bounds where the data can go, which is usually the actual worry behind "we need session recording."

**3. Context-aware access with a managed-device requirement.** Binds the grant to a device the organisation can inspect, which turns "screenshotted to a personal laptop" from invisible into policy-violating. Note this compounds the ACM cost already documented in the README — it lands on the group's whole session, not on the credit-report path alone.

**4. DLP inspection on the objects.** Classifies what is in each report so the audit trail says "read a document containing 1 SSN and 1 full credit file" rather than "read `APP-1001/report.pdf`." Cost scales with object volume, not with grant volume.

**5. Anomaly detection on `DATA_READ`.** The records are already in BigQuery. Nothing queries them. An underwriter reading forty objects in one grant window is inside policy and outside normal, and only a query knows the difference. This is the cheapest item on the list and the one most likely to actually get built.

---

## Two things to know before enabling `DATA_READ` anywhere real

**It is chargeable and it is project-wide.** `DATA_READ` audit logs are not in the free ingestion tier, and the audit config here applies to `storage.googleapis.com` across the whole project — every read of every bucket, not just credit reports. In an isolated project that is fine. Dropped into a shared project with busy buckets it is the largest line on the bill (see [`../COST_ESTIMATE.md`](../COST_ESTIMATE.md) § What scales).

**It records reads, not intent.** A `DATA_READ` entry proves an object was fetched by a principal. It does not prove a human looked at it, and it does not distinguish a deliberate read from a client library prefetching. For evidence purposes that distinction rarely matters. For an accusation it matters a great deal.

---

## Summary claim

The defensible sentence is: *access to each credit report is time-bound, object-scoped, approval-gated, and every read under that grant is logged to an immutable store.*

The sentence to never write is: *underwriter sessions are recorded.* They are not, no code here records them, and the architecture that would record them was rejected on purpose.
