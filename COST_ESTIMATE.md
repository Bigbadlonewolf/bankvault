# Cost Estimate

Derived from the resources in `terraform/` and published GCP list prices (`us-central1`, July 2026). **This project has never been deployed** — see README § What this isn't — so every figure here is computed from the configuration, not measured from a bill. Where a price is the dominant term, it is named so the arithmetic can be checked.

---

## The short answer

| Scenario | Monthly |
| --- | --- |
| Idle — deployed, nobody requesting anything | **~$0.60** |
| One underwriter, ~20 requests/day | **~$1** |
| 200 underwriters, ~2,000 requests/day | **~$14** |
| 200 underwriters, with reconcile at 1-minute cadence | **~$28** |

The pipeline is cheap because it is event-driven and the events are human-paced. A privileged-access broker handles requests at the rate people ask for things, which is several orders of magnitude below anything that makes serverless pricing interesting.

**The cost that actually matters is not on this page.** Access Context Manager's reauth binding forces every underwriter in the bound group to reauthenticate hourly across their entire Google Cloud session (README § Honest limits). At 200 underwriters that is a recurring interruption to people whose time is worth considerably more than $14/month. The dollar cost of this architecture is a rounding error; the human cost of the control it depends on is the real number, and it is not denominated in dollars.

---

## Idle cost

What accrues with zero requests. This is the honest floor — the number you pay for having deployed it.

| Resource | Driver | Monthly |
| --- | --- | --- |
| Cloud Scheduler (`reconcile`) | 3 jobs free; this is 1 | $0 |
| Cloud Functions v2 — reconcile | 2,880 invocations/month at `*/15`, each a few hundred ms. Free tier: 2M invocations, 400k GB-seconds | $0 |
| Cloud Functions v2 — request_broker | 0 invocations | $0 |
| BigQuery storage — `access_grants` | Kilobytes. Free tier: 10 GiB | $0 |
| BigQuery storage — `bankvault_platform_logs` | Log sink export. Tens of MB/month idle | $0 |
| GCS — `credit_reports` | Test objects only, versioned | ~$0.02 |
| GCS — `function_source` | Two zipped functions, <1 MB | ~$0.01 |
| GCS — `platform_logs_worm` | Retention-locked WORM copy of the log stream | ~$0.05 |
| Pub/Sub — `reconcile_trigger` | 2,880 tiny messages. Free tier: 10 GiB | $0 |
| Cloud Logging | Sinks route logs out; ingestion free tier is 50 GiB | $0 |
| PAM entitlement | No charge for the entitlement itself | $0 |
| **Total** | | **~$0.60/mo** |

Rounding up for the odd egress byte and API call. The floor is effectively "the price of three nearly-empty buckets."

**Cloud Scheduler is free only because this is one job.** The free tier is three jobs *per billing account*, not per project. If you already run three schedulers elsewhere, this one costs $0.10/month.

---

## Per-request cost

One underwriter requesting access to one credit report:

| Step | Charge |
| --- | --- |
| `request_broker` invocation | ~$0.0000004 (2M/month free) |
| Compute: 256 MB × ~400 ms | ~$0.000002 (400k GB-s/month free) |
| JWKS fetch to the IdP | Egress, sub-cent per thousand |
| BigQuery streaming insert, one row | ~$0.000000025 at $0.05/GB, row well under 1 KB |
| PAM `CreateGrant` + approval | No per-call charge |
| Object read from `credit_reports` | Class B op, ~$0.0000004 |

**Roughly $0.000003 per request.** Two thousand requests a day is about $0.18/month in request-driven cost. Everything else on the bill is fixed.

This is worth stating plainly because it inverts the usual build-vs-buy argument: the marginal cost of a JIT access request here is not a meaningful input to the decision. ADR-001 chose to build for reasons of control and auditability, not price — and the price would not have changed the answer either way.

---

## What scales, and what does not

| Term | Scales with | Notes |
| --- | --- | --- |
| Broker invocations | Requests | Human-paced. Never the dominant term |
| Ledger storage | Requests, cumulatively | ~1 KB/row. A million grants is ~1 GB — still inside the free tier |
| **Platform log export** | **All admin activity in the project**, not just this system | The one term that can surprise you |
| Reconcile invocations | Cadence, not load | 2,880/month at 15 min; 43,200/month at 1 min |
| WORM bucket | Log volume × retention period | Retention-locked, so you cannot delete early to cut cost |

**The log sink is the term to watch.** `google_logging_project_sink.platform` exports admin-activity logs to BigQuery, and it filters on activity in the project rather than on this system alone. In a dedicated project that is a few hundred MB a month. Dropped into a busy shared project it could be tens of gigabytes, and the WORM copy doubles it. The sink filter is the knob; check it before deploying anywhere other than an isolated project.

**Retention lock is a one-way door.** `platform_logs_worm` uses a retention policy specifically so records cannot be deleted early — that is the point, and it is what makes the bucket evidence rather than a log copy. It also means a mistake in the retention period is a mistake you pay for until it expires. There is no cleanup.

---

## The 1-minute reconcile question

ADR-005 lists a tighter sweep as a rejected alternative. The cost side of that decision:

| Cadence | Invocations/month | Compute | Detection floor |
| --- | --- | --- | --- |
| 15 min (current) | 2,880 | free tier | ~15 min |
| 5 min | 8,640 | free tier | ~5 min |
| 1 min | 43,200 | ~$0.10–0.40 | ~1 min |

A minute-by-minute sweep costs cents. **Cost is not why ADR-005 rejected it** — the reason is that detection is not containment, so buying a fourteen-minute-faster detection floor does not buy faster response, and pretending otherwise would be the overclaim the ADR exists to avoid. Recorded here so the cost table is not mistaken for the rationale.

---

## What this excludes

- **Google Cloud support.** Standard is $29/month minimum; a bank would be on Enhanced or Premium. That single line item is larger than every scenario above.
- **The IdP.** Workforce Identity Federation itself is free, but the identity provider behind it is not, and its per-seat cost dwarfs this infrastructure.
- **Access Context Manager.** No direct charge. The cost is operational, described at the top of this page.
- **Anything measured.** Nothing here comes from a bill. `terraform apply` has never run against this configuration.
- **Data egress beyond the JWKS fetch.** Credit reports are read within GCP in the modelled flow.

---

## Reproducing these numbers

```bash
cd terraform
terraform init
terraform plan -out=tfplan
terraform show -json tfplan | jq -r '.planned_values.root_module.resources[].address' | sort
```

Then price each resource against [cloud.google.com/pricing](https://cloud.google.com/pricing). If a figure here disagrees with the current price list, the price list is right — GCP pricing moves and this document does not.
