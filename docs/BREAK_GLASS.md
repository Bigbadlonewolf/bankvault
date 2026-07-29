# Break-glass

**Nothing in this document is implemented, and that is deliberate.** A break-glass path is a permanent, pre-authorised bypass of the control the rest of this repo exists to enforce. Shipping one into a reference architecture — where it would be copied without the operational scaffolding that makes it safe — creates the exact standing access BankVault removes, and hands it a justification.

What follows is the decision framework, not code.

---

## What actually needs a break-glass here

Worth being precise, because "what if the system is down" covers several different failures with different answers, and only one of them needs a break-glass at all.

| Failure | Does the underwriter lose access? | Break-glass needed? |
| --- | --- | --- |
| `request_broker` is down | **No.** ADR-006: the broker is a pre-flight gate, not a chokepoint. PAM is reachable directly | No. You lose the 900-second `auth_time` ledger row — evidence granularity, not the control |
| `reconcile` is down | No | No. Detection stops; enforcement is PAM's, and it continues |
| BigQuery ledger unavailable | Depends on the broker's write path | No. Grant creation does not depend on it |
| **PAM is unavailable** | **Yes.** No grants can be created | **Yes.** This is the case |
| **The IdP is unreachable** | **Yes.** ACM reauth cannot complete, so no fresh session exists | **Yes**, and it is the more likely of the two |
| The approver is unavailable | Yes, for approval-gated entitlements | Partially — PAM supports multiple approvers, which is the cheaper fix |

**Two failures matter, and neither is in this repo.** Both are platform or identity-plane outages. That shapes everything below: a break-glass for BankVault is not a BankVault feature, it is an organisational control that happens to be needed because BankVault removed the standing access that used to paper over these outages.

That is worth stating rather than hiding. Removing standing access converts a class of quiet degradation into a visible outage. The outage is the correct behaviour — an identity control that keeps granting when it cannot verify who is asking has a bypass, and the bypass opens under exactly the conditions an attacker wants (ADR-004). But the organisation has to decide what happens during it, and "nothing" is only an acceptable answer if a loan decision can wait.

---

## Option A — Standing emergency account under two-person control

A pre-existing account holding the credit-report read role permanently, whose credentials are split so no single person can use it.

**Requires:** credential split across two custodians (physical safe, sealed envelopes, or a secret-sharing scheme); an out-of-band procedure both can execute during an outage; independent alerting on any use that does not route through the account being used; a post-use rotation commitment with a named owner.

**Risks:** the account holds standing access to borrower credit reports permanently — the precise thing this architecture removes. Its access review is the weakest link in the whole design, because it is the one identity that never expires. Two-person control degrades quietly if one custodian leaves and the handover is informal.

**Use when:** the outage window is measured in hours and there is a genuine SLA on loan decisions that cannot absorb it.

**Do not use when:** you cannot commit to rotating after every use. An emergency credential used twice without rotation is a shared password.

---

## Option B — Offline hardware tokens

Hardware security keys held in a safe, bound to accounts that are otherwise dormant, providing the authentication factor that ACM cannot when the IdP is unreachable.

**Requires:** physical custody with a signed chain of custody; tokens enrolled and tested on a schedule, because an untested token is discovered dead during the incident; a documented path from "hold token" to "read the report" that does not itself route through the failed IdP.

**Risks:** physical access becomes the control, which moves the threat model from identity to premises. Tokens go stale — enrolment lapses, firmware ages, the person who knows the procedure changes role. This is the option most likely to be technically sound and operationally dead.

**Use when:** the IdP is the failure you are planning for, and there is a real physical-security programme to hang custody on.

**Do not use when:** nobody owns quarterly testing. An untested token is worse than no plan, because it is a plan people believe in.

---

## Option C — Documented degradation, no bypass

Accept that access stops. Have a communications procedure, an escalation path, and a decision-maker who can invoke Option A or B if the outage runs long.

**Requires:** honesty about the SLA, and a named person authorised to say "we are waiting."

**Risks:** the loan decision waits. In a genuine multi-hour outage this is a business impact somebody will escalate, and if there is no pre-agreed answer the escalation invents one under pressure — which is how unreviewed emergency access gets granted at 2am.

**Use when:** the outage is likely to be short, or the business genuinely tolerates the delay.

**This is the honest default for a reference architecture**, and it is what this repo implements by omission. Not because it is the best answer for a real bank, but because the alternative is shipping a bypass that gets copied without its safeguards.

---

## Choosing

1. **What is the actual SLA on the loan decision?** If it is a business day, Option C is sufficient and the other two are unjustified risk.
2. **Which outage are you planning for?** IdP failure is more likely than PAM failure and argues for Option B. PAM failure argues for A.
3. **Can you commit to the operational cost?** Option A needs rotation after every use. Option B needs quarterly testing. Neither survives being set up once. If the answer is no, choose C and mean it.
4. **Who decides during the incident?** Every option needs a named person. Without one, the default is whoever is most senior on the call, improvising.

---

## If you implement one

Non-negotiable regardless of which:

- **Use is alerted independently.** The break-glass path must not be able to suppress its own alert. This repo's `bankvault_platform_logs` export exists for exactly this shape of problem — an independent record application code cannot touch.
- **Use triggers a post-incident review.** Automatically, not by convention.
- **Credentials rotate after every use**, with an owner and a deadline.
- **The path is tested on a schedule.** An untested break-glass is a documented plan and an undocumented outage.
- **It appears in every access review**, flagged as standing access, so it never becomes background furniture.
- **Its own ADR.** The trade-off is real and someone will ask why in a year.
