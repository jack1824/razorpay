# FAIL MATRIX

> **Fail-open on judgment. Fail-closed on authority.**

Written **before any decision code exists**, alongside `THREAT_MODEL.md`. Derived from
`docs/strategy/13_FAILURE_MODES/FAIL_MATRIX.md`; this file governs the code in this repo.

---

## The principle, stated precisely

Every stage of the authorize pipeline is either establishing **authority** or forming a
**judgment**. The two get opposite treatment when they break:

- **Authority** — who you are, what you were granted, whether the money is there, whether
  the decision was recorded. If any of this is unavailable, the correct answer is *no*.
  Denying costs a sale. Allowing without authority is the failure the entire system exists
  to prevent.
- **Judgment** — how risky this looks, whether the text smells like an injection. If this is
  unavailable, the correct answer is to proceed on authority alone and *tighten* the
  bounds. Halting all commerce because a classifier is down is a worse outcome than
  accepting a residual risk that the ledger already bounds.

The asymmetry is only defensible because the ledger holds regardless. Losing judgment costs
you accuracy within a spend cap that is still enforced by arithmetic.

---

## Component failure

| Component down | Behaviour | Class | Rationale |
|---|---|---|---|
| **Risk model** | **FAIL-OPEN** → policy + budget only, tightened rate limits, `degraded_mode` recorded | Judgment | Classification is advisory. The residual is bounded because the ledger still holds. |
| **Injection detector** | **FAIL-OPEN** → heuristic rules only | Judgment | Same reasoning; blunt cases still caught |
| **Budget ledger** | **FAIL-CLOSED** → deny everything | Authority | Never permit unbounded spend. The system stops selling rather than sell without a limit. |
| **Signature verification** | **FAIL-CLOSED** | Authority | Identity is not optional |
| **Mandate store** | **FAIL-CLOSED** on miss; serve cached mandates read-only if the cache is warm | Authority | Cannot verify authority → cannot authorize |
| **Redis** | **DEGRADE** → stateless per-request policy + conservative global rate limit | Judgment | Lose behavioural context, keep authority |
| **Postgres** | **FAIL-CLOSED** on writes | Authority | Cannot reserve budget → cannot authorize. See the note below: this also means the denial cannot be recorded. |
| **LLM explainer** | **NO EFFECT** on decisions; explanations queue | Off-path | Proves the LLM is off-path. Killing it is a demo beat. |
| **Policy compiler** | Last signed version continues serving | Build-time | Compilation is a build-time activity |
| **Razorpay API** | Reservation held, decision recorded, retry with backoff; release on timeout | Authority | Never leak a reservation |

---

## Postgres down: the consequence the strategy package does not state

When Postgres is unavailable, stage 6 (budget reservation) fails closed and every request
denies. Correct. But stage 8 — **record the decision** — is *also* Postgres, and it is also
fail-closed. So those denials **cannot be written to the chain.** For the duration of the
outage the system denies and produces no audit record of having done so.

This is accepted, not worked around. The reasoning:

> An unrecorded **DENY** is safe — nothing moved. An unrecorded **ALLOW** would be the worst
> outcome in the system. That asymmetry is why fail-closed is doubly correct here.

Buffering the denials to Redis to "not lose them" was considered and **rejected**: it would
create exactly the class of unsigned, mutable, un-chained record that the audit design
exists to eliminate. A record we cannot sign into the chain is not a record. We would rather
have a gap we can explain than an artifact we cannot verify.

The gap is bounded and visible — the chain's `seq` is contiguous per merchant, so an outage
shows up as *absence*, never as a break.

---

## Specific failure scenarios

| Scenario | Response |
|---|---|
| Model returns garbage (NaN, out of range) | Range validation → treat as unavailable → fail-open path, `degraded_mode='risk_model_unavailable'` |
| Tool call times out | Reservation released via a **compensating ledger entry**, never an UPDATE; recorded |
| Duplicate webhook | Absorbed by `idempotency_key UNIQUE` — the most common real payment-integration bug; explicitly tested |
| Agent behaves unexpectedly but within mandate | **Allowed.** This is correct. Dwaar enforces authority, not taste. |
| Conflicting signals (low risk score, policy deny) | **Policy wins.** Deterministic rules override probabilistic ones, always. |
| Confidence low (0.55–0.80) | `step_up` — ask the principal rather than guess |
| Clock skew between agent and gateway | ±120s tolerance; outside → deny with a distinct reason code |
| Ledger row lock contention on a hot mandate | Serialised per mandate by design. If `UNIQUE (mandate_id, prev_entry_id)` ever raises, **the locking is wrong** and the database caught it instead of silently overspending. |
| Two workers append to the chain simultaneously | Serialised by `pg_advisory_xact_lock(hashtext(merchant_id))`; `seq` allocated explicitly under the lock, never by `BIGSERIAL` |

---

## Why `seq` is not a `BIGSERIAL`

`BIGSERIAL` allocates outside transaction control. With `uvicorn --workers 4`, concurrent
inserts commit out of `seq` order and rolled-back transactions leave permanent gaps — while
`prev_hash` requires strict serialisation against `seq - 1`. The chain would have been
broken by construction the first time two requests overlapped.

`seq` is therefore allocated as `max(seq) + 1` **inside** an advisory lock held for the
duration of the transaction, scoped per merchant. Chains are per-merchant; the verifier
iterates chains. With one merchant in the demo this is indistinguishable from a single
chain, and it means the honest answer to "does this scale" is *"the chain is already
sharded by merchant"* rather than a promise.

---

## `FAILURES.md`

Started empty on day 0 and appended to as things break. **Never backfilled.** Written
honestly and in real time it is a scoring artifact against the "Failure Recovery" criterion,
not an apology. It records what broke, what we got wrong, and what we would do with two more
weeks.
