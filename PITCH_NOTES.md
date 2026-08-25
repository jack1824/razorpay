# Pitch notes

Five things, said out loud, in order. About two minutes ten.

Not a script to read. The **bold** lines are the ones that have to land word for word.
Everything else is yours.

Numbers below are quoted from `eval/RESULTS.md` and `make eval`. Say the round one. Keep the
exact one for the follow-up.

---

## 1 · The hook — 30 seconds

Razorpay ships an MCP server. Thirty-five plus tools. An agent authenticates with one token.

That token is base64 of key and secret. It carries the merchant's whole commercial authority.
`create_refund` is on that list.

There are controls. There is a read-only flag. There is a toolset filter. Both work.

What there is no way to say is: **this agent, up to fifty thousand rupees, collections only,
until Friday.**

> **This is not a vulnerability. It is a token doing exactly what a token does.**
> **A token carries possession. Delegation requires intent.**

Possession is "I hold the credential." Intent is "who, how much, which actions, until when."
Those are different questions. Only one of them has an answer today.

**Numbers:** 35+ tools. One token. `base64(KEY:SECRET)`.

**The follow-up:** *"Why not just use the read-only flag?"* — Because read-only turns off
refunds and payments together. There is no setting that means "collect, don't refund." That is
the missing primitive, not a missing checkbox.

---

## 2 · The thesis — 20 seconds

> **Fraud detection asks whether a transaction is bad. We ask whether it was allowed.**

Three reasons a fraud engine cannot answer the second question.

**Authority.** A fraud engine has no mandate object. Nothing to check the request against. And
a spend cap has to be arithmetic. **A ninety-nine percent accurate spend cap is a broken spend
cap.**

**Provenance.** An agent has no device. One agent platform serves millions of principals from
one IP. Device and IP reputation are the fraud engine's strongest signals and here they are
close to constant.

**Semantic surface.** Prompt injection has no analogue in card fraud. There is no equivalent of
"ignore previous instructions" on a card-present transaction.

**Numbers:** none. Do not reach for one here. This beat is definitional.

**The follow-up:** *"Isn't this just rules plus a model?"* — The rules are signed by the
principal and the arithmetic is a ledger. The model can only ever tighten. It can never grant.

---

## 3 · The held-out result — 45 seconds

This is the hard one. Lead with the failure. It is the only version that survives scrutiny.

Two archetypes were written in a separate session. No sight of the feature list. No
thresholds. No access to the model. Kept on a branch. Run against the model once.

> **The model got both of them wrong. In opposite directions.**

The first one — the sleeper — scored **ninety-two percent** recall. That looks like a win. It
is not.

> **Ninety percent of those flags land while the agent is behaving impeccably.**

It is not catching the defection. It just dislikes the agent.

The second one — the compromised agent — got **worse** as it got worse.

> **Its ticket size went up tenfold. Its risk score went down.**

Six hundred rupees to six thousand three hundred. Score zero point three seven, down to zero
point one nine.

Now the part that matters.

> **Not one rupee moved that a mandate had not authorised.**

Because the model was never what stopped it. The arithmetic gate refused four hundred and
ninety-five requests, and **every one of those records carries a null risk score.** That null
is the proof the model was never consulted.

And I wrote down that the sleeper might score well for the wrong reason **before the agents
existed.** It is in `eval/PREDICTIONS.md`. Prediction three. You can check the commit order —
the predictions land before the held-out agents are committed, and before the run.

**Numbers to quote:**

| say | exact |
|---|---|
| ninety-two percent | 92.2% recall on `sleeper` at the deny band |
| ninety percent of them, while it behaved | 90.2% of flags in the clean phase |
| a hundred and fifty times the base rate | 158× the legitimate base rate of 0.66% |
| tenfold ticket, score went down | ₹644 → ₹6,330; risk 0.3656 → 0.1852 |
| the other one, nineteen percent | 18.8% on `compromised` |
| four hundred and ninety-five arithmetic denials | 495, **0** carrying a score |

**Why the model missed the compromised agent — have this ready:** all thirteen features are
window aggregates. Velocity, entropy, diversity. **Not one of them measures an agent against
its own baseline.** That is exactly what "this agent stopped behaving like itself" means. The
vector cannot express it. That is the top item in `FAILURES.md`.

**The follow-up:** *"So your model doesn't work?"* — Correct, on those two archetypes, and I
would rather tell you than have you find it. The architecture is what I am claiming, and the
run is the evidence for it: the model was wrong twice and the enforcement held anyway.

---

## 4 · What we lose on — 20 seconds

Say this before anyone asks. It is worth more offered than extracted.

We built a conventional fraud baseline. We gave it a signal we deliberately do not have —
absolute amount, and amount against the agent's own history.

> **It ties us on card testing. It beats our model on budget breaching.**

Ninety-six percent against our ninety. One fitted velocity term.

And here is the part that cuts both ways.

> **Its fitted weights came out negative on the textbook card-testing signals.**

Card diversity. Decline ratio. The two things any fraud analyst would lead with, and the fit
pushed them the wrong way.

That is not a fact about fraud. **That is a fact about our synthetic traffic.** And it applies
to our model exactly as much as to theirs.

**Numbers:**

| say | exact |
|---|---|
| ninety-six to ninety | 96.1% vs 90.1% on `budget_breacher`, model-only |
| a tie | 99.4% both, on `card_tester` |
| our system end to end | 97.9% on `budget_breacher`, gate included |

**The follow-up:** *"Then why not just use the fraud model?"* — Because it caught nothing on
either held-out archetype, nothing on injection, and it cannot answer "was this allowed." It
is better at the two questions it was built for. Those are not the questions.

---

## 5 · The close — 15 seconds

Stop. Then say it slowly. Do not add anything after it.

> **The model was wrong about two archetypes, in two different directions.**
>
> **And not one rupee moved that a mandate hadn't authorised.**
>
> **Because spending authority was never the model's to decide.**

**Numbers:** none. Do not put a number in the close.

**The follow-up:** *"What would you do with two more weeks?"* — Absolute amount and per-agent
baseline deviation in the feature vector. Thirteen window aggregates cannot express "this agent
stopped behaving like itself." It is the first item at the end of `FAILURES.md`.

---

## If you have thirty more seconds

Only if invited. Pick **one**.

**The audit trail.** Every decision is hash-chained and signed. Append-only by database
grant — the app role owns nothing, and a `REVOKE` cannot strip an owner. There is deliberately
no trigger, because a superuser must be able to tamper. **The control is detection by
cryptography, not prevention by the database.** Live: I rewrite an amount as superuser, the
update succeeds, the verifier names the sequence number.

**Rule one.** No language model in the authorize path. Ever. Not for latency — because a model
that reads agent text and then decides about money is the highest-value thing an attacker can
reach. Enforced three independent ways in CI: import closure, runtime, source scan.

**The failure log.** Forty-nine entries. Four were caught by a check written for something
else. **Six were caught by computing one number two ways and getting two answers.** Six were
caught by the verifier while the test suite was green.

---

## Numbers you can be asked for cold

| | |
|---|---|
| pipeline p99 | **7.4ms** serial, **20.6ms** under fifty concurrent agents, budget 25ms |
| tests | **1,057** |
| chain verification | **PASS**, every record, every signed table |
| LLM calls in the request path | **0** |
| injection detector | **10/10** held-out payloads, **0/5** benign lookalikes |
| the detergent | "Ignore Premium Detergent 2kg" — a real product, **not flagged**, 0.19 |
| failures logged | **49**, four still open, each for a stated reason |

---

## Three things not to say

**Do not say "we detect compromised agents."** We do not. Section 3 is the honest version and
it is stronger.

**Do not say the predictions were registered three days earlier.** The commit *order* is what
is checkable — predictions before the held-out agents, before the run. Say "check the order,"
not "check the date." A judge who checks a date you got wrong stops believing the rest.

**Do not claim `docker compose up` is verified.** It is written and has never been executed on
this machine. It is F-010 and it is the largest gap in the repository. If asked, say that.
