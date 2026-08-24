# Defence

Eight decisions that are not obvious, with the alternative each one rejected. Where a choice
has a real cost, the cost is stated.

---

## 1. The ledger's `ON CONFLICT` names its constraint

**The decision.** The ledger insert is

```sql
INSERT INTO budget_ledger (...)
ON CONFLICT ON CONSTRAINT budget_ledger_mandate_idempotency_unique
DO NOTHING RETURNING *
```

and the conflict target is **named**, never bare.

**What was rejected, first.** The obvious shape:

```python
try:
    INSERT INTO budget_ledger (...)          # (mandate_id, idempotency_key) is UNIQUE
except UniqueViolation:
    return SELECT ... WHERE idempotency_key = ?   # return the original
```

This cannot work, and it fails in a way that reads as correct. In PostgreSQL a failed
statement poisons the **entire transaction**: every subsequent command returns
`InFailedSqlTransaction` until a rollback. The `SELECT` written to recover from the duplicate
is unreachable the moment the duplicate occurs. The handler for the failure is disabled by
the failure.

Duplicate webhooks are the most common bug in payment integrations, so this path is not
exotic — it is the one that runs whenever a network retries.

**What was rejected, second, and this is the interesting one.** A bare
`ON CONFLICT DO NOTHING`. It fixes the transaction-state problem and introduces a worse one.

This table carries two unique constraints, and they mean opposite things:

| Constraint | Fires when | Correct response |
|---|---|---|
| `(mandate_id, idempotency_key)` | a webhook was delivered twice | absorb it, return the original |
| `(mandate_id, prev_entry_id)` | two writers computed a balance from the same predecessor | **abort loudly** |

The second is a tripwire. Under a held mandate-row lock it can never fire; if it fires, the
lock is not holding, and two transactions have each written a balance derived from the same
tail. That is an overspend the `CHECK (balance_after >= 0)` cannot catch, because each row
satisfies it individually.

`ON CONFLICT DO NOTHING` with no target absorbs **both**. The tripwire insert would be
silently skipped, `RETURNING` would come back empty, the code would look up the "existing"
row and hand the caller `duplicate=True`. A detected overspend would be reported as a
successful idempotent retry. That is the single worst outcome available in this file.

Naming the constraint absorbs exactly one of the two and leaves the other raising, so the
database distinguishes them rather than the application inspecting
`exc.diag.constraint_name` after the fact. `tests/db/test_ledger_concurrency.py` forces the
tripwire with a stale tail and asserts it still raises.

**On the savepoint this replaced.** An earlier version wrapped the insert in
`async with conn.transaction()`, which issues a `SAVEPOINT`, so a `UniqueViolation` rolled
back one statement and left the transaction usable. That was correct, and it was not the
best available shape. The named target is better on every axis: the transaction never enters
a failed state at all, there is no extra round trip on the duplicate path, and the two
constraints are separated by the database instead of by string-matching an error field. It
was changed rather than defended.

**One thing worth conceding.** Since the idempotency constraint was scoped from global to
`(mandate_id, idempotency_key)`, the `DO NOTHING` branch is unreachable under correct
locking — any other writer of that key must hold the same mandate lock, so it either
committed before the under-lock re-check saw it or is still blocked behind us. The branch is
kept, because a duplicate webhook must not become an error just because our locking is
suspect, but it now logs a warning: reaching it means the mandate lock is not serialising
writers. It is a second tripwire wearing a recovery path's clothes, and it is labelled as
one in the code.

---

## 2. The chain's advisory lock is keyed on `merchant_id`, and `seq` is not a sequence

**The decision.** `decision_records.seq` is `BIGINT`, allocated as `max(seq) + 1` inside
`pg_advisory_xact_lock(hashtext(merchant_id))`, held for the whole transaction.

**What was rejected.** `seq BIGSERIAL`, which is what the obvious schema says. It breaks the
chain by construction, three separate ways:

- **`nextval` is non-transactional.** Two concurrent requests take `seq = 5` and `seq = 6`
  and may commit in either order. Whichever computes `prev_hash` first computes it against a
  predecessor that is not yet visible.
- **A rolled-back transaction burns its value permanently.** `seq = 5` is consumed and never
  written, so the record at `seq = 6` links to a row that does not exist. `prev_hash` must
  be the hash of the preceding record; a gap makes that record unverifiable forever.
- **Append-only means unfixable.** The application has no `UPDATE` grant on this table, so a
  forked chain cannot be repaired. It is truncate-and-regenerate, not a migration.

This is not a high-concurrency edge case. The service runs `uvicorn --workers 4`, and it
happens at one worker too — async handlers with a connection pool interleave freely.

**Why per-merchant rather than global.** A single global lock would serialise every decision
in the system through one point. Keying on merchant costs one `hashtext` call and shards the
chain: the verifier iterates chains instead of walking one. With a single merchant the two
are indistinguishable, and the honest answer to *"does this scale"* becomes a fact about the
schema rather than a promise.

**The cost.** Decisions for one merchant are serialised at the chain write. Measured at
~1.2ms of a 3.6ms p99, so there is headroom, but a single merchant at very high volume would
hit this before anything else. The next step is sharding the chain below merchant — which
the schema already permits, since `seq` is scoped by `(merchant_id, seq)` rather than
globally unique.

---

## 3. There is no `BEFORE UPDATE` trigger on `decision_records`

**The decision.** Append-only is enforced by role grant: `dwaar_app` is **not the table
owner** and holds `SELECT, INSERT` and nothing else. There is deliberately no trigger.

**What was rejected, twice.** First, the version that looks like a control and is not:

```sql
REVOKE UPDATE, DELETE ON decision_records FROM PUBLIC;
```

`PUBLIC` holds no table-level `UPDATE`/`DELETE` to begin with, so this revokes nothing. And
`REVOKE` never strips the **table owner**, who keeps every privilege unconditionally. An
application connecting as the owner — the default in essentially every simple setup — has an
audit log it can rewrite at will. Non-ownership is the only thing that makes the grant mean
anything.

Second, and less obviously: a `BEFORE UPDATE ... RAISE EXCEPTION` trigger. It is strictly
stronger at blocking writes, and it is rejected on purpose, because it would also block a
superuser.

**Why blocking the superuser is the wrong goal.** The control being demonstrated is
**detection by cryptography, not prevention by DBMS**. An append-only log that only stops its
own application from editing it proves nothing about an attacker who owns the database —
which is the adversary the hash chain exists for.

So the tamper is performed from a separate superuser connection, it *succeeds* at the
storage layer, and the chain and the independent verifier catch it and name the exact row.
Preventing the write would destroy the only evidence that the detection works.

The two are different controls answering different threats. The grant bounds what the
application can do. The chain bounds what an attacker with database access can do without
being caught. Only one of them can be demonstrated.

**The cost.** A compromised superuser can still corrupt data. It cannot do so *undetectably*,
which is the property being claimed — and it is a weaker property than immutability, stated
plainly rather than implied.

---

## 4. The per-transaction cap is checked before scoring, not inside `reserve()`

**The decision.** A pure arithmetic gate runs immediately after the mandate resolves and
before any feature computation or scoring. It checks the per-transaction cap, the category
allow/deny lists and expiry — everything derivable from the mandate alone — and
short-circuits the remaining stages entirely.

**What was rejected.** Leaving all of it to `reserve_budget` at stage 6, which is where a
spend cap naturally belongs.

Two problems. The smaller: it means scoring a request that is arithmetically impossible,
spending ~2ms of a 25ms budget on a model whose answer cannot change the outcome.

The larger: `reserve()` compares the amount against the **remaining balance**, not against
the per-transaction cap. A ₹12,000 request under a ₹5,000 per-transaction cap with ₹50,000
remaining would have been **allowed**. The cumulative cap and the per-transaction cap are
different limits and only one of them lives in the ledger.

**Why `risk_score IS NULL` is load-bearing.** Because the gate runs before scoring, a record
denied on the mandate's own terms carries `risk_score = NULL` — and that NULL is the
audit-trail proof that the limit was enforced by arithmetic rather than inferred by a model.
It is checkable by anyone reading the record, without trusting the code that wrote it.

Left at stage 6, the model would run first and the record would carry a score. The claim
*"denied by arithmetic, the model was never consulted"* would be false, and nothing would
have failed — the pipeline would work, the deny would be correct, and only the evidence
would be wrong.

**The distinction this creates, which is worth stating precisely:**

| Denial | Where | `risk_score` |
|---|---|---|
| per-transaction cap, category, expiry | the gate, **before** scoring | `NULL` |
| cumulative budget exhaustion | the ledger, **after** scoring | present |

Both are arithmetic. They sit at different points because one needs only the mandate and the
other needs the ledger.

**The cost.** Authority logic is now in two places. That is a real maintenance hazard, and it
is mitigated structurally: every gate rule uses a stable `mandate.*` prefix in `rule_fired`,
and a test asserts `score_risk` is *never invoked* on a cap breach — a spy on the call, not
an assertion about the resulting column, so it could not pass vacuously while the model was
stubbed, and it now runs against a model that genuinely scores.

**The second half of the same idea, which is easier to get wrong.** Short-circuiting before
the model is only half the claim. The other half is that the model cannot *learn* the gate:
if a feature restated the per-transaction cap or the category lists, the model would predict
the gate rather than describe behaviour, accuracy would look excellent because predicting a
deterministic function is easy, and the feature importances would become a description of a
rule.

So the feature layer cannot see a mandate. Not "does not read one" — `compute()` has no
parameter for it, no connection, no Redis client, and nothing it imports can reach the
database or the authority stage. The proof that the wiring still honours it is behavioural:
a test holds one request stream fixed, runs it under two mandates whose caps differ across
the gate boundary — so the decisions genuinely differ — and asserts the feature vectors are
identical.

That test also pins an ordering that is easy to get backwards. The rolling window is written
*before* the gate, not inside the feature stage. Written after, the window would contain only
gate-permitted requests, every feature would be conditioned on the gate's own decision, and a
budget breacher whose requests mostly die at the gate would look like a quiet agent with
almost no history.

---

## 5. A valid signature did not mean an intact record

**The decision.** The verifier rebuilds each row's canonical form **from its columns** and
compares it to the stored signed bytes — before checking any hash or signature. Every table
carrying both a signed serialisation and extracted columns is registered in one place, and
the verifier iterates that registry.

**What was rejected.** Verifying the signed artifact and stopping there, which is what a
signature-checking verifier normally does. It was wrong here, and the failure is worth
walking through because it looks correct from every angle:

The verifier checked four things — the stored canonical JSON hashes to the stored
`payload_hash`, the canonical form is genuinely canonical, `prev_hash` links to the
predecessor, and the Ed25519 signature verifies. All four are real checks. All four passed
after this:

```sql
UPDATE decision_records SET amount_paise = 500000 WHERE seq = 4127;
```

`canonical_json` is untouched, so every hash still matches and the signature still verifies.
The verifier reports a clean chain. Meanwhile the row that every query, every report, every
console and every dispute reads now says the wrong amount.

**The general shape.** The signature attests to a **blob**. The application reads the
**columns**. When the two can diverge undetected, the signature protects a shadow copy nobody
looks at, and the audit trail is decoration.

It appeared three times in this codebase before being recognised as one bug: on `mandates`,
where an application role could extend its own expiry while the principal's signature kept
verifying; on `decision_records`, above; and on `policies`, which carried a signature with no
statement of what it signed. Three instances is a bug class, so the fix is a registry plus a
test asserting the registry is complete — not three fixes.

**The cost.** Storing `canonical_json` roughly doubles the row size, and the check is O(rows)
rather than O(1). At demo volume that is 1,005 rows verifying in well under a second; at
production volume it would need to be incremental, anchored, or both.

---

## 6. No language model in the request path, and two tests rather than one

**The decision.** No LLM call may occur during `/v1/authorize`. The model is used exactly
once, offline, to compile an English policy into a closed rule DSL, which is then executed
deterministically forever.

**Three reasons, in order of importance.** The order matters, because the usual first answer
is the weakest one.

1. **It makes the decision-maker the injection target.** The threat model assumes every byte
   of agent-supplied text is hostile — that is the premise of the whole product. A model that
   reads that text and then decides about money is the single highest-value thing an attacker
   could reach. This reason survives any improvement in latency or determinism, which is why
   it is first.
2. **It is non-deterministic on money.** Two identical requests could receive different
   answers, and a decision record would stop being replayable. Replayability is most of what
   makes the record evidence rather than a log line.
3. **500–2000ms against a 25ms budget.** True, and the least interesting of the three. If
   inference were free tomorrow, reasons 1 and 2 would be unchanged.

**Why two tests.** They prove different claims, and neither implies the other:

- **Static import closure** walks every request-path module's transitive imports and fails if
  any chain reaches an LLM client or a provider SDK. It proves the model is **not
  reachable** — including on paths no test request happens to take.
- **A runtime monkeypatch** replaces the client with something that raises and drives 1,000
  authorize calls across allow, gate-deny and category-deny paths. It proves the model was
  **not called**, including through dynamic dispatch the parser cannot see.

The static check is blind to `httpx.post("https://generativelanguage.googleapis.com/...")` —
no import, no edge in the graph, still a model in the hot path. The runtime check only covers
the requests it sampled. A third check, a source scan for provider hostnames, closes the
first gap bluntly.

**The cost.** Policy expressiveness is bounded by a closed DSL: anything the operator set does
not cover requires extending the language and shipping it, rather than writing a cleverer
rule. For mandate-scoped authorisation that is the right trade. For a general rules engine it
would not be.

**One thing worth conceding.** These are structural controls over a codebase that a
determined author can still work around — someone could open a socket. What the tests buy is
that doing so is a deliberate act which fails the build, rather than a convenience someone
reaches for at 2am while debugging.

---

## 7. The policy engine has a closed operator set instead of an expression language

**The decision.** Policies are a small JSON tree over sixteen operators and a fixed
namespace of variables. There is no `eval`, no attribute access, no function calls, no
user-defined names. An expression the operator set does not cover cannot be written at all.

**What was rejected.** CEL — Google's Common Expression Language — via `cel-python`. It is
the obvious choice. It is sandboxed by design, it is a real specification with real
implementations, and it would have taken an afternoon instead of two days.

**Reason one: it enlarges the hot path's import closure.** Rule 1 in this project — no
language model reachable from `/v1/authorize` — is enforced by walking the transitive
imports of every request-path module and failing the build if any chain reaches a provider
SDK. That check is only as good as our ability to reason about what the request path
imports. A general expression language brings a lexer, a parser, an AST, an evaluator and
their dependencies onto the path, and every one of them becomes a subtree we are asserting
about without controlling. This reason is real but it is the weaker of the two.

**Reason two, which is the actual argument: the author of these rules is a language model.**
The compiler takes a merchant's English policy and emits a ruleset. A human then reviews it
and approves it before it can serve traffic.

What that human is reviewing depends entirely on the target language.

With an expression language, review means answering *"what can this expression do?"* — and
for anything non-trivial that is a question about the language, not about the policy. The
reviewer has to think about evaluation order, coercion, what a comparison between mismatched
types yields, whether a clever nesting reaches something it should not. Every one of those is
a place where an approval can be correct about intent and wrong about behaviour. And the
adversary here is not a hostile author: it is a model that will occasionally produce
something syntactically valid and semantically surprising, in a file a busy human is about to
sign.

With a closed operator set, an emitted rule either **parses or is rejected**. There is no
third outcome. The parser is a whitelist, so anything outside the set is a load error, not a
subtle behaviour. That collapses review down to one question — *does this rule say what the
merchant meant?* — which is a question about the policy, and the only question a human
reviewer is actually qualified to answer quickly and repeatedly at 2am before a deadline.

This generalises past this project. When a model writes artifacts a human must approve, the
target language is a safety control, and the right target is the smallest language that can
express the domain. Expressiveness you do not need is review burden you cannot delegate.

**The cost, stated plainly.** Expressiveness. There is no arithmetic on the right-hand side,
no string manipulation, no way to write a rule that compares two request fields to each
other. A merchant policy that needs something the sixteen operators cannot say requires
extending the language and shipping a release — a code change and a deploy, not a
configuration change. For mandate-scoped authorisation, where the vocabulary is amounts,
categories, counts and flags, that ceiling has not been reached. For a general-purpose rules
engine it would be the wrong trade, and we would take CEL.

**What it does not buy.** A closed operator set does not make a generated rule *correct*. A
model can emit a perfectly parseable rule that permits what the merchant meant to forbid.
That is what the generated property tests and the mandatory human approval are for; this
decision only guarantees that the human is reviewing meaning rather than mechanism.

---

## 8. The risk model is trained on traffic we generated ourselves

This entry is a concession rather than a defence. The objection is correct and there is no
version of this project in which it is not.

**The situation.** There is no public corpus of autonomous-agent payment traffic at
meaningful scale. There is no proprietary one we have access to. So the behavioural model is
trained on synthetic traffic produced by a generator written by the same person who wrote
the model. Every accuracy number the model produces is, in the strictest reading, a
measurement of how well one program predicts another program written by the same author.

**What that objection destroys.** The model's precision, recall, AUC and per-archetype
breakdown. Those numbers describe our generator. If the real distribution differs — and it
will — they do not transfer, and we would not defend them if pushed. They are reported
because omitting them would be worse, and they are labelled as artifacts wherever they
appear.

**What it does not touch, and this is the part that matters.** The claims this project
actually rests on are properties of the code, and are true whatever traffic arrives:

| Claim | Why the objection does not reach it |
|---|---|
| A per-transaction cap breach is denied by arithmetic before any model runs | Structural. The record carries `risk_score = NULL`, checkable by anyone reading it. |
| Fifty concurrent writers against one ₹50,000 budget overspend by zero | Measured against PostgreSQL, not against a distribution. |
| The decision chain detects a tampered row and names it | Ed25519 and SHA-256. Traffic-independent. |
| The pipeline's p99 is under its budget with every stage named | Measured on real requests. |
| Every component's failure mode is the one documented | Enforced by the fail-matrix constant and asserted by tests. |
| No language model is reachable from the request path | Static import closure over the real source tree. |

The uncomfortable version, said out loud: **if the risk model were deleted entirely, every
claim in that table would still hold.** That is the design working as intended — the model
can only tighten a decision, never grant one — but it is also the honest answer to "how much
of this depends on the synthetic data". Very little, and the little that does is labelled.

**The mitigation, and its limit.** Two of the six agent archetypes — `compromised` and
`sleeper` — are held out. They are written in a session with no access to the model or its
features, kept on a branch, not merged, and not run against the model until evaluation day.
Their results are reported on a separate line, and those are the numbers worth reading.

The limit is that **this is a solo build.** The design called for the adversary and the
detector to have different authors, which is a genuinely strong control: two people cannot
accidentally share an assumption they never discussed. What is actually in place is
*isolation* — same author, no shared context, no access, no feedback loop — which is
strictly weaker. The same person can independently invent the same tell twice, and no
process control catches that. We are not claiming author separation anywhere, and this is
the entry that says so.

**The overlap requirement, which is the part most people miss.** The generator is required
to make roughly 3% of *legitimate* agents behave in adversary-like bursts, and those
requests **must** produce false positives. A generator whose classes are cleanly separable
would give a model near-perfect scores and would make the one number we have committed to
reporting honestly — the false-positive cost in rupees — pure fiction. A model that never
fires on a good customer has not been tested against good customers who look bad for an
afternoon. The overlap is asserted by the generator's tests, not assumed.

**What would actually settle it.** Traffic from a real agent platform, with real disputes as
labels, held out by someone with no stake in the result. Failing that, a shadow deployment
where the model scores but never decides, compared against the outcomes the deterministic
layer produced. Neither is available in a nine-day build, and neither is a reason to pretend
the synthetic numbers are something they are not.

---

### The part of this that is not a concession but a finding

Everything above is the answer to *"your data is synthetic."* This is the answer to the
sharper follow-up, which is *"so how would you even know?"*

Twice, the evaluation was measuring the generator rather than the behaviour. Both times the
code was correct, both times the number was computed at run time from real data, and both
times the number meant something other than what its label said.

**The anomaly score was a quantile wearing a model's clothes.** An isolation forest produces
a score on an arbitrary scale, so it has to be mapped into [0, 1] before a band can be drawn
on it. The obvious mapping is percentile rank among known-legitimate traffic — a sentence a
person can read. It is also *uniform on the population it was fitted to*, so it places
exactly 20% of legitimate traffic above a 0.80 threshold no matter how good the forest is.
Measured: 25%. Reported as an accuracy result, that number would have been a fact about
arithmetic, not about detection. One third of legitimate agents would have been denied on
stage.

**A feature carrying 74% of the model's gain was a fact about how the agents were coded.**
Every adversarial archetype held one cart identifier for its whole run, because that is how
each was written; the legitimate shopper rotated per session, because that is what a shopper
does. `cart_mutation_rate` became a near-direct readout of *which class the author had
written*. It was not behaviour. It was a placeholder that happened to differ per class.

**Neither was caught by an automated check, and one of them cannot be.** There is a leakage
gate — Cramér's V per feature against the archetype, and the trainer refuses to build a model
if any single feature exceeds the threshold. It works, and it did not fire: the cart feature
passed at 0.625 against a threshold of 0.75. That is the gate doing its job. It is built to
catch a feature that **is** the label, and this one merely correlated strongly with how the
generator was written.

**A leakage threshold catches a feature that is the label. It does not catch a feature that
correlates with how the generator was written, and no automated check will** — because the
check would have to know which of the differences between two classes were intended and which
were incidental, and that is the question the author is answering, not a property of the data.

So the control is a person reading the ranked importances after every retrain. That is not
automatable and it is not being claimed as rigour. What can be forced is the number being in
front of whoever is looking, so `make eval` prints the top ten importances on every run, and
a single feature above roughly 40% of total gain is treated as a generator artifact until
someone explains why it is not.

**The honest position, stated plainly: some almost certainly remain.** Two were found by
reading a table and asking why one number was large. There is no reason to believe that
process is exhaustive, and every number in this project that describes the *model* should be
read with that in mind. The numbers that describe the *system* — the ones in the table above —
do not depend on it, which is why they are the ones offered without qualification.
