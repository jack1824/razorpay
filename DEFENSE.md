# Defence

Six decisions that are not obvious, with the alternative each one rejected. Where a choice
has a real cost, the cost is stated.

---

## 1. `reserve()` wraps its INSERT in a savepoint

**The decision.** The ledger insert runs inside a savepoint, so a unique-key collision rolls
back one statement rather than the transaction.

**What was rejected.** The obvious shape:

```python
try:
    INSERT INTO budget_ledger (...)          # idempotency_key is UNIQUE
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

**Why the savepoint.** `async with conn.transaction()` inside an open transaction issues a
`SAVEPOINT`. The violation rolls back to it, the transaction survives, and the winning row
can be read and returned.

**The better shape, and its cost.** `INSERT ... ON CONFLICT (...) DO NOTHING RETURNING *`,
then `SELECT` on an empty return. The transaction never enters a failed state at all, so no
savepoint is needed. That is what `decision_records` uses.

The ledger does not, and deliberately: a bare `ON CONFLICT DO NOTHING` would also swallow a
violation of `UNIQUE (mandate_id, prev_entry_id)` — the tripwire that fires only if the
mandate row lock is not holding, which means an overspend. That must never be absorbed
silently. Naming a specific conflict target is possible; the savepoint keeps the two
outcomes distinguishable with less SQL, at the cost of one extra round trip on the duplicate
path.

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
an assertion about the resulting column, so it cannot pass vacuously while the model is
stubbed.

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
