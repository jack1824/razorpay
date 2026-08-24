# THREAT MODEL

Written **before any decision code exists.** That ordering is the point of the document.

This is the repo's own threat model. It is derived from `docs/strategy/12_SECURITY/THREAT_MODEL.md`
and diverges from it where `docs/adr/0001-phase-1-2-decisions.md` decided otherwise. Where
they conflict, this file governs the code in this repository.

---

## What this system is, stated so the architecture cannot drift

Dwaar answers exactly one question: **was this action within the authority the principal
delegated?**

It does not answer *"is this transaction bad?"* That is fraud detection, it is a different
product, and it has a different failure mode. The distinction is not marketing. It
determines what fails open and what fails closed, it determines what may be probabilistic,
and it determines what the audit record is evidence *of*.

Concretely, the drift test for any proposed change:

| If the change makes the system... | Verdict |
|---|---|
| ...decide using a signed grant of authority and arithmetic over a ledger | In scope |
| ...decide using a model's opinion about the transaction's character | **Out of scope** |
| ...able to *withhold* authority the principal granted | In scope (tighten only) |
| ...able to *grant* authority the principal did not | **Structurally forbidden** |

The model can never grant authority. It can only withhold it. Authority is granted by a
signed mandate and enforced by a ledger. A hallucinating model is therefore a degraded
experience here, not a security incident — and that is precisely why fail-open and
fail-closed split the way they do in `FAIL_MATRIX.md`.

---

## Trust boundaries

1. **Agent ↔ Dwaar** — the agent is fully untrusted, *including every byte of its free
   text*. The agent is the adversary in the majority of the threats below.
2. **Dwaar ↔ Razorpay** — mutual, credential-based. Dwaar holds the merchant credential;
   the agent never does. That inversion is the product.
3. **Dwaar ↔ database** — two roles, and the boundary is real, not conventional:
   - `dwaar_owner` owns every table and runs migrations. **The API never connects as it.**
   - `dwaar_app` is *not* the table owner. On `decision_records` it holds `SELECT, INSERT`
     and nothing else.
   This is the only reason `decision_records` is genuinely append-only. See "The
   append-only control" below — the strategy package's original formulation did not work.
4. **Merchant ↔ policy** — the merchant is trusted to *set* policy, but no policy goes live
   without passing generated tests and an explicit human approval recorded in
   `policies.approved_by`. A NULL there means not live.
5. **Principal ↔ mandate** — the principal is the root of authority. Compromise the
   principal key and you own the mandate. Nothing downstream can save you, and the design
   does not pretend otherwise. What it *does* do is bound the loss to that mandate's
   `max_total_paise`.

---

## The append-only control, and why the obvious version is theatre

The strategy package specifies:

```sql
REVOKE UPDATE, DELETE ON decision_records FROM PUBLIC;
```

**This does nothing.** `PUBLIC` does not hold table-level `UPDATE`/`DELETE` by default, so
there is nothing to revoke; and `REVOKE` never strips the **table owner**, who retains every
privilege unconditionally. If the API connects as the owner — the default in essentially
every simple Compose setup — the table is fully mutable and the control is fiction.

What this repo does instead:

```sql
CREATE ROLE dwaar_app LOGIN PASSWORD '...';        -- NOT the table owner
GRANT SELECT, INSERT ON decision_records TO dwaar_app;
-- no UPDATE, no DELETE, ever granted
```

`tests/db/test_append_only_grant.py` asserts that an `UPDATE` issued on the `dwaar_app`
connection raises `InsufficientPrivilege`, and that the same statement on the owner
connection succeeds.

### Why there is deliberately no trigger

A `BEFORE UPDATE ... RAISE EXCEPTION` trigger would be strictly stronger at blocking
writes — and it is **rejected on purpose**, because it would also block a superuser, and a
superuser must be able to tamper.

The control being demonstrated is **detection by cryptography, not prevention by DBMS.** An
append-only log that only stops its own application from editing it proves nothing about an
attacker who owns the database. So the tamper is performed from a separate superuser
connection, it *succeeds* at the storage layer, and the hash chain and the independent
verifier catch it and name the exact `seq`. Preventing the tamper would destroy the only
evidence that the detection works.

Grants bound what the *application* can do. The chain bounds what an *attacker with database
access* can do without being caught. They are different controls answering different
threats, and only one of them can be demonstrated.

---

## Threat table

| # | Threat | Impact | Likelihood | Mitigation | Detection | Recovery |
|---|---|---|---|---|---|---|
| 1 | **Forged agent identity** | Critical | Med | Ed25519 over RFC 9421 covered components + body digest; **fail-closed** | Signature failure counter | Auto-suspend the agent after N failures |
| 2 | **Replay attack** | High | Med | Per-request nonce + timestamp window + `idempotency_key UNIQUE`. See the gap note below — the per-request store is day 4. | Duplicate nonce counter | Reject; alert |
| 3 | **Stolen agent key** | Critical | Med | Behavioural drift detection; short mandate expiry; rotation with an overlap window (`previous_public_key`) | Risk model + change-point | Revoke key, cancel mandates, replay the chain to scope the blast radius |
| 4 | **Compromised legitimate agent platform** | Critical | Low-Med | **The ledger caps the blast radius even if the compromise is never detected.** | Behavioural drift | Revoke; loss is bounded by `max_total_paise` |
| 5 | **Prompt injection via catalogue or free text** | High | **High** | Injection classifier + delimiter neutralisation + provenance tagging — and, structurally, **there is no LLM in the decision path to inject into** | `injection_flag` | Quarantine, notify merchant |
| 6 | **Tool injection via MCP** | Critical | Med | Scope map, default-deny for unlisted tools, amount check on outbound tools | Denied-scope counter | Record and alert |
| 7 | **Budget circumvention via many small transactions** | High | High | **Cumulative** cap, not merely per-transaction. Both are arithmetic. | Ledger balance trend | The mandate exhausts; every further call denies |
| 8 | **Race / double-spend** | Critical | Med | `SELECT ... FROM mandates FOR UPDATE` serialises per mandate; `CHECK (balance_after >= 0)`; `UNIQUE (mandate_id, prev_entry_id)` tripwire; `idempotency_key UNIQUE` | 50-writer concurrency test; the tripwire firing at all | Transaction rollback |
| 9 | **Audit log tampering** | Critical | Low | Non-owner app role + hash chain + Ed25519 signature + independent verifier | Continuous chain verification | The chain break names the exact `seq`; anchors bound the damage window |
| 10 | **Policy-boundary probing** | Med | High | Coarse reason codes outbound, fine-grained inbound; continuous rather than thresholded scoring; cumulative budget | Probe-pattern feature | Throttle |
| 11 | **Model hallucination** | Med | n/a | **The model cannot authorize anything. It can only tighten.** Authority is deterministic. | — | Structurally prevented |
| 12 | **Rate-limit abuse / DoS** | Med | High | Redis token bucket per `(agent, principal)`; request body size caps enforced in middleware from day 1 | Prometheus counters | 429 + backoff |
| 13 | **Credential theft (merchant token)** | Critical | Med | The MCP proxy means the agent never holds the raw token — **this is the product** | Anomalous tool mix | Rotate; the proxy bounds exposure meanwhile |
| 14 | **Data leakage via logs** | High | Med | Structured logging with a field **allowlist**, not a denylist; PII scan in CI | Log scan job | Rotate, purge |
| 15 | **Insider misuse** | High | Low | Policy changes require human approval, are signed with an identity, and are chained | Policy version diff | Revert to the prior signed version |
| 16 | **Signing key rotation breaks the audit trail** | High | Low | `decision_records.signing_key_id` FK to `signing_keys`. The verifier resolves the key per record rather than assuming one. | Verifier reports unknown `key_id` | Retired keys stay in the table forever; verification of old records is unaffected |

Threat 16 is not in the strategy package. It was added because the verifier is a headline
artifact and would silently break on the first key rotation.

---

## Known gaps, recorded rather than hidden

**Per-request replay has no store yet (threat 2).** `mandates.nonce` is a nonce *per
mandate*, not per request. `budget_ledger.idempotency_key` only exists for requests that
reach a ledger write — so a replayed request that is **denied** writes no ledger row and is
not caught by it. The ±120s skew window needs a seen-nonce set keyed on
`(agent_id, nonce)` with a TTL of twice the window. Redis `SETEX` is the right home. This
lands on day 4 with the rest of the crypto layer. It is not Phase 2 blocking and it is not
fixed here.

**Rate limiting is not implemented in Phase 1.** Only the request body size cap is. Threat
12's token bucket lands with Redis in the request path.

**The console auth is a static token** and is not a real authentication system. Single
tenant by design. Stated so nobody mistakes it for one.

---

## The structural argument, for Q&A

> The model can never *grant* authority. It can only *withhold* it. Authority is granted by
> a signed mandate and enforced by a ledger. That is why a hallucinating model is a degraded
> experience here rather than a security incident — and it is the reason we split fail-open
> from fail-closed the way we did.

And on the audit log specifically:

> We did not make the log immutable. We made it *tamper-evident*. An attacker who owns the
> database can change a row — we let them, on stage — and the chain names the row they
> changed. Preventing the write would only have proved that our own application is
> well-behaved, which was never in doubt.
