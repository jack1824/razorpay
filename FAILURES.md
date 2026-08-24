# FAILURES

What broke, what we got wrong, and what we would do with two more weeks.

**This file is append-only by discipline.** Entries are written when the failure is found,
not reconstructed later. Nothing here is backfilled. If an entry is wrong, it gets a
correction *below* it, never an edit in place — the same rule the decision chain enforces in
code.

Newest entries at the bottom.

---

## 2026-08-24 — Day 0, pre-code review

Six defects found by reading the strategy package before a line of code was written. They
are recorded here rather than silently fixed, because *when* a defect was found is part of
what the record is for. All six were confirmed by the project owner in
`docs/adr/0001-phase-1-2-decisions.md`.

Three further defects — in the schema itself — were found in the same pass and are recorded
in the ADR as approved design changes rather than here, because they were corrected before
any code depended on them. They were: the append-only `REVOKE` being a no-op, the budget
ledger having no safe lock target, and `BIGSERIAL` breaking the hash chain under
concurrency. Each would have surfaced as a demo failure between day 6 and the dress
rehearsal.

---

### F-001 — Demo beat 3 could never have fired the risk model — OPEN upstream

**Found:** reading `16_DEMO_DATA/timeline.json` against `16_DEMO_DATA/mandates.json`.

Beat 3 requests ₹4,800 of `gift_cards` and asserts `expect_rule: "behavioural_drift"`, with
the note *"Signature OK, mandate OK. Only behaviour catches it."* But every mandate in
`mandates.json` carries `"deny_categories": ["gift_cards"]`. The request dies on
deterministic set membership at the policy stage and never reaches the risk model.

**Why it matters:** beat 3 is the *only* moment in the demo where the model earns its place.
As scripted it demonstrated the opposite of its intent, and it would have looked correct on
stage — a deny is a deny — while the `rule_fired` column quietly said something else. A
judge reading the decision record would have caught it.

**What we got wrong:** we treated the demo fixtures as data and the demo script as prose,
and never executed one against the other. Fixture-vs-fixture contradictions are invisible to
every test that does not exist yet.

**Resolution:** owner has redesigned beat 3 as a matched pair in an *allowed* category —
₹475 apparel warm-up at t=20 establishing normal, then ₹4,800 same-SKU at t=22 with a burst
index, under the per-txn cap with a valid signature and mandate. `risk_score` MUST be
non-null, mirroring beat 2's `risk_score: null`.

**Status: OPEN.** The corrected fixtures are not present on this machine — see F-006.

---

### F-002 — Demo beat 1 budget arithmetic is in the wrong unit — OPEN upstream

**Found:** same pass.

`timeline.json` beat 1 notes `"Budget 5000 -> 3760"` for an `amount_paise` of 124000. That
arithmetic treats ₹5,000 as the mandate total. It is not — `max_total_paise` is 5000000
(₹50,000), and ₹5,000 is `max_per_txn_paise`. The true balance after beat 1 is ₹50,000 →
₹48,760.

**Why it matters:** the console's budget bar is driven by the ledger, not by the note. On
stage the bar would have contradicted the script by a factor of ten, live, in the first
fifteen seconds.

**What we got wrong:** paise/rupee confusion in a document *about* a system whose central
discipline is that money is BIGINT paise and never a float. The code was going to be right
and the narration was going to be wrong.

**Resolution:** owner corrected the note to ₹50,000 → ₹48,760.

**Status: OPEN.** Corrected fixture not present on this machine — see F-006.

---

### F-003 — Under ledger failure, denials cannot be recorded — ACCEPTED, not fixed

**Found:** reading `13_FAILURE_MODES/FAIL_MATRIX.md` against the 8-stage pipeline in
`ARCHITECTURE.md`.

Demo beat 5 kills the ledger and asserts *"ALL authorize requests deny — fail-closed on
authority."* True. But stage 8, *record the decision*, is the same Postgres and is also
fail-closed. So for the duration of the outage the system denies and writes **no audit
record of having denied.**

**Why it matters:** it is a real hole in the audit trail, and it would have been discovered
by a judge asking "show me the records for the outage window" rather than by us.

**Resolution: accepted and narrated, not engineered around.** An unrecorded DENY is safe —
nothing moved. An unrecorded ALLOW would be the worst outcome in the system. That asymmetry
is why fail-closed is doubly correct here. Buffering denials to Redis was considered and
rejected: it would manufacture exactly the class of unsigned, mutable, un-chained record the
audit design exists to eliminate. Recorded in `FAIL_MATRIX.md` under "Postgres down".

**Status: closed as accepted.** This is a design position, not a bug, and it is stated in
the open rather than discovered.

---

### F-004 — The seed path needs private keys and nothing said where they live — RESOLVED

**Found:** reading `16_DEMO_DATA/*.json` against `07_DATABASE/schema.sql`.

`agents.json` and `principals.json` carry `"public_key_placeholder": true` — not keys.
`mandates.json` has no `canonical_json`, no `signature`, no `mandate_hash`, all three of
which are `NOT NULL`. So seeding requires generating keypairs *and signing mandates with
principal private keys*, and no document said where those keys come from or live.

**Why it matters:** it would have surfaced on day 2 as "the seeder cannot run", and the
convenient fix at that moment — commit a keypair — is the one that puts a private key in git
forever.

**Resolution:** all keypairs derived deterministically from `SEED.txt` (seed 20260905) via
HKDF. Public keys to the database; private keys only to a gitignored `.keys/` that `zoo/`
reads. `.keys/` was added to `.gitignore` in Phase 1, before the first commit, specifically
so this cannot be gotten wrong later.

**Status: resolved.** Seeder itself is day 2+ work; the decision is locked.

---

### F-005 — Replayed denials are not caught by any existing control — OPEN, day 4

**Found:** reading threat 2 of `12_SECURITY/THREAT_MODEL.md` against the schema.

The stated mitigation is "nonce + timestamp window + idempotency key UNIQUE". But
`mandates.nonce` is one nonce *per mandate*, not per request; and
`budget_ledger.idempotency_key` only exists on requests that reach a ledger write. A
request that is **denied** writes no ledger row — so a replayed denial is caught by nothing.

**Why it matters:** it is a genuine hole in replay defence that reads as covered. Denials
are exactly the requests an attacker replays while probing.

**Resolution:** Redis `SETEX` seen-nonce set keyed on `(agent_id, nonce)`, TTL twice the
skew window. Lands day 4 with the crypto layer.

**Status: OPEN by schedule, not by oversight.** Not Phase 2 blocking. Recorded in
`THREAT_MODEL.md` under "Known gaps" so it is visible until it closes.

---

### F-006 — The corrected strategy package never arrived — OPEN, blocks F-001/F-002

**Found:** immediately after the ADR was issued, attempting to act on it.

The decision record states that items 11, 12 and 16 are "already fixed in the strategy
package" and instructs: *"Re-pull `16_DEMO_DATA/` and `10_SIMULATION/generate_demo_data.py`
rather than fixing them yourself."*

**There is nothing to re-pull from.** The strategy package on this machine is a plain
directory with no git remote and no upstream. Every file is still dated `2026-08-22 16:08`.
Verified after the ADR arrived:

- `timeline.json` beat 3 still reads `"category": "gift_cards"` with
  `"expect_rule": "behavioural_drift"` — F-001 still live
- beat 1 note still reads `"Budget 5000 -> 3760"` — F-002 still live
- `schema.sql:6` still reads `CREATE EXTENSION IF NOT EXISTS pgcrypto;`
- `DEMO_SCRIPT.md` line 3 still begins with the literal `-e ` echo artifact

**What we got wrong:** we reported three defects as findings and received them back as
already-fixed, and neither side checked that the artifact carrying the fixes had actually
moved. A fix that exists in one person's working copy and nowhere else is indistinguishable
from no fix at all — which is the same failure class as F-001, one step up the stack.

**Resolution:** per the instruction, these were **not** fixed locally. `docs/strategy/` is
byte-identical to the package as received, so the divergence stays visible instead of being
papered over. None of the three blocks Phase 1 or Phase 2 — F-001 and F-002 bind on day 11,
and the `pgcrypto`/`-e` items are cosmetic.

The repo's own migrations do not use `pgcrypto` regardless; `gen_random_uuid()` is core in
PostgreSQL 13+ and the target is 16. That is the repo's schema, not an edit to the vendored
package.

**Status: OPEN. Needs the owner to supply the corrected package or authorise local edits.**

---

## 2026-08-24 — Day 0, building phases 1 and 2

Three defects the tests caught within minutes of the code existing, plus one environment
problem that blocks an acceptance criterion. Recorded because the first three are exactly
the failures the design is meant to prevent, and they were still made.

---

### F-007 — `reserve()` could not survive a duplicate webhook — FIXED

**Found:** `test_duplicate_idempotency_key_under_concurrency_charges_once` and
`test_reserve_absorbs_the_duplicate_instead_of_raising`, on their first run against a real
PostgreSQL. Every one of the 50 racing writers returned
`InFailedSqlTransaction: current transaction is aborted`.

The duplicate-recovery path read:

```python
except UniqueViolation:
    winner = await get_by_idempotency_key(conn, idempotency_key)
```

**In PostgreSQL a failed statement aborts the entire transaction.** Every subsequent command
returns `InFailedSqlTransaction` until a rollback. So the `SELECT` written to recover from
the duplicate could never execute — the handler for the failure was itself unreachable once
the failure occurred.

**Why it matters:** `FAIL_MATRIX.md` calls the duplicate webhook *"the most common real
payment-integration bug"* and says it is "explicitly tested". The code claiming to absorb it
would have surfaced it to the caller as an unrelated transaction error. The claim was in the
design document, the test, and the docstring — and false in the implementation.

**What we got wrong:** we wrote the recovery path from the shape of the exception rather than
from the state the database is in *after* it. Knowing that a `UniqueViolation` is raised is
not the same as knowing what you may still do on that connection.

**Fix:** the `INSERT` runs inside a savepoint (`async with conn.transaction()`), so a
violation rolls back only the statement and leaves the transaction usable. Separately, the
idempotency check now also runs *under the mandate lock*, which keeps the common case off the
exception path entirely. The exception path still matters — `idempotency_key` is globally
unique, so two different mandates can collide on one key and no mandate lock helps there.

---

### F-008 — A "one active signing key" index made rotation impossible — FIXED

**Found:** every test using `make_signing_key` failed with
`duplicate key value violates unique constraint "idx_signing_keys_one_active"`.

While implementing the approved `signing_keys` table we added a constraint that was not in
the decision record:

```sql
CREATE UNIQUE INDEX idx_signing_keys_one_active ON signing_keys((retired_at IS NULL))
    WHERE retired_at IS NULL;
```

"At most one active signing key" reads like tightening. It is the opposite. Rotation uses an
**overlap window** everywhere else in this system — `agents.previous_public_key` exists for
precisely that reason (threat 3) — and this constraint would have made Dwaar's own signing
key the one identity in the design that cannot rotate without a gap. Records in flight during
a rotation would be signed with a key the constraint had just forbidden.

**What we got wrong:** we added an invariant that was not asked for, to a table that had been
specified exactly, and it contradicted a rotation strategy already present elsewhere in the
same schema. The tests caught it in minutes; a reviewer might not have, because the
constraint looks like discipline.

**Fix:** index removed. "Which key is current" is answered by `created_at`/`retired_at`, not
enforced by the schema. The verifier resolves each record's key by `signing_key_id`, so
several active keys are a non-event for verification. A `retired_at >= created_at` check was
added, which is an actual invariant.

---

### F-009 — Two test bugs that would have hidden real ones — FIXED

Neither is a product defect, but both are the kind of test bug that passes for the wrong
reason later.

1. **A `pytest.raises(InsufficientPrivilege)` followed by another on the same connection.**
   The first denial aborts the transaction, so the second assertion saw
   `InFailedSqlTransaction`. Had the test caught a broader exception class it would have
   *passed* — while proving nothing about the second grant. Each denial now runs in its own
   `force_rollback` transaction.

2. **`make_mandate` had a fixed `max_per_txn_paise=500_000` default.** Any test lowering
   `max_total_paise` below that hit `CHECK (max_per_txn_paise <= max_total_paise)` — a
   constraint violation unrelated to what the test was checking. The per-txn cap now follows
   the total unless a test asks otherwise.

---

### F-010 — Docker is not installed; `docker compose up` is UNVERIFIED — OPEN

**Found:** attempting the first acceptance criterion.

`/usr/local/bin/docker` is a **broken symlink** to
`/Applications/Docker.app/Contents/Resources/bin/docker`, and `Docker.app` does not exist.
Docker Desktop was uninstalled without removing the symlink. There is no Colima, Podman, or
Lima either.

So `docker compose up` **has not been run and is not verified.** `docker-compose.yml`, the
`Dockerfile`, `scripts/entrypoint.sh` and `scripts/init-db/01-roles.sh` are written but
unexecuted. They are the acceptance criterion, so this is not a detail.

**What was done instead:** PostgreSQL 16.14 installed via Homebrew, and
`scripts/init-db/local-bootstrap.sh` written to create the same two roles and the same
ownership the Docker init script creates. The full suite — all 53 database tests including
the 50-writer concurrency test and the append-only grant — runs green against a real
PostgreSQL 16. The database-layer claims are genuinely verified; the *containerisation* of
them is not.

The risk this leaves is specific and worth naming rather than glossing: the two role-creation
paths could drift. If `01-roles.sh` ever fails to make `dwaar_app` a non-owner, the
append-only control is absent under Compose while the local suite still passes. Both scripts
carry a comment saying so.

**Status: OPEN. Needs Docker installed, then `make up` run on a clean machine.**

---

### F-011 — The mandate golden vector was specified for day 2 and shipped in phase 2.5 — CLOSED

**Found:** porting the seed generator, when it needed to sign a mandate and there was
nothing pinning what "signed" meant.

ADR 0001 item 9 said, in capitals: *"COMMIT THE GOLDEN VECTOR AS A TEST FIXTURE ON DAY 2,
not day 4."* Phase 2 implemented half of it — `test_mandate_defaults_are_materialised`
asserts the three defaulted columns are never NULL in the database — and skipped the half
that mattered. The instruction was about **bytes**, not columns.

**Why the database assertion does not cover it:** a signature is over a serialisation. Any
change to key ordering, string escaping, number formatting, or field membership silently
invalidates every signature ever produced, and the symptom is "signature invalid" — which is
indistinguishable from a forgery. The column check would have kept passing throughout.

**What we got wrong:** we read a requirement about canonical form as a requirement about
schema defaults, because the schema was what we were building that day. The literal
instruction named day 2 precisely so this could not be deferred behind the crypto layer,
and it was deferred anyway.

**Resolution:** `dwaar/crypto/jcs.py` (RFC 8785), `dwaar/crypto/mandate.py` (the ten-field
signed payload), and `tests/crypto/test_mandate_vector.py` pinning the exact canonical
string and its sha256. Day 4 builds RFC 9421 and the chain signer *around* these rather than
beside them — two canonicalisers that must agree is the same masking problem that makes
shared signing code between `dwaar/` and `zoo/` a bad idea.

**Also worth recording, because it is the rule-4 failure class in miniature:** the first
draft of that test carried an `EXPECTED_HASH` literal written from memory rather than
computed. It failed on the first run. The canonical-string pin passed, which is what caught
it. A hash nobody computed is a metric nobody measured.

---

### F-006 — CLOSED

Resolved by porting rather than patching. `tools/gen_seed.py` is now this repo's own
artifact and the source of truth for fixtures; the strategy package stays frozen, untracked,
and byte-identical to what was received, so the divergence remains auditable instead of
being papered over.

Carried across in the port: F-001 (beat 3 moved to `apparel` as a warm-up plus a drift
event, under the per-txn cap, `risk_score` asserted non-null), F-002 (beat 1 corrected to
₹50,000 → ₹48,760), F-004 (HKDF-derived Ed25519 keypairs, public keys in the fixtures,
private keys only under a gitignored `.keys/`, mandates genuinely signed).

**A fourth defect found during the port, not previously recorded:** the original generator
wrote `generated=datetime.now(timezone.utc)` into `SEED.txt` while printing *"Re-running
reproduces byte-identical output."* The single file asserting determinism was the only file
breaking it, and every downstream reproducibility claim rested on that assertion. There is
no wall-clock read anywhere in the port, and `test_same_seed_produces_byte_identical_output`
compares bytes rather than trusting the claim.

The demo's `kill_container` target was also corrected from `dwaar-ledger`, which is not a
container, to `dwaar-postgres`, which is — asserted against `docker-compose.yml` by
`test_kill_target_matches_a_real_compose_container`, so the demo cannot again name a
container that does not exist.

---

## 2026-08-24 — Day 0, package audit returns

A wide adversarial audit of the strategy package (194 agents, 128 confirmed findings) was
started before Phase 1 and landed after Phase 2 shipped. It independently reproduced the
three schema defects already corrected in ADR 0001 — the no-op `REVOKE`, `BIGSERIAL`
breaking the chain, and `TECH_STACK.md` naming the wrong lock target — which is reassuring
about those three and about nothing else.

It also found defects in work that was already written and pushed.

---

### F-012 — Three false claims were transcribed into this repo's own THREAT_MODEL and FAIL_MATRIX — FIXED

**Found:** the package audit, after the documents had been committed and pushed.

`THREAT_MODEL.md` and `FAIL_MATRIX.md` exist to stop the architecture drifting. They were
written before any decision code, which was the right order — and three claims were carried
across from the source without being checked against the rest of the design.

1. **"continuous rather than thresholded scoring"**, listed as a mitigation for
   policy-boundary probing. The design is explicitly thresholded:
   `05_AI_ARCHITECTURE/AI_ARCHITECTURE.md:32` reads *"`0.55 ≤ score < 0.80` → `step_up` …
   Above `0.80` → deny."* Those are precisely the clean edges a prober searches for. We
   credited a control that does not exist, in the document whose job is preventing exactly
   that kind of drift.

2. **"serve cached mandates read-only if the cache is warm"**, as the mandate store's
   failure behaviour. That is **fail-open on authority** — the one thing the document's own
   governing sentence forbids — sitting in the same table cell as the words FAIL-CLOSED. A
   mandate can be revoked; a warm cache cannot see the revocation, which is the write that
   matters most, and `openapi.yaml` promises `403` for a revoked mandate.

3. **"anchors bound the damage window"**, as recovery for audit-log tampering.
   `chain_anchors` has no signature, no external witness, and lives in the same PostgreSQL
   as the rows it anchors. An attacker who can rewrite records can rewrite anchors. It is
   also cut item #3 if the schedule slips.

**What we got wrong, and it is the more useful finding:** we reviewed the package's *schema*
adversarially and its *prose* deferentially. Nine defects were caught by reading
`schema.sql` against `timeline.json`; three were carried straight through from a threat
table because a threat table reads like a conclusion rather than a claim. A mitigation
column is an assertion about the system and deserves the same treatment as a CHECK
constraint.

**Fix:** all three removed, with the reasoning left in place under a heading — a deleted
claim is invisible, and *why* it was deleted is the part worth keeping. Two additions came
out of the same pass: auto-suspend (threat 1's recovery) is itself a DoS vector, since
signature verification happens before authentication and anyone who learns an `agent_id`
can suspend a legitimate agent with garbage signatures; and `agents.status` currently has no
enforcement point because no stage reads it. Both recorded, both land day 4.

Also corrected: the fail matrix said "Confidence low (0.55–0.80)". That band is the risk
*score*. Calibrated confidence is a separate quantity, and conflating the two makes the
escalation rule unimplementable.

---

### F-013 — The app role could extend its own authority — FIXED

**Found:** the package audit, in code already committed and pushed.

Migration 0009 granted table-wide `UPDATE` on `mandates`, `agents`, `policies` and
`signing_keys`, because the app legitimately mutates one or two columns on each —
`revoked_at`, `status`, `approved_by`, `retired_at`. Table-wide `UPDATE` also granted every
*other* column on those tables, and on `mandates` the other columns **are the authority**.

Demonstrated against the running database before the fix:

```
$ psql "postgresql://dwaar_app:...@localhost/dwaar"
UPDATE mandates SET expires_at = now() + interval '100 years' WHERE ...;
UPDATE 1
```

The application could extend its own mandate indefinitely, or raise `max_per_txn_paise`,
and **nothing would detect it.** The principal's signature covers `canonical_json`, which
is untouched, so the mandate still verifies. The hot path reads the denormalised columns,
not the signed blob. The signature stays valid while the authority it attests to has been
rewritten underneath it.

**What we got wrong:** we reasoned about `decision_records` as *the* table that needed a
narrow grant, because that is the one the pitch is about, and granted the others by asking
"does the app write here?" rather than "which column, and what else does that permit?".
Same class of defect as the no-op `REVOKE` we caught in the package — a grant that reads as
a control and is not one — one table over, in our own work, twelve hours later.

It is also worse than the original defect in one respect. Tampering with `decision_records`
is caught by the hash chain. Tampering with `mandates` is caught by nothing: no chain, no
signature over the mutable columns, and the one signature that exists keeps verifying.

**Fix:** migration `0010`, column-level grants. PostgreSQL supports them, so the grant now
states the intent exactly — revocation is an UPDATE the app must make; the caps and the
expiry are not. Nine columns of `mandates`, plus `registered_by` on `agents` (an agent must
not move itself to another merchant), `compiled_rules` on `policies` (an approved policy's
rules are frozen; a change is a new version, which is an INSERT), and `public_key` on
`signing_keys` (rewriting a key that has already signed records invalidates every one of
them, and invalidation is indistinguishable from forgery). Each is asserted by a test, and
so is the fact that revocation, suspension and key rotation still work.

`mandates.mandate_hash` also became UNIQUE. It is how the verifier resolves a record back
to the authority that was exercised; a plain index made that join fast, UNIQUE makes it
unambiguous.

**Still open, and the audit is right that it matters:** the hot path reads the denormalised
columns rather than re-deriving from `canonical_json`. Column grants close the path through
the app role, but a superuser can still rewrite `max_per_txn_paise` and leave a valid
signature over stale terms. The honest fix is a verifier invariant asserting the columns
agree with the signed blob. Day 4, with the rest of the verifier.

---

## 2026-08-24 — Phase 3, the authorize pipeline

Three defects in code that was already written and pushed, all found by tests added in this
phase. Two of them were invisible because the thing they broke did not exist yet.

---

### F-014 — The import walker could not see submodule imports — FIXED

**Found:** by a positive control written for `test_hot_path_purity.py`, on its first run.

`build_graph` recorded `from X import Y` as a single edge to `X`. It never recorded `X.Y`.
So a chain like `from dwaar.crypto import keys` produced an edge to `dwaar.crypto`, whose
`__init__` imports nothing — and the traversal stopped there. Every module reached only via
`from package import submodule` was **invisible to the walk**.

That weakened both structural guards: `test_import_isolation` (rule 3, shipped in Phase 1)
and `test_hot_path_purity` (rule 1). Both were passing. Both would have kept passing.

**What we got wrong:** we tested the walker only against a codebase that is supposed to be
clean. A check whose job is to never fail cannot be validated by never failing — its silence
is indistinguishable between "nothing to find" and "cannot find anything."

**Fix:** record both edges for `from X import Y`, since statically we cannot tell a
submodule from a name. Plus positive controls in both test files: a synthetic package built
to be *dirty*, asserted to be flagged. There is also a negative control (`openai_helper` is
not `openai`), because a check that fires on a prefix match is a broken build with no defect
behind it, which is how a good check gets deleted.

---

### F-015 — The body-size cap silently emptied every POST body — FIXED

**Found:** the first HTTP request to `/v1/authorize` returned
`422 {"loc": ["body"], "msg": "Field required"}` for a request with a perfectly good body.

`BodySizeLimitMiddleware` was a `BaseHTTPMiddleware`. It consumed `request.stream()` to
count bytes, then re-attached the buffer via `request._receive`. But `BaseHTTPMiddleware`
builds a **different** `Request` for the downstream app: the mutation landed on an object
the route never sees. The stream was drained and nothing replaced it.

**Why nothing caught it for two phases:** `/health` is a GET. The only POSTs in the suite
existed to trigger the 413, and a POST to a GET route returns 405 whether or not the body
survived. The middleware was tested exclusively against requests that have no body.

**Fix:** rewritten as pure ASGI, which can hand the downstream app a `receive` callable it
actually uses. Plus a regression test that POSTs a real body and asserts the failure is
*field-level validation*, not a missing body.

**The lesson worth keeping:** a middleware tested only against GET is a middleware tested
against the case where its bug cannot appear. The same is true of the size cap itself — the
413 path was covered, the success path never was.

---

### F-016 — The chain verifier did not check the columns, so demo beat 6 would have printed PASS — FIXED

**Found:** by `test_tampering_breaks_the_chain_and_names_the_seq`, written to reproduce
demo beat 6.

`verify_chain` checked four things: `payload_hash` matches `canonical_json`,
`canonical_json` is in canonical form, `prev_hash` links to the predecessor, and the
signature verifies. All four passed after the tamper. **It never checked that the columns
agree with the bytes that were signed.**

Demo beat 6 is literally:

```sql
UPDATE decision_records SET amount_paise = 500000 WHERE seq = 4127;
```

A column edit. `canonical_json` is untouched, so every hash still matches and the signature
still verifies. The verifier would have printed a green PASS on stage, immediately after the
presenter announced a tamper.

**What we got wrong:** we verified the signed artifact and forgot that the columns are what
everyone actually reads. `canonical_json` is a shadow copy; the row is the record. A
signature over a shadow nobody queries protects nothing.

This is the same defect as F-013's residual, one table over — there it was `mandates`
columns diverging from a valid principal signature, here it is `decision_records` columns
diverging from a valid Dwaar signature. Both come from the same mistake: treating the signed
blob as the record rather than as evidence *about* the record.

**Fix:** `verify_chain` now rebuilds the payload from the stored columns
(`recordmod.payload_from_row`) and compares it to `canonical_json` **before** anything else.
Two tests cover it: the naive tamper (edit a column) and the smarter one (edit
`canonical_json` to match, which then fails the hash and would need the signing key to
forge).

The `mandates` half of this is still open and lands with the verifier CLI on 25 Aug.

---

## 2026-08-24 — Phase 4: idempotency, RFC 9421, the verifier

---

### F-017 — Idempotency was a cross-tenant denial of service — FIXED

**Found:** flagged in the Phase 3 review, decided in the Phase 4 brief, fixed here.

`idempotency_key TEXT NOT NULL UNIQUE` was **global**, and the key is supplied by the agent,
and the agent is untrusted. Three consequences, one of them a security bug:

1. Agent A could burn a key belonging to agent B on an unrelated mandate. B's request fails
   as a duplicate and receives A's outcome. It is also an oracle: A learns whether B is
   using a given key.
2. An agent could submit `idempotency_key = "release:1234"`. When the system later released
   ledger entry 1234, its derived key collided, the insert was absorbed as a duplicate,
   **the release silently no-opped, and that reservation leaked permanently** — budget
   consumed forever against nothing.
3. `decision_records` had no idempotency key at all, so a replayed authorize deduped at the
   ledger and still minted a second chained record. Two records for one logical decision.

**What we got wrong:** we took `UNIQUE` on a column whose value comes from an untrusted
party as a safety property. It is a safety property only once the *scope* and the
*namespace* are also decided, and neither was.

**Fix:** `UNIQUE (mandate_id, idempotency_key)`; every client key stored prefixed `rsv:`;
server-derived keys in their own namespaces (`genesis:`, `release:<entry_id>`,
`settle:<entry_id>`); `request_idempotency_key` on `decision_records` with
`UNIQUE (mandate_hash, request_idempotency_key)`; and a replay lookup after stage 2 that
returns the original decision verbatim.

Prefixing is a *property*, not a validation: nothing has to remember to check agent input,
because the namespaces cannot overlap. `release:<entry_id>` also makes releases idempotent
for free.

---

### F-018 — Test fixtures wrote mandates a verifier would reject — FIXED

**Found:** the first run of `make verify`, which failed on every mandate in the database.

`make_mandate` wrote `canonical_json='{"test":true}'` with a random `mandate_hash`. Every
mandate the suite had ever created was, in the verifier's terms, tampered: columns that
disagree with the bytes that were signed.

**Why it matters more than a fixture bug:** fixtures a verifier rejects cannot be used to
*test* a verifier. Every chain test would have needed the check disabled, and the natural
next step is to disable it.

**Fix:** fixtures build a real canonical form and sign it with a derived principal key. Test
data is now indistinguishable from production data, which is the only state in which a test
of an integrity control means anything.

---

### F-019 — The same timezone bug, in a second place — FIXED

**Found:** immediately after F-018, by the verifier again.

`mandates.expires_at` was signed as `datetime.isoformat()` from Python but re-derived from
PostgreSQL, which returns `TIMESTAMPTZ` in the **session timezone**. Signer and verifier
produced different strings for the same instant, so every mandate read as tampered.

Phase 3 had already fixed exactly this for `decision_records.created_at` — and the fix was
applied to that one field rather than to the rule. **A datetime crossing a signature
boundary must be normalised to UTC**, and the normalisation belongs in `build_payload`, not
at each call site.

Both canonicalisers now normalise. Pinned by a vector asserting that the same instant in two
timezones produces identical bytes.

---

### F-020 — The verifier was read-only in name only — FIXED

**Found:** by its own test, `test_the_verifier_cannot_write`, which did not raise.

`conn.execute("SET default_transaction_read_only = on")` governs transactions started
*after* it. Run as a statement, it left the transaction it ran in read-write — so the
verifier could have written, and the docstring claiming otherwise was false.

The whole value of an independent verifier is that its report does not depend on trusting
the thing it verifies. "Chooses not to write" is a promise; "cannot write" is a property.

**Fix:** passed as a connection option (`-c default_transaction_read_only=on`), so it
applies from connection time. Asserted by a test that attempts a real INSERT.

---

### F-016 — extended, and generalised

The Phase 3 fix covered `decision_records`. `mandates` was known-open. `policies` was found
by looking for the pattern rather than waiting for the bug: it carried a `signature` with no
statement of what it signed, so the column could only ever have been decorative.

Now one helper and a registry (`dwaar/crypto/integrity.py`), iterated by the verifier, with
the standing rule recorded in `docs/adr/0001-phase-1-2-decisions.md`: any table carrying both
a signed serialisation and extracted columns must be registered, and its positive controls
ship in the same commit as its check.

`make verify` currently reports PASS across 1,005 chained records, 8 mandates and the ledger
invariants — and FAILs, naming the row, on a mutation of any single column across all three
tables.
