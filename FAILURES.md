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
