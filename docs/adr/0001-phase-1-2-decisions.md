# ADR 0001 — Phase 1 & 2 decisions

- **Status:** Accepted
- **Date:** 2026-08-24
- **Scope:** Phase 1 (repository & architecture) and Phase 2 (data model)
- **Authority:** This ADR is the verbatim decision record issued by the project owner in
  response to the pre-build package review. **Where this document contradicts anything in
  the strategy package (vendored read-only at `docs/strategy/`), this document wins.**

---

## Verbatim decision record

> Answers below. Where this contradicts anything in the strategy package, this wins.
> Add this whole message to the repo as docs/adr/0001-phase-1-2-decisions.md before
> you write code.
>
> ### REPO LOCATION
>
> Use https://github.com/jack1824/razorpay.git — clone it and develop in the repo
> root. Not Desktop. The strategy package stays read-only reference; if you vendor
> it, put it under docs/strategy/ so its THREAT_MODEL.md and FAIL_MATRIX.md are not
> confused with the repo's own.
>
> On the stray ~/.git — you were right not to commit into it. Do not rm -rf it.
> Verify it is empty first:
> ```
>   git -C ~ log --all --oneline 2>&1 | head
>   git -C ~ stash list
>   git -C ~ remote -v
> ```
> If all three are empty, move it aside: mv ~/.git ~/.git.bak-20260824. Reversible,
> and it stops git status scanning your home directory.
>
> ### Q1 — TWO ROLES. APPROVED as proposed.
>
> The REVOKE ... FROM PUBLIC was security theatre and you were right to call it.
> PUBLIC never holds table-level UPDATE/DELETE by default, and REVOKE never touches
> the owner.
> ```
>   dwaar_owner — owns tables, runs migrations, never used by the API
>   dwaar_app   — non-owner, GRANT SELECT, INSERT on decision_records only
>   Two DSNs in compose: DATABASE_URL_MIGRATE and DATABASE_URL_APP
>   Test asserts InsufficientPrivilege on UPDATE as dwaar_app
> ```
>
> Your no-trigger reasoning is the sharpest point in the review and it goes in the
> pitch. A BEFORE UPDATE trigger blocks superuser too, which destroys demo beat 6 —
> the tamper must SUCCEED at the database so the chain verifier catches it
> cryptographically. The control we demonstrate is detection by cryptography, not
> prevention by DBMS. A log that only stops its own app from editing it proves
> nothing about an attacker who owns the database. Say exactly that if asked.
>
> ### Q2 — (a) MANDATE ROW LOCK as the mechanism, PLUS (b)'s column as a tripwire.
>
> You are correct. FOR UPDATE locks rows that exist; the race is two transactions
> each inserting a new tail computed from the same predecessor, both passing
> CHECK (balance_after >= 0). TECH_STACK.md said "lock the ledger row, not the
> mandate" and that advice was wrong — it is corrected at source with a dated
> strikethrough, not silently.
>
> Do both:
> ```
>   1. Mechanism: SELECT ... FROM mandates WHERE mandate_id = $1 FOR UPDATE, then
>      read tail, compute, insert, one transaction. No retry logic. Clean under the
>      50-writer test.
>   2. Tripwire: add prev_entry_id BIGINT + UNIQUE (mandate_id, prev_entry_id).
> ```
>
> Under correct locking the constraint can never fire. If it ever fires, the lock
> is wrong and the database catches it instead of silently overspending. One column
> buys a structural assertion that survives any future refactor of the locking code
> — same philosophy as the two-role grant and the hash chain.
>
> I chose (a) over pure optimistic append because the 50-writer test is maximum
> contention on a single mandate, where (b) alone degrades into a retry cascade.
> Real contention is per-mandate and naturally low.
>
> Judge answer: "One row lock per mandate; contention is per-mandate and inherently
> low. If a mandate ever became hot, the unique constraint on
> (mandate_id, prev_entry_id) already lets us move to lock-free optimistic append
> with no schema change."
>
> ### Q3 — GENESIS ENTRY. APPROVED exactly as proposed.
> ```
>   delta_paise     = +max_total_paise
>   balance_after   = max_total_paise
>   reason          = 'mandate_created'
>   idempotency_key = 'genesis:' || mandate_id
> ```
> Written in the same transaction as the mandate insert. Makes
> balance == sum(deltas) literally true, which is what TEST_PLAN's property test
> asserts. The genesis key also doubles as an "already initialised" guard for free.
>
> ### Q4 — ADVISORY LOCK APPROVED, but key it on merchant_id, not globally.
>
> Your diagnosis is the most consequential catch in the review. BIGSERIAL allocates
> outside transaction control, so with --workers 4 concurrent inserts commit out of
> seq order and rollbacks leave permanent gaps, while prev_hash requires strict
> serialisation. The chain would be broken by construction on day 6 and we would
> have found it in the dress rehearsal.
>
> Take pg_advisory_xact_lock + explicit seq = max(seq)+1 under the lock. One
> change: lock on hashtext(merchant_id) and make the chain per-merchant. Cost is
> about five lines and the verifier iterating chains instead of one chain — with
> one merchant in the demo this is identical in practice. Benefit: you delete the
> README apology. The answer becomes "the chain is already sharded by merchant; we
> only have one merchant in the demo" instead of "shard later to scale."
>
> If this costs more than an hour, fall back to your global lock plus the README
> note. It is not worth a day.
>
> ### Q5 — SIGNING KEY TABLE. APPROVED.
> ```sql
>   CREATE TABLE signing_keys (
>       key_id      TEXT PRIMARY KEY,
>       public_key  BYTEA       NOT NULL,
>       created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
>       retired_at  TIMESTAMPTZ
>   );
>   ALTER TABLE decision_records ADD COLUMN signing_key_id TEXT NOT NULL
>       REFERENCES signing_keys(key_id);
> ```
> Two columns on day 2 versus a migration on day 4 is not a close call. The
> standalone verifier is a headline artifact and must stay correct across rotation.
>
> ### ITEMS 6-10 — all accepted as you picked them.
> ```
>   6  Numbered .sql + small runner + schema_migrations. Your reasoning is right:
>      Alembic drags in SQLAlchemy, the exact ORM the package bans from the hot
>      path, and having it installed invites it in at 2am on day 9.
>   7  psycopg[binary,pool] 3.x. The BYTEA/NUMERIC type-return point is real and it
>      matters for the crypto layer.
>   8  Everything nested under dwaar/. The package was internally inconsistent here
>      and you resolved it correctly — the two files naming concrete import paths
>      win over the one implying a layout.
>   9  All 10 mandate keys always present, defaults materialised before signing,
>      pinned by a golden vector. Genuine footgun: under JCS an absent key and []
>      hash differently, so the same mandate would have had two valid hashes.
>      COMMIT THE GOLDEN VECTOR AS A TEST FIXTURE ON DAY 2, not day 4.
>   10 BYTEA in DB, lowercase hex at every JSON boundary, conversion only in the
>      repository layer.
>   --  make eval/demo/verify exit 2 with "not implemented until day N". Correct.
>      A green stub is the same failure mode as a hardcoded metric.
> ```
>
> ### ITEMS 11-16 — all confirmed.
>
> 11, 12 and 16 are already fixed in the strategy package. Re-pull 16_DEMO_DATA/
> and 10_SIMULATION/generate_demo_data.py rather than fixing them yourself.
>
> ```
>   11 Beat 3 contradiction — CONFIRMED and fixed now, not day 11. Verified every
>      mandate carries deny_categories ["gift_cards"], so the request died on set
>      membership and never reached the model. Beat 3 is now two events in an
>      ALLOWED category:
>        t=20  Rs 475 apparel, expect allow  (warm-up, establishes normal)
>        t=22  Rs 4,800 apparel, same SKU, _burst_index 7, expect deny /
>              behavioural_drift
>      10x ticket, 20x velocity, same SKU repeated — a resale pattern, under the
>      per-txn cap, valid signature, valid mandate. Only behaviour can catch it.
>      The note asserts risk_score MUST be non-null, the exact mirror of beat 2's
>      risk_score: null. Those two beats are now a matched pair and that pairing is
>      the strongest thirty seconds in the demo.
>
>   12 Unit error — CONFIRMED, fixed. max_total_paise is 5000000 (Rs 50,000);
>      Rs 5,000 is the per-txn cap. Note now reads Rs 50,000 -> Rs 48,760.
>
>   13 Beat 5 consequence — CONFIRMED. Narrate it, do not buffer to Redis. Add to
>      the script: "Notice these denials have no chain record. We will not write a
>      decision we cannot sign into the chain, so under ledger failure we deny and
>      we say nothing. An unrecorded DENY is safe — nothing moved. An unrecorded
>      ALLOW would be the worst outcome in the system. That asymmetry is why
>      fail-closed is doubly correct here." Buffering to Redis would create exactly
>      the class of unsigned mutable record the audit design exists to eliminate.
>
>   14 Seed keys — CONFIRMED, HKDF proposal approved. Derive all keypairs
>      deterministically from SEED.txt (20260905); public keys to the DB, private
>      keys only to a gitignored .keys/ that zoo/ reads. Add .keys/ to .gitignore
>      in Phase 1, before the first commit.
>
>   15 Replay store — CONFIRMED, logged for day 4. mandates.nonce is per-mandate
>      not per-request, and idempotency_key only exists on requests reaching a
>      ledger write, so a replayed deny is uncaught. Redis SETEX seen-nonce set
>      keyed on (agent_id, nonce), TTL = 2x the skew window. Correct that it is not
>      Phase 2 blocking.
>
>   16 Both confirmed and fixed. pgcrypto removed (gen_random_uuid is core since
>      PG13). The literal "-e" on line 3 of five files was an echo -e artifact from
>      the placeholder-banner pass. Stripped at source.
> ```
>
> ### 18 — GROUND TRUTH ISOLATION TEST: YES.
>
> 16_DEMO_DATA/README.md currently claims this test exists, so the package documents
> a control it does not ship. Build it.
>
> ### 19 — STRUCTURAL NO-LLM ASSERTION: YES, and this is the best suggestion in the review.
>
> "Not reachable" is strictly stronger than "not called on 1,000 sampled
> requests," and it converts our central architectural claim from behavioural to
> structural — the same move as the two-role grant and the unique constraint.
>
> KEEP BOTH TESTS. The import walker cannot see a raw
> httpx.post("https://api.anthropic.com/...") — no SDK import, still an LLM in the
> hot path. Static closure catches reachability; the runtime monkeypatch catches
> dynamic calls. In the README you get to say the claim is enforced two independent
> ways. This is a strengthening of rule 1, not a re-scope. Approved without
> reservation.
>
> ### NOW BUILD PHASE 1 AND 2.
>
> Open FAILURES.md with this review. Items 11-16 are the first entries: defects
> found before any code, by reading. A day-0 entry proves the file was kept in real
> time rather than backfilled on day 13, which is the difference between it scoring
> and it reading as an apology.
>
> Report back when the acceptance criteria pass:
> ```
>   docker compose up clean from nothing
>   make test green
>   test_import_isolation passes
>   50-parallel-writer concurrency test on budget_ledger passes
>   UPDATE on decision_records raises InsufficientPrivilege as dwaar_app
>   README.md has the architecture diagram at the top
> ```

---

## Implementation notes recorded against this ADR

These are observations made while executing the decisions above. They do not alter
any decision; they record how each was carried out, and where reality diverged.

### Repo location
Cloned to `~/razorpay` (outside `Desktop/`). The remote was an empty repository, so
`main` starts from this work. Strategy package vendored read-only at `docs/strategy/`;
the repo's own `THREAT_MODEL.md` and `FAIL_MATRIX.md` live at the repo root and are
authored for this codebase, not copies.

### Stray `~/.git`
Verified empty before touching it — `git -C ~ log --all --oneline`, `git -C ~ stash
list`, `git -C ~ remote -v` and `find ~/.git/refs -type f` all returned nothing. Moved
to `~/.git.bak-20260824`. Reversible.

### Items 11, 12, 16 — the upstream fixes are NOT present in the local package copy
The instruction was to re-pull `16_DEMO_DATA/` and `10_SIMULATION/generate_demo_data.py`
rather than fix them locally. **There is nothing to pull from.** The strategy package on
this machine is a plain directory with no git remote, and every file is still dated
`2026-08-22 16:08`. Verified after the decision arrived:

- `16_DEMO_DATA/timeline.json` beat 3 still reads `"category": "gift_cards"` with
  `"expect_rule": "behavioural_drift"` — the contradiction of item 11 is still live.
- Beat 1 note still reads `"Budget 5000 -> 3760"` — item 12 still live.
- `07_DATABASE/schema.sql:6` still reads `CREATE EXTENSION IF NOT EXISTS pgcrypto;`
- `DEMO_SCRIPT.md` line 3 still begins with the literal `-e ` artifact.

Per the instruction these were **not** fixed locally. The vendored copy at
`docs/strategy/` is byte-identical to the package as received. Items 11 and 12 are
demo-data concerns that bind on day 11, and item 16 is cosmetic; none of the three
blocks Phase 1 or Phase 2. Recorded in `FAILURES.md` as open.

**Action required from the owner:** supply the corrected package (a remote, or an
updated copy), or authorise local edits to the vendored copy.

### Item 16, pgcrypto — resolved in the repo's own migrations regardless
The migrations in `migrations/` are authored for this repo and do not `CREATE EXTENSION
pgcrypto`; `gen_random_uuid()` is core in PostgreSQL 13+ and the target is 16. This is
not a local edit to the vendored package — it is the repo's own schema, which the
strategy package's `schema.sql` informs but does not bind.

### Q4 — implemented as per-merchant, not the global fallback
The per-merchant variant was implemented; it cost well under the one-hour budget. This
required a column the strategy schema does not have: `decision_records.merchant_id`.
Without it there is no key to shard the chain on and no way for the verifier to
enumerate chains. `seq` is therefore unique **per merchant**, not globally, and
`prev_hash` links within a merchant's chain. See `migrations/0007_decision_records.sql`.

### Q2 tripwire — `prev_entry_id` is NULL for genesis
`UNIQUE (mandate_id, prev_entry_id)` does not constrain rows where `prev_entry_id IS
NULL`, because PostgreSQL treats NULLs as distinct in a unique index. Genesis entries
are exactly those rows. The `idempotency_key = 'genesis:' || mandate_id` uniqueness
from Q3 is what prevents two genesis rows for one mandate, so the guarantee holds — but
it holds via a different constraint than the tripwire, and that is worth knowing when
reading a failure.
