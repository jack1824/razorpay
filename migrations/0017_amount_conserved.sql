-- 0017 — The money invariant, and the two columns it needs to be checkable.
--
-- WHY
--
-- F-038: a `bound` decision told the agent it could spend ₹500 and debited ₹1,800. Latent
-- since Phase 5. Every visible surface agreed — the decision, the response, `amount_paise` —
-- and only `budget_before - budget_after` disagreed, with nothing comparing the two. It was
-- found only because an order was made to derive its amount FROM the reservation, which
-- forced two representations of one quantity into contact for the first time.
--
-- That is F-016's shape for the third time (signed blob vs columns, mandate terms vs the
-- denormalised copy, and now decided-amount vs reserved-amount). The first was closed by
-- making the comparison structural rather than by fixing the instance. So is this one:
--
--     For any decision with a monetary effect:
--         amount actually reserved == amount stated in the decision
--     where the BOUND amount, not the requested amount, is the stated amount.
--
-- The rule is written once, in `dwaar/invariants.py`, and enforced in three places: the
-- write path raises before the row is built, this constraint refuses it at the database,
-- and `dwaar-verify` recomputes it across all history.
--
-- ── Two new columns, both signed, both PRESENT-IFF-NON-NULL ─────────────────────────
--
-- `bounded_amount_paise` is what makes the invariant checkable at all. Without it the record
-- states the REQUESTED figure and nothing else, so a bound decision's true authorised amount
-- exists only in the ledger — and an invariant with one side missing is not an invariant.
--
-- `tool` is the MCP tool a call named. A record that says `mcp.scope.money.outbound` without
-- naming the tool is evidence of a category of refusal rather than of a refusal; the console
-- panel for demo beat 7 needs the tool, and assembling it for display instead of reading it
-- from the record would make the console a parallel view of what happened rather than a view
-- of what was recorded.
--
-- Both are included in the signed canonical payload IFF the column is non-NULL — the same
-- exception, for the same reason, as `mandates.scopes` in migration 0015. The discriminator
-- is the nullness of a column that the signer and the verifier both read off the same row,
-- so there is no case in which they can disagree about which form applies. Every record
-- written before today has NULL in both, its canonical form is unchanged, and its signature
-- keeps verifying.

ALTER TABLE decision_records ADD COLUMN bounded_amount_paise BIGINT;
ALTER TABLE decision_records ADD COLUMN tool                 TEXT;

COMMENT ON COLUMN decision_records.bounded_amount_paise IS
    'The amount a `bound` decision reduced the request to — the figure the agent was told '
    'and the only figure an order may be created for. NULL when no bound applied. In the '
    'signed payload IFF non-NULL (migration 0017, same mechanism as mandates.scopes).';

COMMENT ON COLUMN decision_records.tool IS
    'The MCP tool this call named, when the request arrived through dwaar/mcp/. NULL for a '
    'direct /v1/authorize call. In the signed payload IFF non-NULL.';

-- ── The baseline: where "forward-only" starts, recorded rather than assumed ─────────
--
-- 1,099 existing rows violate the invariant, in exactly two classes:
--
--     1,093  moved_without_permission     F-043 — `throttle` and `step_up` reserved budget.
--                                         Stage 6 ran whenever the policy verdict was not
--                                         `deny`, and stage 7 returns those two verdicts
--                                         before it ever looks at the ledger. An agent told
--                                         "come back later" was debited, and its retry —
--                                         a different idempotency key — was debited again.
--         6  bound_without_stated_amount  bound rows written before the column existed.
--
-- A NOT VALID constraint exempts them at the database. The verifier cannot see NOT VALID,
-- so without this table it would have to either fail forever on history or treat both
-- classes as permanently forgiven — and "permanently forgiven" means a reintroduction of
-- F-043 next month is reported as a note.
--
-- So the watermark is recorded explicitly: violations at or below it are history, violations
-- above it are failures. The app role may read it and may not write it, for migration 0010's
-- reason — an application that can move its own baseline forward can exempt its own bugs.
CREATE TABLE invariant_baselines (
    invariant   TEXT        NOT NULL,
    merchant_id TEXT        NOT NULL,
    max_seq     BIGINT      NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    note        TEXT,
    PRIMARY KEY (invariant, merchant_id)
);

INSERT INTO invariant_baselines (invariant, merchant_id, max_seq, note)
SELECT 'amount_conserved',
       merchant_id,
       max(seq),
       'Rows at or below this seq predate migration 0017. See FAILURES.md F-038 and F-043.'
FROM decision_records
GROUP BY merchant_id;

GRANT SELECT ON invariant_baselines TO dwaar_app;

COMMENT ON TABLE invariant_baselines IS
    'Where forward-only enforcement of an invariant begins, per merchant chain. Written by '
    'migrations only; the app role has SELECT and nothing else. dwaar-verify fails on a '
    'violation above the watermark and reports one at or below it as history.';

-- ── The invariant, enforced at the database. INSERT ONLY, and that is the point. ──
--
-- WHY A TRIGGER AND NOT A CHECK CONSTRAINT
--
-- The first version of this was `ADD CONSTRAINT ... CHECK (...) NOT VALID`, which is the
-- idiom migration 0014 uses and was the obvious choice. It was wrong, and the test suite
-- said so within the minute: a CHECK constraint governs UPDATE as well as INSERT, so
--
--     UPDATE decision_records SET amount_paise = 999999 WHERE seq = 3;
--
-- started being refused by the database. That statement is demo beat 6. Migration 0007
-- states the rule it broke:
--
--     "a superuser MUST be able to tamper: the control being demonstrated is detection by
--      cryptography, not prevention by DBMS. Preventing the tamper would destroy the only
--      evidence that the detection works."
--
-- The distinction is not a workaround, it is the definition of what this invariant is.
-- `budget_before` and `budget_after` are inside the signed canonical payload, so EDITING
-- them is already caught — by the signature, by the payload hash, and by the column/blob
-- agreement check in `dwaar/crypto/integrity.py`. Three controls already cover the attacker.
--
-- None of them cover the application writing a row that was wrong at the moment it was
-- written, because a signature attests that we said it, not that it was true. That is the
-- only gap this closes, and it exists entirely on the INSERT path. A control scoped wider
-- than the gap it closes is a control that eventually blocks something it was never aimed at
-- — which is exactly what happened here.
--
-- The trigger is therefore BEFORE INSERT and nothing else. A superuser can still rewrite any
-- column afterwards, and the verifier still catches it.

CREATE OR REPLACE FUNCTION decision_records_assert_amount_conserved()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    moved  BIGINT;
    stated BIGINT;
BEGIN
    -- 1. A reservation records both balances or neither. Half of one was assembled by hand,
    --    not derived from a ledger entry.
    IF (NEW.budget_before IS NULL) <> (NEW.budget_after IS NULL) THEN
        RAISE EXCEPTION 'amount invariant: budget_before=% budget_after=%; a reservation '
                        'records both balances or neither',
                        NEW.budget_before, NEW.budget_after;
    END IF;

    IF NEW.budget_before IS NULL THEN
        -- 2. A permit for a positive amount that never reached the ledger is an
        --    authorisation against no budget. Zero is correct and normal: a read-only MCP
        --    tool is delegated, permitted and free.
        IF NEW.decision IN ('allow', 'bound') AND COALESCE(NEW.amount_paise, 0) > 0 THEN
            RAISE EXCEPTION 'amount invariant: % of % paise recorded no ledger movement',
                            NEW.decision, NEW.amount_paise;
        END IF;
        RETURN NEW;
    END IF;

    moved := NEW.budget_before - NEW.budget_after;

    -- 3. A reservation only ever reduces. A release is a compensating ENTRY with its own
    --    row, never an edit, so a balance rising inside one record cannot happen.
    IF moved < 0 THEN
        RAISE EXCEPTION 'amount invariant: balance rose by % paise on a %', -moved, NEW.decision;
    END IF;

    IF moved = 0 THEN
        IF NEW.decision IN ('allow', 'bound') THEN
            RAISE EXCEPTION 'amount invariant: % reserved nothing', NEW.decision;
        END IF;
        RETURN NEW;
    END IF;

    -- 4. Money moved, so the decision must have permitted spending. THIS IS F-043: stage 6
    --    used to run on any verdict that was not `deny`, and stage 7 returns `throttle` and
    --    `step_up` before it ever looks at the ledger.
    IF NEW.decision NOT IN ('allow', 'bound') THEN
        RAISE EXCEPTION 'amount invariant: % paise reserved on a % decision; only allow and '
                        'bound authorise spending (FAILURES.md F-043)', moved, NEW.decision;
    END IF;

    -- 5. A bound that moved money records what it was bound to. Without it the authorised
    --    figure exists only in the ledger and the invariant has one side missing.
    IF NEW.decision = 'bound' AND NEW.bounded_amount_paise IS NULL THEN
        RAISE EXCEPTION 'amount invariant: a bound decision reserved % paise without '
                        'recording what it was bound to', moved;
    END IF;

    stated := COALESCE(NEW.bounded_amount_paise, NEW.amount_paise);
    IF stated IS NULL THEN
        RAISE EXCEPTION 'amount invariant: % paise reserved on a decision stating no amount',
                        moved;
    END IF;

    -- 6. A bound may only ever reduce.
    IF NEW.amount_paise IS NOT NULL AND stated > NEW.amount_paise THEN
        RAISE EXCEPTION 'amount invariant: decision states % paise against a request for %',
                        stated, NEW.amount_paise;
    END IF;

    -- 7. THIS IS F-038. What moved equals what was stated.
    IF moved <> stated THEN
        RAISE EXCEPTION 'amount invariant: the ledger moved % paise and the decision states '
                        '% (FAILURES.md F-038)', moved, stated;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER decision_records_amount_conserved
    BEFORE INSERT ON decision_records
    FOR EACH ROW EXECUTE FUNCTION decision_records_assert_amount_conserved();

COMMENT ON FUNCTION decision_records_assert_amount_conserved() IS
    'The money invariant: what the ledger moved equals what the decision stated, and only '
    'allow/bound may move anything. BEFORE INSERT ONLY — a superuser must still be able to '
    'UPDATE a row, because demo beat 6 is that UPDATE and the control being demonstrated is '
    'detection by cryptography. See dwaar/invariants.py, FAILURES.md F-038 and F-043.';
