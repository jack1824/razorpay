-- 0015 — Delegated SCOPES on the mandate.
--
-- WHY
--
-- A mandate bounds how much an agent may spend. It says nothing about WHICH money-moving
-- actions it may take, and those are different questions: an agent authorised to collect
-- 50,000 rupees is not thereby authorised to refund 40,000 of them outward.
--
-- Razorpay's MCP server exposes 35+ tools behind one merchant token. `create_order` and
-- `create_refund` are both reachable with the same credential, and the documented controls
-- are a read-only flag and a toolset filter — neither of which is per-principal. So the
-- amount cap alone cannot express "this agent may take payments and may not issue refunds",
-- which is the most ordinary delegation a merchant would want.
--
-- `scopes` is that statement, and it is signed by the principal like every other term.
--
-- WHY IT IS NULLABLE, WHICH IS A DELIBERATE EXCEPTION
--
-- `dwaar/crypto/mandate.py` says "exactly ten keys, always" and forbids omit-if-default,
-- because under JCS an absent key and an empty array serialise differently — one mandate
-- would have two valid hashes and a verifier could disagree with the signer.
--
-- Adding an eleventh REQUIRED field would invalidate every mandate signed before today.
-- Those signatures are correct; the terms they cover have not changed. Breaking them to add
-- a column would be rewriting history to accommodate a feature.
--
-- So the field is included in the signed payload **if and only if this column is NOT NULL**,
-- and that is safe for the one reason the original rule exists to protect: the discriminator
-- is not a default value that signer and verifier might reason about differently, it is the
-- nullness of a column both of them read from the same row. There is no case where they can
-- disagree about which form applies.
--
--     NULL   signed before scopes existed. Grants no scope statement.
--     '{}'   explicitly grants nothing.
--     {...}  the delegated scopes.
--
-- NULL and '{}' are both refused by the proxy, which fails closed on anything not
-- explicitly delegated. They differ in the record, not in the outcome, and the record is
-- where the difference belongs.

ALTER TABLE mandates ADD COLUMN scopes TEXT[];

COMMENT ON COLUMN mandates.scopes IS
    'Delegated action scopes, signed by the principal. Included in the canonical payload '
    'IFF non-NULL — see migration 0015. NULL means the mandate predates scopes and grants '
    'none. The MCP proxy fails closed on anything not listed.';

-- The app role may read them and may not write them. Same reasoning as migration 0010: an
-- application that can widen its own delegation is not delegated to, it is trusted.
GRANT SELECT (scopes) ON mandates TO dwaar_app;
