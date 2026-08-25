-- 0016 — Webhook deliveries, and the constraint that makes duplicates free.
--
-- Razorpay retries a webhook until it gets a 2xx, and a delivery that succeeded but whose
-- response was lost is retried anyway. The same event arriving twice is the NORMAL case.
--
-- Absorbing it is the same shape as the budget ledger's: a unique key and a named conflict
-- target, so "already processed" is a fact the database establishes rather than something
-- the application remembers between restarts.
--
-- The key is `rzp:<event-id>` — namespaced for the reason F-017 exists. An unprefixed
-- external identifier shares a namespace with our own derived keys, and a collision there
-- silently no-ops a real ledger entry.

CREATE TABLE webhook_deliveries (
    delivery_id      BIGSERIAL   PRIMARY KEY,
    idempotency_key  TEXT        NOT NULL UNIQUE,
    event_type       TEXT        NOT NULL,
    payload          JSONB       NOT NULL,
    received_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_webhook_deliveries_type ON webhook_deliveries(event_type, received_at DESC);

COMMENT ON TABLE webhook_deliveries IS
    'One row per DISTINCT webhook delivery. A retry collides on idempotency_key and is '
    'absorbed by a named ON CONFLICT target. BIGSERIAL is fine here — unlike '
    'decision_records.seq, nothing chains these, so a gap from a rolled-back transaction '
    'costs nothing.';

COMMENT ON COLUMN webhook_deliveries.idempotency_key IS
    'rzp:<x-razorpay-event-id>. Namespaced so an external identifier cannot collide with a '
    'key this system derives. See dwaar/idempotency.py and FAILURES.md F-017.';

-- The API inserts and reads. It does not update or delete: a delivery record that can be
-- edited is a delivery record that can be made to look like it never arrived.
GRANT SELECT, INSERT ON webhook_deliveries TO dwaar_app;
GRANT USAGE, SELECT ON SEQUENCE webhook_deliveries_delivery_id_seq TO dwaar_app;
