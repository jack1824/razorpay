-- 0008 — Evaluation runs.
--
-- results is [DERIVED] and is never hand-edited. Rule 4: no hardcoded metrics — every
-- number in the eval table is computed at run time. A row here is the provenance for a
-- number we say out loud, which means seed and versions are stored alongside it so any
-- figure can be reproduced on demand.

CREATE TABLE eval_runs (
    run_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seed           INT         NOT NULL,
    model_version  TEXT        NOT NULL,
    policy_version INT         NOT NULL,
    results        JSONB       NOT NULL,   -- [DERIVED] never hand-edited
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_eval_runs_time ON eval_runs(created_at DESC);
