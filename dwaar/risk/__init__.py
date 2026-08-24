"""Behavioural judgment: rolling-window features and the risk model.

Nothing in this package may decide. The arithmetic gate, the policy engine and the ledger
decide; this package produces a number that can only ever *tighten* what they already
permit. The split is not stylistic — it is what makes `risk_score IS NULL` on a
per-transaction breach a checkable claim rather than a promise.

Three modules, and the boundary between them is load-bearing:

    observations.py   rolling windows in Redis, keyed on (agent_id, principal_id)
    features.py       PURE. window in, feature vector out. No I/O, no mandate.
    model.py          ONNX inference. onnxruntime and numpy, nothing else.

Training lives in `tools/train_risk.py`, outside this package on purpose: the trainer must
read evaluation labels and the service must never be able to. That is enforced by
`tests/test_ground_truth_isolation.py`, which scans this package for any reference to one.
"""
