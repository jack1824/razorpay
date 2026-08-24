"""Evaluation. The only place in this repository that reads archetype labels at scale.

`dwaar/` cannot see this package's inputs, and `tests/test_ground_truth_isolation.py`
enforces that: the gateway never reads `ground_truth.json` or a run manifest. The split is
what makes the numbers here worth printing at all — the system under measurement has no
access to the answer key.

Everything printed is computed at run time from what the gateway actually recorded. There is
no constant in this package that is a result.
"""
