"""Prometheus metrics.

The latency story needs two different numbers and they are not interchangeable:

- ``decision_records.latency_us`` is measured request-start → just-before-INSERT. It cannot
  include its own write, because it is a column in the row being written and patching it
  afterwards would need an UPDATE grant on an append-only table.
- ``dwaar_authorize_duration_seconds`` below is the **complete** pipeline including the
  insert. This is the operational number.

Quoting either is fine. Quoting one while implying the other is not, which is why both
exist and why the README states the boundary.
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram

# Buckets chosen around the 25ms target rather than Prometheus defaults, so the histogram
# actually resolves the region we make claims about.
_BUCKETS = (0.001, 0.002, 0.005, 0.010, 0.015, 0.020, 0.025, 0.050, 0.100, 0.250, 1.0)

authorize_duration = Histogram(
    "dwaar_authorize_duration_seconds",
    "Full authorize pipeline including the decision-record insert.",
    labelnames=("decision",),
    buckets=_BUCKETS,
)

stage_duration = Histogram(
    "dwaar_authorize_stage_duration_seconds",
    "Per-stage duration. The stage split is what makes the latency claim legible.",
    labelnames=("stage",),
    buckets=_BUCKETS,
)

decisions_total = Counter(
    "dwaar_decisions_total",
    "Decisions rendered, by outcome and the rule that fired.",
    labelnames=("decision", "rule_fired"),
)

rejected_total = Counter(
    "dwaar_rejected_requests_total",
    "Requests refused before a decision could be attributed to a principal. "
    "These are security events, not authorization decisions, and are never chained.",
    labelnames=("reason",),
)

llm_calls_in_hot_path = Counter(
    "dwaar_llm_calls_in_hot_path_total",
    "MUST BE ZERO. Incremented only if an LLM is invoked during authorize.",
)
