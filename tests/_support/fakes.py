"""Test doubles that behave like the real thing, including where the real thing is strict.

A double that is looser than what it replaces is how a test passes against an object the
production code would reject. `FixedScorer` returns the same shape `dwaar.risk.model.Scorer`
returns — bands included, computed from the same constants — so a test using it cannot pass
while the real scorer would have produced a different verdict from the same number.
"""

from __future__ import annotations

from dwaar.risk.bands import band_for
from dwaar.risk.model import RiskScore


class FixedScorer:
    """Always returns the score it was constructed with.

    Used where a test needs a *specific* risk score to exercise something downstream — the
    policy-beats-the-model conflict, the band boundaries — and training a model to produce
    that number on demand would be absurd.
    """

    def __init__(
        self,
        score: float,
        *,
        supervised: float | None = None,
        anomaly: float | None = None,
        model_version: str = "fake-1.0.0",
    ) -> None:
        self.score_value = score
        self.supervised = supervised if supervised is not None else score
        self.anomaly = anomaly if anomaly is not None else 0.0
        self.model_version = model_version
        self.calls: list[dict] = []

    def score(self, features: dict[str, int]) -> RiskScore:
        self.calls.append(dict(features))
        return RiskScore(
            risk_score=self.score_value,
            supervised_score=self.supervised,
            anomaly_score=self.anomaly,
            band=band_for(self.score_value),
            model_version=self.model_version,
            top_features=[],
        )


class ExplodingScorer:
    """Raises on every call. Proves the fail-open path is the implemented one, not just the
    documented one."""

    model_version = "exploding-1.0.0"

    def score(self, features: dict[str, int]) -> RiskScore:
        raise RuntimeError("inference graph is corrupt")
