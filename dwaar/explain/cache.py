"""The cache key: what makes two decisions have the same explanation.

`(rule_fired, decision, risk_band)` and nothing else — no agent, no amount, no timestamp.

That is a claim about what an explanation IS, not a lookup optimisation. An explanation
describes the reason a decision was reached, and the reason is fully named by the rule that
fired, the verdict it produced, and the band the score fell in. If two decisions sharing all
three needed different text, the text would be describing something the record does not
contain — and text that describes something unrecorded is text nobody can check.

The amount is deliberately out. "You exceeded your per-transaction cap" is the explanation;
"you exceeded it by ₹7,000" is the record, and the console shows the record beside the text.
Putting the amount in the key would make the cache useless (every burst becomes a cache
miss) AND make the explanation restate a number the reader can already see.
"""

from __future__ import annotations

#: Bands are named rather than numeric so a threshold change does not invalidate the cache
#: in a way that reads as a bug. `dwaar/risk/bands.py` owns the boundaries.
NO_MODEL = "none"
"""The band for a record whose `risk_score` is NULL — the model was never consulted. Not
`low`: 'confidently benign' and 'nobody asked' are different facts, and conflating them here
would produce an explanation claiming a score that does not exist."""


def cache_key(*, rule_fired: str | None, decision: str, risk_band: str | None) -> str:
    return f"{decision}|{rule_fired or 'none'}|{risk_band or NO_MODEL}"


def band_for(risk_score: float | None) -> str:
    """Name the band a stored score falls in. NULL stays NULL-shaped."""
    if risk_score is None:
        return NO_MODEL
    from dwaar.risk import bands

    return bands.band_for(float(risk_score))
