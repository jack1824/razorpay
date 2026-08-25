"""The async explainer. The ONLY place an LLM meets a decision, and it meets it afterwards.

── What it is ──────────────────────────────────────────────────────────────────────────

A separate process. It reads decision records off a Redis stream, asks Gemini for two
sentences a merchant could read, and writes them to `explanations`. The decision it explains
was written, signed and chained before the stream message existed.

    /v1/authorize  ──►  decide, reserve, sign, chain, COMMIT  ──►  respond
                                                             └──►  XADD (best effort)
                                                                     │
                                                    dwaar-llm-explainer reads it here

There is no ordering in which this changes an outcome. The record is durable before the
message is published, and the publish itself is wrapped so that a Redis failure at that
moment cannot fail a request that has already been answered.

── Four things make "off the decision path" a property rather than a claim ─────────────

    1. a separate PROCESS          killing it is demo beat 5 and nothing else moves
    2. a separate DATABASE ROLE    `dwaar_explainer` holds SELECT on decision_records and
                                   INSERT on explanations. It cannot write a decision, edit
                                   one, or touch the ledger. See migration 0018.
    3. publish-after-commit        and best effort — and the publisher is not even in
                                   this package. `dwaar/outbox.py` says why.
    4. the import closure          `tests/test_hot_path_purity.py` fails the build if
                                   `dwaar.llm` becomes reachable from `dwaar.api.app`

(2) is the one worth pointing at. The other three are properties of code, and code changes.

── The cache, which is not an optimisation ─────────────────────────────────────────────

Keyed on `(rule_fired, decision, risk_band)`. A card tester produces thirty denials in
ninety seconds and they all have the same explanation, because they have the same REASON —
the explanation describes the rule, not the transaction. So the cache is a statement about
what an explanation is: if two decisions with identical reasons needed different text, the
text would be describing something the record does not contain.

It also means a burst costs one model call rather than thirty, which matters on a laptop on
stage. That is the second reason, not the first.
"""

from __future__ import annotations

from dwaar.explain.cache import cache_key
from dwaar.explain.render import fallback_text, prompt_for
from dwaar.outbox import STREAM

__all__ = ["STREAM", "cache_key", "fallback_text", "prompt_for"]
