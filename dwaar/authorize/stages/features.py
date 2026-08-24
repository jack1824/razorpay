"""Stage 3 — behavioural feature computation.  [STUB — real on 27 Aug]

Budget 2ms. Redis rolling windows. **Degrades**: losing behavioural context costs judgment,
never authority.

STUB CONTRACT
    returns features={} 
    degraded token: "features_stubbed"

An empty dict here is indistinguishable from a computed-and-empty feature set, which is why
`stages_executed` exists on the record: the degradation token says the stage was stubbed,
and the stage list says whether it ran at all.

When this becomes real: `features` lands inside an append-only, hash-chained row that can
never be purged. It must therefore hold **numerics, booleans and hashes only — never raw
agent text.** Threat 14's stated recovery is "rotate, purge", and purge is impossible by
construction on this table. A `free_text` substring reaching `features` would be
unrecoverable by design.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dwaar.authorize.types import AuthorizeRequest, FeatureResult

DEGRADED_TOKEN = "features_stubbed"
STAGE_NAME = "compute_features"


async def compute_features(
    request: AuthorizeRequest, mandate: Mapping[str, Any], *, redis=None
) -> FeatureResult:
    return FeatureResult(
        ok=True,
        degraded=DEGRADED_TOKEN,
        features={},
        internal_reason="features_not_computed_stub",
    )
