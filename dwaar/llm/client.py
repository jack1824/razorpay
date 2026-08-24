"""Provider-agnostic LLM interface.

Gemini is the chosen provider, for native JSON-schema-constrained output — the policy
compiler needs a rule DSL that parses on the first attempt, not prose it has to retry.
**Nothing outside this module knows that.** Callers see `complete()`; swapping providers is
a change to one file, and the two callers (policy compiler, async explainer) are unaffected.

Both callers are off the request path by construction:

    policy compiler   build-time. Compiles English into a tested, human-approved ruleset
                      once; the hot path then executes it deterministically forever.
    async explainer   queue-driven. Killing it changes no decision — that is a demo beat.

If you are reading this because you want an LLM in `/v1/authorize`: the answer is no, and
the reason is not latency. 500-2000ms against a 25ms budget would merely be slow. The real
problem is that it makes the decision-maker the injection target, on a system whose entire
threat model assumes agent-supplied text is hostile.
"""

from __future__ import annotations

from typing import Any


class LLMUnavailable(RuntimeError):
    """The provider could not be reached. Never fatal: every caller is off-path."""


async def complete(
    prompt: str,
    *,
    schema: dict[str, Any] | None = None,
    max_tokens: int = 2048,
) -> str:
    """Single completion, optionally constrained to a JSON schema.

    Not implemented until the policy compiler lands (26 Aug). It raises rather than
    returning a placeholder, so nothing can accidentally depend on a stubbed answer — the
    same rule the pipeline's stub stages follow.
    """
    raise NotImplementedError(
        "LLM client lands with the policy compiler on 26 Aug. It is deliberately not "
        "stubbed: a stub that returns text would let a caller depend on an answer no model "
        "produced."
    )
