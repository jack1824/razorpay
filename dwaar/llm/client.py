"""Provider-agnostic LLM interface. OFFLINE AND ASYNC ONLY.

Gemini is the provider, chosen for **native JSON-schema-constrained output**: the policy
compiler needs a rule DSL that parses on the first attempt, and getting schema conformance
from the API is categorically better than a retry loop around a model that returns prose
with a code fence in it.

**Nothing outside this module knows that.** Callers see `complete()` and `complete_json()`.
Swapping providers is a change to one file.

── Why this is not in the request path, three reasons in order ─────────────────────────

1. **It makes the decision-maker the injection target.** The threat model assumes every
   byte of agent-supplied text is hostile. A model that reads that text and then decides
   about money is the highest-value thing an attacker could reach. This reason survives any
   improvement in latency or determinism.
2. **It is non-deterministic on money.** Two identical requests could receive different
   answers, and a decision record would stop being replayable — which is most of what makes
   it evidence.
3. **500–2000ms against a 25ms budget.** The least important of the three, and the one
   usually given first.

Both callers are off-path by construction: the policy compiler is a build-time CLI, and the
explainer is queue-driven and can be killed without changing a decision.

── Enforcement ─────────────────────────────────────────────────────────────────────────

`tests/test_hot_path_purity.py` proves this module is not *reachable* from a request path.
`tests/test_no_llm_in_hot_path.py` proves it is not *called*. Neither subsumes the other:
static closure is blind to a raw `httpx.post` to a provider URL, and the runtime test only
covers the requests it sampled. A source scan for provider hostnames closes the third gap.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from google import genai
from google.genai import types as genai_types

DEFAULT_MODEL = "gemini-2.5-pro"

#: Deterministic sampling. A compiler that produced a different ruleset each run would make
#: the human review meaningless — the reviewer would be approving one sample of a
#: distribution rather than the artifact that goes live.
DEFAULT_TEMPERATURE = 0.0


class LLMUnavailable(RuntimeError):
    """The provider could not be reached, or no credential is configured.

    Never fatal to a decision: every caller is off the request path. The compiler surfaces
    it as a failed CLI run, which is correct — a policy that could not be compiled must not
    go live.
    """


@dataclass(frozen=True)
class Completion:
    text: str
    model: str
    """Recorded alongside the compiled policy, so a ruleset can be traced to what produced
    it. A generated artifact with no provenance is one nobody can re-derive."""


def _client() -> genai.Client:
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise LLMUnavailable(
            "GEMINI_API_KEY is not set. The policy compiler is an offline CLI, so this is a "
            "setup error rather than a runtime degradation — nothing in the request path "
            "reaches this module."
        )
    return genai.Client(api_key=api_key)


async def complete(
    prompt: str,
    *,
    schema: dict[str, Any] | None = None,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 8192,
) -> str:
    """One completion, optionally constrained to a JSON schema."""
    return (await _complete(prompt, schema=schema, model=model, max_tokens=max_tokens)).text


async def complete_json(
    prompt: str,
    *,
    schema: dict[str, Any],
    model: str = DEFAULT_MODEL,
    max_tokens: int = 8192,
) -> tuple[dict[str, Any], str]:
    """Schema-constrained completion, parsed. Returns ``(payload, model)``.

    The schema is enforced by the API, so a parse failure here means the provider returned
    something outside a constraint it had accepted — worth failing loudly rather than
    retrying into.
    """
    completion = await _complete(prompt, schema=schema, model=model, max_tokens=max_tokens)
    try:
        return json.loads(completion.text), completion.model
    except json.JSONDecodeError as exc:
        raise LLMUnavailable(
            f"schema-constrained output did not parse as JSON: {exc}. The schema was "
            "accepted by the API, so this is a provider fault rather than a prompt problem."
        ) from exc


async def _complete(
    prompt: str,
    *,
    schema: dict[str, Any] | None,
    model: str,
    max_tokens: int,
) -> Completion:
    config: dict[str, Any] = {
        "temperature": DEFAULT_TEMPERATURE,
        "max_output_tokens": max_tokens,
    }
    if schema is not None:
        config["response_mime_type"] = "application/json"
        config["response_schema"] = schema

    try:
        response = await _client().aio.models.generate_content(
            model=model,
            contents=prompt,
            config=genai_types.GenerateContentConfig(**config),
        )
    except LLMUnavailable:
        raise
    except Exception as exc:  # noqa: BLE001
        raise LLMUnavailable(f"{type(exc).__name__}: {exc}") from exc

    text = getattr(response, "text", None)
    if not text:
        raise LLMUnavailable("provider returned an empty response")
    return Completion(text=text, model=model)
