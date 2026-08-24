"""The single source of truth for "what counts as an LLM in the hot path".

A module constant, not a literal repeated in two test files, because the failure mode this
guards against is *adding a provider and forgetting one of the lists*. One list, two tests
importing it.

Gemini is the chosen provider (native JSON-schema-constrained output, which the policy
compiler needs). The blocklist is deliberately wider than that:

- ``openai`` is here even though we do not use OpenAI. NVIDIA's inference endpoint speaks
  the OpenAI-compatible protocol through the same SDK, so importing `openai` is a live way
  to reach a model.
- ``dwaar.llm`` and ``dwaar.explain`` are ours and off-path by construction. If either
  becomes reachable from a request path, the architecture changed without anyone deciding.
"""

from __future__ import annotations

PROVIDER_SDKS: tuple[str, ...] = (
    "google.generativeai",
    "google.genai",
    "groq",
    "openai",           # NVIDIA's endpoint uses the OpenAI-compatible SDK
    "anthropic",
    "cohere",
    "mistralai",
    "ollama",
    "litellm",
    "langchain",
    "langchain_core",
    "llama_index",
    "transformers",
)

OWN_LLM_MODULES: tuple[str, ...] = (
    "dwaar.llm",
    "dwaar.explain",
)

BLOCKED_MODULES: tuple[str, ...] = OWN_LLM_MODULES + PROVIDER_SDKS

# Hosts a raw HTTP call could reach a model at. The static import walker is blind to
# `httpx.post("https://generativelanguage.googleapis.com/...")` — no import involved — so
# the source scan below catches what the walker cannot.
PROVIDER_HOSTS: tuple[str, ...] = (
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "api.openai.com",
    "api.anthropic.com",
    "api.groq.com",
    "integrate.api.nvidia.com",
    "api.mistral.ai",
    "api.cohere.ai",
)
