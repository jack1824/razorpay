"""LLM access. OFFLINE AND ASYNC ONLY — never reachable from a request path.

Two independent tests enforce that, for a reason:

- `tests/test_hot_path_purity.py` walks the static import closure from every request-path
  module and fails if any chain reaches this package or a provider SDK. It proves the LLM
  is NOT REACHABLE.
- `tests/test_no_llm_in_hot_path.py` monkeypatches `complete` to raise and drives 1,000
  authorize requests. It proves the LLM was NOT CALLED.

Neither subsumes the other. The static walker cannot see
`httpx.post("https://generativelanguage.googleapis.com/...")` — no import involved, still
an LLM in the hot path. The runtime test only covers the requests it sampled.
"""
