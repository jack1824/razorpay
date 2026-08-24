"""Policy: a closed rule DSL, a deterministic evaluator, and an offline compiler.

`dsl` and `engine` are hot-path. `compiler` is not, and imports an LLM client — which is
why it lives beside them rather than inside `engine`, and why `tests/test_hot_path_purity.py`
asserts the authorize path can reach `dwaar.policy.engine` but never `dwaar.policy.compiler`.
"""
