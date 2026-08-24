"""The /v1/authorize pipeline.

Eight named stages plus one arithmetic gate, each a separate function so per-stage timing
is legible and so the day-4/5/7 work has an obvious place to land. Nothing in this package
imports an LLM client; `tests/test_hot_path_purity.py` walks the import closure from here
and fails the build if that ever changes.
"""
