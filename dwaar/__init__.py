"""Dwaar — authorization and policy enforcement for AI agents that spend money.

Dwaar answers one question: *was this action within the authority the principal
delegated?*  It does not answer *"is this transaction bad?"* — that is fraud detection,
a different product with a different failure mode.

Two structural rules are enforced by tests rather than convention:

- ``dwaar.*`` must never transitively import ``zoo.*``          (tests/test_import_isolation.py)
- the authorize path must never reach an LLM client            (tests/test_hot_path_purity.py)
"""

__version__ = "0.1.0"
