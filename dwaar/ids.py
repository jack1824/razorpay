"""Identifier generation and the patterns the API enforces.

The prefixes are load-bearing in the audit trail: `agt_`, `prn_`, `mnd_`, `pol_` make a
bare id in a log line or a dispute self-describing, without a lookup to find out what kind
of thing it names.
"""

from __future__ import annotations

import re
import secrets

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
LENGTH = 12

AGENT_PATTERN = re.compile(r"^agt_[a-z0-9]{12}$")
MANDATE_PATTERN = re.compile(r"^mnd_[a-z0-9]{12}$")
PRINCIPAL_PATTERN = re.compile(r"^prn_[a-z0-9]{12}$")


def new_id(prefix: str) -> str:
    """A random identifier. `secrets`, not `random`: ids appear in an evidence chain, and a
    predictable one is a small but free thing to give an attacker."""
    body = "".join(secrets.choice(ALPHABET) for _ in range(LENGTH))
    return f"{prefix}_{body}"
