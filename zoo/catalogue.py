"""The product catalogue the agents shop from.

Loaded from `data/seed/catalogue.json`, which `tools/gen_seed.py` produces deterministically.
Agents pick from the same catalogue so that a SKU an adversary probes is a SKU a legitimate
shopper might also buy — if adversaries shopped from their own list, `distinct_skus_1h` would
separate the classes perfectly and the model would be a lookup table.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

CATALOGUE_PATH = Path("data/seed/catalogue.json")


@dataclass(frozen=True)
class Item:
    sku: str
    name: str
    category: str
    price_paise: int


def load(path: Path | str = CATALOGUE_PATH) -> list[Item]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return [
        Item(
            sku=entry["sku"],
            name=entry["name"],
            category=entry["category"],
            price_paise=int(entry["price_paise"]),
        )
        for entry in raw
    ]


def by_category(items: list[Item]) -> dict[str, list[Item]]:
    grouped: dict[str, list[Item]] = {}
    for item in items:
        grouped.setdefault(item.category, []).append(item)
    return grouped
