"""The prompt, and the answer for when there is no model.

── The fallback is not a degradation, it is the floor ──────────────────────────────────

`fallback_text()` produces a sentence from the record alone, with no model involved. It runs
when Gemini is unreachable, when no key is configured, and in every test — so the explainer
container has something to write in all three cases, and the console never shows an empty
panel that reads as a bug.

It is deterministic and derived from the reason code, which means it is also the thing that
bounds how much the model can be wrong: the model is asked to phrase a fact the record
already states, not to work out why something happened.

── Why the prompt gets the RECORD and not the request ──────────────────────────────────

The explainer never sees agent-supplied text — no `free_text`, no cart notes, no tool
arguments. It sees decision, reason code, rule, band and amount.

That is the same boundary `dwaar/risk/injection.py` enforces one layer up, for the same
reason: the threat model assumes every byte an agent wrote is hostile, and the explainer's
output is rendered to a merchant in a console. An injected instruction that reached this
prompt could not change a decision — the decision is already signed — but it could put
attacker-chosen text in front of a human who is deciding whether to intervene. That is a
smaller problem than a compromised gate and it is still a real one, so the free text does
not come here either.
"""

from __future__ import annotations

from typing import Any

from dwaar.money import format_inr

MAX_WORDS = 60

SYSTEM = (
    "You explain authorization decisions made by a spending-control system to the merchant "
    "who owns the agent. Two sentences at most, plain English, no jargon, no markdown. "
    "State what was decided and the specific reason. Never speculate about intent, never "
    "recommend an action, and never mention risk scores as probabilities of fraud — this "
    "system decides whether something was ALLOWED, not whether it was fraudulent."
)

#: One line per outbound reason code. The floor the model is phrasing, not replacing.
FALLBACKS: dict[str, str] = {
    "allowed": "Allowed. The request was within every limit the principal set.",
    "denied": "Denied. The request fell outside what the principal authorised.",
    "not_authorized": "Denied. The mandate for this agent is expired, revoked or unknown.",
    "unavailable": (
        "Denied. A component needed to establish authority was unavailable, and this system "
        "refuses rather than guesses."
    ),
    "step_up_required": "Held. The principal must confirm this one before it can proceed.",
    "throttled": "Throttled. This agent is acting faster than the policy permits.",
    "scope_not_delegated": (
        "Denied. This agent was never delegated the power to take this kind of action, "
        "whatever the amount."
    ),
    "tool_not_permitted": (
        "Denied. The tool requested is not one this system has been configured to allow."
    ),
}

DEFAULT_FALLBACK = "A decision was recorded. See the record for the reason code."


def fallback_text(row: dict[str, Any]) -> str:
    """A sentence from the record alone. No model, no network, no failure mode."""
    base = FALLBACKS.get(row["reason_code"], DEFAULT_FALLBACK)
    rule = row.get("rule_fired")
    if rule:
        base = f"{base} Rule: {rule}."
    if row["decision"] == "bound" and row.get("bounded_amount_paise"):
        base = (
            f"{base} The amount was reduced from "
            f"{format_inr(row['amount_paise'])} to "
            f"{format_inr(row['bounded_amount_paise'])}."
        )
    return base


def prompt_for(row: dict[str, Any]) -> str:
    """Build the prompt from the RECORD. Never from the request.

    `risk_score` is described in words rather than passed as a number, because a merchant
    reading "0.62" learns nothing and a model given "0.62" will invent a meaning for it.
    NULL is stated explicitly as "the model was never consulted" — on a per-transaction
    breach that absence is the most interesting fact in the record.
    """
    lines = [
        SYSTEM,
        "",
        f"decision: {row['decision']}",
        f"reason code: {row['reason_code']}",
        f"rule fired: {row.get('rule_fired') or 'none'}",
    ]
    if row.get("amount_paise"):
        lines.append(f"amount requested: {format_inr(row['amount_paise'])}")
    if row.get("bounded_amount_paise"):
        lines.append(f"amount authorised: {format_inr(row['bounded_amount_paise'])}")
    if row.get("tool"):
        lines.append(f"tool called: {row['tool']}")
    if row.get("risk_score") is None:
        lines.append(
            "behavioural model: NOT CONSULTED. This decision was arithmetic — the request "
            "was outside a limit the principal set, so no score was ever computed."
        )
    else:
        from dwaar.explain.cache import band_for

        lines.append(f"behavioural model: consulted, band {band_for(row['risk_score'])}")
    if row.get("degraded_mode"):
        lines.append(f"degraded components at the time: {', '.join(row['degraded_mode'])}")
    lines += ["", f"Write the explanation now. At most {MAX_WORDS} words."]
    return "\n".join(lines)
