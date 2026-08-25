"""Types flowing through the authorize pipeline.

Every stage result is frozen. A later stage cannot retroactively alter an earlier one, so
the record written at stage 8 is a faithful account of what each stage actually returned
rather than of whatever the last writer left in a shared mutable object.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from dwaar.money import Paise

Action = Literal["purchase", "refund", "payout", "payment_link"]
DecisionKind = Literal["allow", "bound", "throttle", "step_up", "deny"]
PolicyVerdict = Literal["permit", "deny", "bound", "step_up", "throttle"]


@dataclass(frozen=True)
class AuthorizeRequest:
    agent_id: str
    mandate_id: str
    action: Action
    amount_paise: Paise
    idempotency_key: str
    category: str | None = None
    sku: str | None = None
    free_text: Mapping[str, str] = field(default_factory=dict)

    # Behavioural context. Optional because a caller that omits them still gets a decision —
    # the corresponding features simply carry no signal — and because requiring a card BIN
    # to authorise a payout would be nonsense.
    #
    # Neither is ever stored raw. `dwaar/risk/observations.py` hashes both before they enter
    # the rolling window, and nothing downstream of that sees the values: BIN *diversity* and
    # cart *mutation* are the signals, and counting distinct things does not require knowing
    # what they are. A raw BIN reaching `decision_records.features` would be unrecoverable,
    # because that table cannot be purged.
    instrument_bin: str | None = None
    cart_id: str | None = None

    # MCP tool calls. Set only when the request arrived through `dwaar/mcp/`.
    #
    # Deliberately on the SAME request type rather than a parallel one: an MCP denial and an
    # HTTP denial are the same kind of authority decision and belong in the same chain,
    # evaluated by the same gate. A second request type would have meant a second place to
    # get authority wrong.
    tool: str | None = None
    tool_arguments: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StageResult:
    """Base for every stage.

    ``degraded`` is the token that ends up in ``decision_records.degraded_mode``. A stub
    that does not set one is a stub that can be demoed as a working component by accident,
    which ``tests/test_stub_contracts.py`` makes impossible.
    """

    ok: bool = True
    degraded: str | None = None
    internal_reason: str | None = None


@dataclass(frozen=True)
class SignatureResult(StageResult):
    agent_id: str | None = None
    key_used: Literal["current", "previous"] | None = None


@dataclass(frozen=True)
class MandateResult(StageResult):
    mandate: Mapping[str, Any] | None = None
    merchant_id: str | None = None
    principal_id: str | None = None
    mandate_hash: bytes | None = None


@dataclass(frozen=True)
class AuthorityResult(StageResult):
    """The pure arithmetic gate (stage 2.5).

    ``permitted=False`` short-circuits stages 3-6 entirely. That is what makes
    ``risk_score IS NULL`` on a per-transaction breach a structural property rather than an
    accident of which stages happened to be stubbed.
    """

    permitted: bool = True
    rule_fired: str | None = None


@dataclass(frozen=True)
class FeatureResult(StageResult):
    features: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RiskResult(StageResult):
    # None means NOT CONSULTED. Never 0.0-as-unknown: 0.0 is a real score meaning
    # "confidently benign", and conflating the two destroys the audit-trail claim.
    risk_score: float | None = None
    model_version: str | None = None
    injection_flag: bool = False

    # The two components, kept apart all the way to the log line. A supervised classifier
    # trained on four archetypes cannot recognise a fifth; an isolation forest fit on
    # legitimate traffic alone can. Which of them fired is the interesting result on
    # evaluation day, including the outcome where the supervised half does nothing, and a
    # combined number alone cannot answer it.
    #
    # They are NOT stored as columns. `decision_records` keeps the feature vector, so both
    # components are recoverable by replaying a stored row against the named model version —
    # which is a stronger property than storing them would be, because a replay can be
    # checked and a stored number can only be believed.
    supervised_score: float | None = None
    anomaly_score: float | None = None
    band: str | None = None
    top_features: tuple[tuple[str, float], ...] = ()


@dataclass(frozen=True)
class InjectionResult(StageResult):
    """Stage 3.5. `flagged` is a TRISTATE and lands in the record as one.

    None means the detector did not run. False means it ran and found nothing — including
    the case where there was no free text at all, because "nothing to read" is a finding and
    "nobody read" is not. Migration 0014 constrains the column to agree with
    `stages_executed`, so the two cannot drift.
    """

    flagged: bool | None = None
    confidence: float | None = None
    matched_pattern: str | None = None
    model_version: str | None = None


@dataclass(frozen=True)
class PolicyResult(StageResult):
    verdict: PolicyVerdict = "permit"
    rule_fired: str | None = None
    policy_version: int | None = None
    bounded_amount_paise: Paise | None = None


@dataclass(frozen=True)
class LedgerResult(StageResult):
    reserved: bool = False
    entry_id: int | None = None
    budget_before: Paise | None = None
    budget_after: Paise | None = None
    rule_fired: str | None = None

    not_required: bool = False
    """The action moves no money, so there was nothing to reserve.

    Distinct from `reserved=False`, which means a reservation WAS attempted and refused. A
    read-only MCP tool — `fetch_payment` — is delegated, permitted and free; collapsing the
    two would deny it for insufficient budget, which is both wrong and confusing to read in
    a record.

    `budget_before` and `budget_after` stay NULL in this case, because nothing moved and
    recording a balance would imply the ledger was consulted."""

    reservation: Any | None = None
    """The `ReserveResult` itself, carried through so a collection can be bounded by the
    ledger's own arithmetic rather than by a number copied out of it.

    `balance_before - balance_after` IS the reserved amount, and it cannot disagree with the
    ledger because it is the ledger. An `amount_paise` field here would be a second copy,
    and a second copy is a place for the request's figure to reappear."""


@dataclass(frozen=True)
class Decision:
    decision: DecisionKind
    reason_code: str
    """COARSE, returned to the agent. Fine detail leaks the mandate's shape (threat 10)."""
    internal_reason: str
    """Fine-grained. Stored and logged; never serialised to the agent."""
    rule_fired: str | None = None
    bounded_amount_paise: Paise | None = None
    retry_after_ms: int | None = None


@dataclass(frozen=True)
class RecordResult(StageResult):
    record_id: str | None = None
    seq: int | None = None
    payload_hash: bytes | None = None
