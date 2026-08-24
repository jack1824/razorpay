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
