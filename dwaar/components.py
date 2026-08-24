"""Component severity, derived from the fail matrix.

── One constant, two consumers ─────────────────────────────────────────────────────────

`/health` colours the console and `degraded_mode` labels the audit trail. Both answer
"which components are down and how bad is that", and both must answer it the same way.

Hand-writing the mapping twice guarantees drift, and the drift shows up at the worst
moment: on demo beat 5 the console would assert DEGRADED MODE while every record written in
that window carried a contradicting `degraded_mode`. Banner and audit trail visibly
disagreeing in front of judges is worse than either being wrong alone.

── The mapping is not invented; it is the fail matrix ──────────────────────────────────

    fail-open / degrade  →  DEGRADED  (amber)  judgment. Bounded residual risk, because
                                               the ledger still holds.
    fail-closed          →  CRITICAL  (red)    authority. The system stops selling.
    no-effect            →  NOMINAL   (grey)   genuinely off the decision path.

The LLM explainer is the interesting case. The fail matrix says NO EFFECT on decisions, and
the console spec asks for amber when it dies. Both are right about different things: no
decision changes, and an operator should still know. It is therefore `NOMINAL` for
severity — it can never make the service degraded — and reported with `status: "down"` so
the console can show it without claiming the gateway is impaired. Killing it is a demo
beat precisely because nothing else moves.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    """Worst-wins ordering. Values are what `/health` serialises."""

    NOMINAL = "nominal"
    DEGRADED = "degraded"
    CRITICAL = "critical"


#: Explicit rather than relying on Enum declaration order, because the ordering is what
#: computes the overall status and an accidental reorder would silently downgrade an outage.
SEVERITY_RANK: dict[Severity, int] = {
    Severity.NOMINAL: 0,
    Severity.DEGRADED: 1,
    Severity.CRITICAL: 2,
}


class FailMode(StrEnum):
    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN = "fail_open"
    DEGRADE = "degrade"
    NO_EFFECT = "no_effect"


#: The single source of truth. Adding a component means adding it here, and both `/health`
#: and the degradation vocabulary inherit it.
FAIL_MODE_SEVERITY: dict[FailMode, Severity] = {
    FailMode.FAIL_CLOSED: Severity.CRITICAL,
    FailMode.FAIL_OPEN: Severity.DEGRADED,
    FailMode.DEGRADE: Severity.DEGRADED,
    FailMode.NO_EFFECT: Severity.NOMINAL,
}


@dataclass(frozen=True)
class Component:
    name: str
    fail_mode: FailMode
    rationale: str

    @property
    def severity_when_down(self) -> Severity:
        return FAIL_MODE_SEVERITY[self.fail_mode]


#: Transcribed from FAIL_MATRIX.md. Each entry's fail_mode is the row's classification.
COMPONENTS: tuple[Component, ...] = (
    Component("postgres", FailMode.FAIL_CLOSED,
              "Cannot reserve budget or chain a decision, so no decision can be made."),
    Component("ledger", FailMode.FAIL_CLOSED,
              "Never permit unbounded spend. The system stops selling rather than sell "
              "without a limit."),
    Component("mandate_store", FailMode.FAIL_CLOSED,
              "Cannot verify authority, so cannot authorize. Uncached by design."),
    Component("signature_verification", FailMode.FAIL_CLOSED,
              "Identity is not optional."),
    Component("nonce_store", FailMode.FAIL_CLOSED,
              "Cannot distinguish a first use from a replay, which would be fail-open on "
              "identity."),
    Component("redis", FailMode.DEGRADE,
              "Lose behavioural context, keep authority."),
    Component("risk_model", FailMode.FAIL_OPEN,
              "Classification is advisory; the residual is bounded because the ledger holds."),
    Component("injection_detector", FailMode.FAIL_OPEN,
              "Same reasoning; blunt cases still caught by heuristics."),
    Component("policy_engine", FailMode.DEGRADE,
              "Last signed version continues serving. A policy can only tighten."),
    Component("explainer", FailMode.NO_EFFECT,
              "Off the decision path. Killing it changes no decision — that is the point."),
)

BY_NAME: dict[str, Component] = {component.name: component for component in COMPONENTS}


def overall(severities: list[Severity]) -> Severity:
    """Worst component wins.

    A service with one critical component down is not "mostly fine": the thing that failed
    is the thing that decides about money.
    """
    if not severities:
        return Severity.NOMINAL
    return max(severities, key=lambda severity: SEVERITY_RANK[severity])
