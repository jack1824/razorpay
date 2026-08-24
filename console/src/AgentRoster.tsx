import type { Agent, Health } from "./types";

/**
 * Screen 2 — the single most intuitive visual in the project.
 *
 * The bar shows what REMAINS and drains as the agent spends. When the budget-breacher is
 * denied and its bar does not move, the audience understands enforcement with no
 * explanation — which is the entire reason this screen is built properly rather than
 * quickly.
 *
 * The numbers come from `budget_ledger` via the API, never from summing the decision
 * stream. The ledger is the enforcement record; a bar driven by anything else could show a
 * different number from the one that actually denied a request.
 */
export function AgentRoster({ agents, health }: { agents: Agent[]; health: Health | null }) {
  if (!agents.length) {
    return <div className="empty">no agents registered for this merchant</div>;
  }

  return (
    <>
      {health && health.status !== "nominal" && <DegradedBanner health={health} />}
      <div className="roster">
        {agents.map((agent) => {
          const remainingFraction = 1 - agent.spent_fraction;
          return (
            <div className="card" key={agent.agent_id}>
              <h3>{agent.display_name}</h3>
              <div className="id">
                {agent.agent_id} · {agent.status}
              </div>

              <div className="bar-label">
                <span>
                  <b>{agent.remaining_display}</b> remaining
                </span>
                <span className="spent">of {agent.total_display}</span>
              </div>
              <div className="bar">
                <div
                  className="fill"
                  style={{ width: `${Math.max(0, Math.min(1, remainingFraction)) * 100}%` }}
                  data-low={remainingFraction < 0.25 && remainingFraction > 0}
                  data-empty={remainingFraction <= 0}
                />
              </div>

              <div className="meta">
                <span>
                  per txn <b>{agent.per_txn_display}</b>
                </span>
                <span>
                  decisions <b>{agent.decisions}</b>
                </span>
                <span>
                  denied <b>{agent.denials}</b>
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </>
  );
}

/**
 * Severity comes from the API, which derives it from the fail matrix. The console does not
 * decide what "degraded" means — if it did, the banner and the audit trail would eventually
 * disagree, and the place that surfaces is on stage.
 */
function DegradedBanner({ health }: { health: Health }) {
  const impaired = Object.entries(health.components).filter(
    ([, component]) => component.severity !== "nominal",
  );
  return (
    <div
      style={{
        border: `1px solid var(--${health.status})`,
        borderRadius: 8,
        padding: "12px 18px",
        marginBottom: 18,
        background: "var(--panel)",
      }}
    >
      <strong style={{ color: `var(--${health.status})` }}>
        {health.status === "critical" ? "CRITICAL" : "DEGRADED MODE"}
      </strong>
      <div className="tokens" style={{ marginTop: 8 }}>
        {impaired.map(([name, component]) => (
          <span className="token" key={name} title={component.rationale}>
            {name} · {component.severity}
          </span>
        ))}
      </div>
    </div>
  );
}
