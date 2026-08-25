import type { Health } from "./types";

/**
 * Screen 5 — demo beat 5, both halves.
 *
 *   kill dwaar-llm-explainer  →  one row goes grey. Nothing else moves. Decisions continue.
 *   kill dwaar-postgres       →  the authority rows go red and every request denies.
 *
 * ── The colours are not chosen here ───────────────────────────────────────────────────
 *
 * Severity comes from the server, which derives it from `dwaar/components.py`, which is a
 * transcription of `FAIL_MATRIX.md`. Hand-writing the mapping in the console would guarantee
 * drift, and the place drift surfaces is on stage: the banner asserting DEGRADED while every
 * record written in that window says something else. Banner and audit trail visibly
 * disagreeing in front of judges is worse than either being wrong alone.
 *
 * So this file renders `severity` and never computes it.
 *
 * ── The explainer is the interesting row ──────────────────────────────────────────────
 *
 * It reports `status: down` with severity NOMINAL — down, and unable to make the gateway
 * degraded. The fail matrix says NO EFFECT on decisions and the console spec asks for amber
 * when it dies; both are right about different things. An operator should know, and no
 * decision changes. That is the whole content of beat 5's first half, and it should look
 * boring.
 */
export function SystemHealth({ health }: { health: Health | null }) {
  if (!health) {
    return <div className="empty">no health report</div>;
  }

  const entries = Object.entries(health.components);
  const down = entries.filter(([, c]) => c.status === "down");

  return (
    <>
      <div className={`health-banner ${health.status}`}>
        <span className={`dot ${health.status}`} />
        <b>{health.status.toUpperCase()}</b>
        <span className="muted">
          {down.length === 0
            ? "every component reporting up"
            : `${down.length} component(s) down: ${down.map(([name]) => name).join(", ")}`}
        </span>
      </div>

      <div className="components">
        {entries.map(([name, component]) => (
          <div
            className="component"
            key={name}
            data-severity={component.status === "up" ? "nominal" : component.severity}
            data-down={component.status === "down"}
          >
            <div className="component-head">
              <span className={`dot ${component.status === "up" ? "nominal" : component.severity}`} />
              <b>{name}</b>
              <span className="fail-mode">{component.fail_mode.replace("_", "-")}</span>
            </div>

            <div className="component-status">
              {component.status === "up" ? "up" : `down — ${component.reason ?? "unknown"}`}
              {/* Only the explainer carries one. A backlog while it is dead is the count of
                  decisions that went on being made without it. */}
              {component.backlog !== undefined && component.backlog > 0 && (
                <span className="backlog"> · {component.backlog} queued</span>
              )}
            </div>

            {/* Why this component's failure has the severity it has. Straight from the fail
                matrix, so the answer to "why is that amber and this red" is on the screen
                rather than in the presenter's memory. */}
            <div className="rationale">{component.rationale}</div>

            {component.model_version && (
              <div className="rationale mono">{component.model_version}</div>
            )}
          </div>
        ))}
      </div>

      {Object.keys(health.integrations ?? {}).length > 0 && (
        <div className="integrations">
          <h4>Integrations</h4>
          {/* Reported separately from components because they are not in the fail matrix,
              and giving them a severity would imply they are. What matters is one bit: is
              the thing we are about to show anyone real, or simulated? */}
          {Object.entries(health.integrations ?? {}).map(([name, integration]) => (
            <div className="integration" key={name}>
              <b>{name}</b>
              <span className="mode">{integration.mode}</span>
              {integration.simulated && <span className="simulated-badge">SIMULATED</span>}
            </div>
          ))}
        </div>
      )}
    </>
  );
}
