import { useCallback, useEffect, useRef, useState } from "react";
import type { Agent, DecisionSummary, Health } from "./types";
import { DecisionStream } from "./DecisionStream";
import { AgentRoster } from "./AgentRoster";
import { DecisionDetail } from "./DecisionDetail";

const MERCHANT = "mch_demo0001";
const MAX_ROWS = 200;

type Tab = "stream" | "roster";

/**
 * Two screens and a detail panel. No router, no state library, no component library —
 * a tab switch is a `useState`, and anything more would be scope for zero benefit at
 * 1080p on a projector.
 */
export function App() {
  const [tab, setTab] = useState<Tab>("stream");
  const [decisions, setDecisions] = useState<DecisionSummary[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [health, setHealth] = useState<Health | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const seen = useRef<Set<number>>(new Set());

  // Which integrations are stubbed, from the server. Recomputed on every health poll, so
  // switching RAZORPAY_MODE and restarting the API changes the badge without a rebuild.
  const simulated = Object.entries(health?.integrations ?? {})
    .filter(([, integration]) => integration.simulated)
    .map(([name]) => name);

  // Roster and health poll. The roster is what drives the budget bars, and it must keep
  // up with the stream — a bar that lags the decision that drained it breaks the one
  // visual the audience reads without explanation.
  useEffect(() => {
    let alive = true;
    const poll = async () => {
      try {
        const [rosterResponse, healthResponse] = await Promise.all([
          fetch(`/v1/console/agents?merchant_id=${MERCHANT}`),
          fetch("/health"),
        ]);
        if (!alive) return;
        setAgents((await rosterResponse.json()).agents ?? []);
        setHealth(await healthResponse.json());
      } catch {
        // A blip must not take the console down: it is the debugging tool for every
        // remaining phase, and one that dies with the thing it watches is useless
        // exactly when it is needed.
      }
    };
    poll();
    const timer = setInterval(poll, 1000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);

  // Backfill, then stream. Opening the console mid-run should show history rather than an
  // empty table that fills only as new decisions arrive.
  useEffect(() => {
    let source: EventSource | null = null;
    let alive = true;

    (async () => {
      try {
        const response = await fetch(`/v1/console/decisions?merchant_id=${MERCHANT}&limit=50`);
        const initial: DecisionSummary[] = (await response.json()).decisions ?? [];
        if (!alive) return;
        initial.forEach((d) => seen.current.add(d.seq));
        setDecisions(initial);
      } catch {
        /* stream will backfill as new decisions land */
      }

      source = new EventSource(`/v1/console/stream?merchant_id=${MERCHANT}`);
      source.onmessage = (event) => {
        const decision: DecisionSummary = JSON.parse(event.data);
        if (seen.current.has(decision.seq)) return;
        seen.current.add(decision.seq);
        setDecisions((current) => [decision, ...current].slice(0, MAX_ROWS));
      };
    })();

    return () => {
      alive = false;
      source?.close();
    };
  }, []);

  const close = useCallback(() => setSelected(null), []);

  return (
    <div className="app">
      <header>
        <h1>DWAAR</h1>
        <span className="tag">authorization for agents that spend money</span>
        {simulated.length > 0 && (
          /*
           * The demo safety net. Visible whenever ANY integration is running against a stub,
           * naming which ones, driven by /health rather than by a build flag.
           *
           * The failure this exists to prevent is standing in front of judges describing a
           * stub as a live integration. That is not a bug anyone can walk back afterwards,
           * so the badge is loud, it is at the top, and nobody has to remember to turn it on.
           */
          <span className="simulated-badge" title={`Stubbed: ${simulated.join(", ")}`}>
            SIMULATED · {simulated.join(" · ")}
          </span>
        )}
        {health && (
          <span className="health">
            <span className={`dot ${health.status}`} />
            {health.status.toUpperCase()}
          </span>
        )}
        <nav>
          <button data-active={tab === "stream"} onClick={() => setTab("stream")}>
            Decision stream
          </button>
          <button data-active={tab === "roster"} onClick={() => setTab("roster")}>
            Agents
          </button>
        </nav>
      </header>

      <main>
        {tab === "stream" ? (
          <DecisionStream decisions={decisions} onSelect={setSelected} />
        ) : (
          <AgentRoster agents={agents} health={health} />
        )}
      </main>

      {selected && <DecisionDetail recordId={selected} onClose={close} />}
    </div>
  );
}
