import { useCallback, useEffect, useRef, useState } from "react";
import type { Agent, DecisionSummary, Health, McpCall, Verification } from "./types";
import { DecisionStream } from "./DecisionStream";
import { AgentRoster } from "./AgentRoster";
import { DecisionDetail } from "./DecisionDetail";
import { ChainVerifier } from "./ChainVerifier";
import { McpPanel } from "./McpPanel";
import { SystemHealth } from "./SystemHealth";

const MERCHANT = "mch_demo0001";
const MAX_ROWS = 200;

const TABS = [
  ["stream", "Decision stream"],
  ["roster", "Agents"],
  ["mcp", "MCP enforcement"],
  ["chain", "Chain verifier"],
  ["health", "System health"],
] as const;

type Tab = (typeof TABS)[number][0];

/**
 * Five screens and a detail panel. No router, no state library, no component library —
 * a tab switch is a `useState`, and anything more would be scope for zero benefit at
 * 1080p on a projector.
 *
 * The tab ORDER is the demo order: stream (beats 1-4), agents (the budget bars), MCP
 * (beat 7), chain (beat 6), health (beat 5). `make demo` drives the console through them
 * on the timeline's schedule, so the presenter talks instead of clicking.
 */
export function App() {
  const [tab, setTab] = useState<Tab>("stream");
  const [decisions, setDecisions] = useState<DecisionSummary[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [health, setHealth] = useState<Health | null>(null);
  const [verification, setVerification] = useState<Verification | null>(null);
  const [mcp, setMcp] = useState<{ calls: McpCall[]; known_tools: string[] }>({
    calls: [],
    known_tools: [],
  });
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
        const [rosterResponse, healthResponse, mcpResponse, verifyResponse] =
          await Promise.all([
            fetch(`/v1/console/agents?merchant_id=${MERCHANT}`),
            fetch("/health"),
            fetch(`/v1/console/mcp?merchant_id=${MERCHANT}`),
            // Server-side cached; a cold call re-verifies the whole chain and takes
            // seconds, so the panel shows the result's AGE rather than pretending it is
            // live. Polled unconditionally so demo beat 6 goes red while the presenter is
            // still on it, rather than when someone remembers to click the tab.
            fetch(`/v1/console/verify?merchant_id=${MERCHANT}`),
          ]);
        if (!alive) return;
        setAgents((await rosterResponse.json()).agents ?? []);
        setHealth(await healthResponse.json());
        setMcp(await mcpResponse.json());
        setVerification(await verifyResponse.json());
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
          {TABS.map(([name, label]) => (
            <button key={name} data-active={tab === name} onClick={() => setTab(name)}>
              {label}
              {/* The chain verifier's tab carries its verdict, so a break is visible from
                  whichever screen is up when the tamper happens. */}
              {name === "chain" && verification && !verification.ok && (
                <span className="tab-alert">BROKEN</span>
              )}
            </button>
          ))}
        </nav>
      </header>

      <main>
        {tab === "stream" && <DecisionStream decisions={decisions} onSelect={setSelected} />}
        {tab === "roster" && <AgentRoster agents={agents} health={health} />}
        {tab === "mcp" && <McpPanel calls={mcp.calls} knownTools={mcp.known_tools} />}
        {tab === "chain" && <ChainVerifier verification={verification} />}
        {tab === "health" && <SystemHealth health={health} />}
      </main>

      {selected && <DecisionDetail recordId={selected} onClose={close} />}
    </div>
  );
}
