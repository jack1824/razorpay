import type { McpCall } from "./types";

/**
 * Screen 4 — demo beat 7, the one worth pausing on.
 *
 * `create_refund` for ₹40,000 against a mandate that delegates `[read, collect.create]`.
 * The amount is fine. The direction is not. The mandate never delegated the power to move
 * money outward, so the call is refused on the mandate's own terms — and `risk_score` is
 * NULL, which is the proof no model was consulted.
 *
 * ── Every column here comes from the chain ────────────────────────────────────────────
 *
 * `tool` is a signed field of the decision record (migration 0017) and the delegated scopes
 * come from the mandate the record names by hash. The alternative was a ring buffer of
 * recent tool calls kept in the API for display, which would have been an hour's work
 * instead of a migration — and would have made this panel a second account of what
 * happened, next to the audit trail, free to disagree with it.
 */
export function McpPanel({ calls, knownTools }: { calls: McpCall[]; knownTools: string[] }) {
  return (
    <>
      <div className="mcp-legend">
        <span>
          <b>{knownTools.length}</b> tools mapped. Anything unlisted is <b>denied</b> — a
          proxy in front of a vendor's tool list whose default is allow stops enforcing the
          day the vendor adds a tool.
        </span>
      </div>

      {calls.length === 0 ? (
        <div className="empty">no MCP tool calls in this chain yet</div>
      ) : (
        <table className="stream">
          <thead>
            <tr>
              <th>seq</th>
              <th>tool</th>
              <th>scope required</th>
              <th>scopes delegated</th>
              <th>decision</th>
              <th>rule</th>
              <th className="num">amount</th>
              <th>risk</th>
            </tr>
          </thead>
          <tbody>
            {calls.map((call) => (
              <tr key={call.record_id}>
                <td className="num">{call.seq}</td>
                <td>
                  <code>{call.tool}</code>
                  {call.money_direction === "outbound" && (
                    <span className="outbound" title="moves money OUT of the merchant account">
                      ↑ outbound
                    </span>
                  )}
                </td>
                <td>
                  {call.required_scope ? (
                    <code>{call.required_scope}</code>
                  ) : (
                    /* Unlisted is not "unknown, allowed with a warning". It is a statement
                       that nobody has decided, and the default for that is deny. */
                    <span className="unmapped">unmapped → deny</span>
                  )}
                </td>
                <td className="tokens">
                  {call.delegated_is_null ? (
                    <span className="null-literal">NULL</span>
                  ) : call.delegated.length === 0 ? (
                    <span className="null-literal">none</span>
                  ) : (
                    call.delegated.map((scope) => (
                      <span
                        className="token"
                        key={scope}
                        data-match={scope === call.required_scope}
                      >
                        {scope}
                      </span>
                    ))
                  )}
                </td>
                <td>
                  <span className={`chip ${call.decision}`}>{call.decision}</span>
                </td>
                <td className="rule">{call.rule_fired ?? "—"}</td>
                <td className="num">{call.amount_display ?? "—"}</td>
                <td>
                  {call.risk_score_is_null ? (
                    /* The headline artifact. The mandate settled it, so the model was never
                       asked — and the record proves it rather than asserting it. */
                    <span className="null-literal" title="the model was never consulted">
                      NULL
                    </span>
                  ) : (
                    "scored"
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
