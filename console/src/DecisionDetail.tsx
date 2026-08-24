import { useEffect, useState } from "react";
import type { DecisionDetail as Detail } from "./types";

/**
 * Screen 3 — opened by clicking a row.
 *
 * The NULL risk score is rendered as the literal word, styled distinctly. That is demo
 * beat 2's headline artifact: a NULL here is the audit-trail proof that a per-transaction
 * breach was denied by arithmetic and the model was never consulted. A blank cell would
 * read as "we did not fill this in", which is the opposite of the claim.
 *
 * `stages_executed` is shown beside it, because that is what distinguishes "the model was
 * skipped" from "the model was stubbed" — an empty feature set alone cannot.
 */
export function DecisionDetail({
  recordId,
  onClose,
}: {
  recordId: string;
  onClose: () => void;
}) {
  const [detail, setDetail] = useState<Detail | null>(null);

  useEffect(() => {
    let alive = true;
    fetch(`/v1/console/decisions/${recordId}`)
      .then((response) => response.json())
      .then((data) => alive && setDetail(data))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [recordId]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="detail-backdrop" onClick={onClose}>
      <div className="detail" onClick={(event) => event.stopPropagation()}>
        <button className="close" onClick={onClose}>
          esc
        </button>
        <h2>Decision {detail ? `#${detail.seq}` : ""}</h2>

        {!detail ? (
          <div className="empty">loading…</div>
        ) : (
          <>
            <dl>
              <dt>decision</dt>
              <dd>
                <span className={`chip ${detail.decision}`}>{detail.decision}</span>
              </dd>

              <dt>rule fired</dt>
              <dd>{detail.rule_fired ?? "—"}</dd>

              <dt>reason code</dt>
              <dd>{detail.reason_code}</dd>

              <dt>risk score</dt>
              <dd>
                {detail.risk_score_is_null ? (
                  <>
                    <span className="null-literal">NULL</span>
                    <div style={{ color: "var(--muted)", fontSize: 13, marginTop: 6 }}>
                      the model was never consulted
                    </div>
                  </>
                ) : (
                  <>
                    {detail.risk_score?.toFixed(4)}
                    {detail.model_version && (
                      <span style={{ color: "var(--muted)" }}> · {detail.model_version}</span>
                    )}
                  </>
                )}
              </dd>

              <dt>amount</dt>
              <dd>{detail.amount_display ?? "—"}</dd>

              <dt>budget</dt>
              <dd>
                {detail.budget_before ?? "—"} → {detail.budget_after ?? "—"} paise
              </dd>

              <dt>agent</dt>
              <dd>{detail.agent_id}</dd>

              <dt>principal</dt>
              <dd>{detail.principal_id}</dd>

              <dt>policy version</dt>
              <dd>
                {detail.policy_version === null
                  ? "NULL — the engine was never consulted"
                  : detail.policy_version === 0
                    ? "0 — no approved policy exists"
                    : detail.policy_version}
              </dd>

              <dt>latency</dt>
              <dd>{(detail.latency_us / 1000).toFixed(3)} ms</dd>
            </dl>

            <section>
              <h4>stages executed</h4>
              <div className="tokens">
                {detail.stages_executed.map((stage) => (
                  <span className="token" key={stage}>
                    {stage}
                  </span>
                ))}
              </div>
            </section>

            {detail.degraded_mode.length > 0 && (
              <section>
                <h4>degraded</h4>
                <div className="tokens">
                  {detail.degraded_mode.map((token) => (
                    <span className="token" key={token}>
                      {token}
                    </span>
                  ))}
                </div>
              </section>
            )}

            <section>
              <h4>feature values used</h4>
              <pre>{JSON.stringify(detail.features, null, 2)}</pre>
            </section>

            <section>
              <h4>chain</h4>
              <dl>
                <dt>prev_hash</dt>
                <dd>{detail.prev_hash}</dd>
                <dt>payload_hash</dt>
                <dd>{detail.payload_hash}</dd>
                <dt>signing key</dt>
                <dd>{detail.signing_key_id}</dd>
              </dl>
              <h4>signed bytes</h4>
              <pre>{detail.canonical_json}</pre>
            </section>
          </>
        )}
      </div>
    </div>
  );
}
