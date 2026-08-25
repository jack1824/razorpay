import type { Verification } from "./types";

/**
 * Screen 3 — demo beat 6.
 *
 * A superuser rewrites `amount_paise` on a committed record. The UPDATE succeeds, because
 * it must: the control being demonstrated is detection by cryptography, not prevention by
 * the database. Then this panel goes red and names the seq.
 *
 * The verdict is deliberately enormous. It is the one moment in the demo where the audience
 * should read a single word from across the room and understand it without the presenter
 * saying anything.
 *
 * ── The command is on screen for a reason ─────────────────────────────────────────────
 *
 * This panel asks the API whether the API's own audit trail is intact, which is exactly the
 * circularity the independent verifier exists to break. So `make verify` is printed beside
 * the result: the verdict here is for the room, and the command is for the reader who does
 * not take our word for it — a separate process, a read-only connection, no cooperation
 * from the service being checked.
 */
export function ChainVerifier({ verification }: { verification: Verification | null }) {
  if (!verification) {
    return <div className="empty">verifying the chain…</div>;
  }

  const { ok, records, broken_at_seq, failures, gaps, legacy, verified_ago_s } = verification;
  const legacyTotal = Object.values(legacy ?? {}).reduce((sum, n) => sum + n, 0);

  return (
    <div className="verifier">
      <div className={`verdict ${ok ? "pass" : "fail"}`}>
        {ok ? "PASS" : broken_at_seq !== null ? `CHAIN BROKEN AT SEQ ${broken_at_seq}` : "FAIL"}
      </div>

      <div className="verdict-sub">
        {records.toLocaleString()} records verified against their signatures and their columns
        {" · "}
        {/* The AGE, always. A cached PASS read as a live one is the same failure the
            SIMULATED badge exists to prevent. */}
        <span className="muted">checked {verified_ago_s}s ago</span>
      </div>

      {!ok && (
        <ul className="failures">
          {failures.map((failure) => (
            <li key={failure}>{failure}</li>
          ))}
        </ul>
      )}

      <div className="verifier-notes">
        {gaps.length > 0 && (
          <p>
            <b>{gaps.length} sequence gap(s)</b> — reported, not treated as a break. A
            Postgres outage produces denials that cannot be chained, and absence must not
            read as a tamper.
          </p>
        )}
        {legacyTotal > 0 && (
          <p>
            <b>{legacyTotal} record(s)</b> written before the money invariant was enforced do
            not conserve money:{" "}
            {Object.entries(legacy)
              .map(([code, n]) => `${n} × ${code}`)
              .join(", ")}
            . Counted rather than hidden — a violation above the watermark is a failure.
          </p>
        )}
        <p className="command">
          Do not take this panel's word for it. It is the API reporting on the API:
          <code>{verification.command}</code> runs the same checks from a separate process on
          a read-only connection.
        </p>
      </div>
    </div>
  );
}
