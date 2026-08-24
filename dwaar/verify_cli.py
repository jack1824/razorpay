"""`dwaar-verify` — the independent verifier.

    python -m dwaar.verify_cli [--dsn ...] [--merchant ...] [--json]

Exit 0 if everything verifies, 1 if anything does not.

── No write path, and that is structural ───────────────────────────────────────────────

This module imports no repository that writes, opens its connection **read-only**, and
issues only SELECTs. The point of an independent verifier is that its report does not
depend on trusting the thing it is verifying — a verifier that could modify the chain would
be no more credible than the application.

It is also the artifact that answers *"why should I believe your audit log?"*: run it
yourself, against the same database, with no cooperation from the running service.

── What it checks ──────────────────────────────────────────────────────────────────────

1. **Columns agree with the signed bytes**, for every table in
   ``dwaar/crypto/integrity.py``'s registry. This is first because it is the check that was
   missing (F-016): demo beat 6 is ``UPDATE decision_records SET amount_paise``, which
   leaves the signed blob untouched, so hash and signature both still verify.
2. **The chain links**, per merchant, by walking rather than by `seq - 1` arithmetic —
   a Postgres outage produces absent records, and absence must not read as a tamper.
3. **Signatures verify**, resolved through the `signing_key_id` each record names, so a key
   rotation does not invalidate history.
4. **Ledger invariants**: no negative balance, and `sum(deltas) == balance` per mandate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field

import psycopg
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from psycopg.rows import dict_row

from dwaar.crypto import record as recordmod
from dwaar.crypto.integrity import REGISTRY, IntegrityError, assert_columns_match_canonical


@dataclass
class Findings:
    checked: dict[str, int] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)
    gaps: dict[str, list[int]] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.failures

    def fail(self, message: str) -> None:
        self.failures.append(message)


def _connect(dsn: str) -> psycopg.Connection:
    """Read-only, and told so at the server.

    ``default_transaction_read_only`` means the database itself refuses a write from this
    connection. A verifier that merely *chooses* not to write is a promise; one that cannot
    is a property.
    """
    # Passed as a connection OPTION, not executed as a statement. `SET
    # default_transaction_read_only = on` governs transactions started *after* it, so
    # running it as a statement leaves the transaction it runs in read-write — the
    # verifier would have been read-only in name only.
    return psycopg.connect(
        dsn, row_factory=dict_row, options="-c default_transaction_read_only=on"
    )


def check_columns_match_signed_form(
    conn: psycopg.Connection, findings: Findings, merchant: str | None = None
) -> None:
    """The check whose absence would have printed a green PASS on stage.

    Scoped by merchant when asked. Without that, `--merchant` would narrow the chain walk
    but still scan every other merchant's rows, so verifying one merchant could fail on
    someone else's data — which is not a useful answer to "is MY chain intact".
    """
    for check in REGISTRY:
        sql = f"SELECT * FROM {check.table}"  # noqa: S608
        params: tuple = ()
        if merchant is not None and check.merchant_predicate is not None:
            sql += f" WHERE {check.merchant_predicate}"
            params = (merchant,)
        rows = conn.execute(sql, params).fetchall()
        findings.checked[f"{check.table}.columns"] = len(rows)
        for row in rows:
            try:
                assert_columns_match_canonical(row, check)
            except IntegrityError as exc:
                findings.fail(str(exc))


def check_chains(conn: psycopg.Connection, findings: Findings, merchant: str | None) -> None:
    keys = {
        r["key_id"]: bytes(r["public_key"])
        for r in conn.execute("SELECT key_id, public_key FROM signing_keys").fetchall()
    }

    if merchant is not None:
        merchants = [merchant]
    else:
        merchants = [
            r["merchant_id"]
            for r in conn.execute(
                "SELECT DISTINCT merchant_id FROM decision_records ORDER BY merchant_id"
            ).fetchall()
        ]

    total = 0
    for merchant_id in merchants:
        rows = conn.execute(
            "SELECT * FROM decision_records WHERE merchant_id = %s ORDER BY seq",
            (merchant_id,),
        ).fetchall()
        total += len(rows)
        if not rows:
            continue

        expected_prev = b"\x00" * 32  # genesis
        for row in rows:
            seq = row["seq"]

            recomputed = hashlib.sha256(row["canonical_json"].encode()).digest()
            if recomputed != bytes(row["payload_hash"]):
                findings.fail(
                    f"decision_records seq={seq} ({merchant_id}): payload_hash does not "
                    "match canonical_json"
                )
                break

            if recordmod.canonical_json(json.loads(row["canonical_json"])) != row["canonical_json"]:
                findings.fail(
                    f"decision_records seq={seq} ({merchant_id}): canonical_json is not in "
                    "canonical form"
                )
                break

            if bytes(row["prev_hash"]) != expected_prev:
                findings.fail(
                    f"decision_records seq={seq} ({merchant_id}): CHAIN BROKEN — prev_hash "
                    "does not match the preceding payload_hash"
                )
                break

            public = keys.get(row["signing_key_id"])
            if public is None:
                findings.fail(
                    f"decision_records seq={seq} ({merchant_id}): unknown signing_key_id "
                    f"{row['signing_key_id']!r}"
                )
                break
            try:
                Ed25519PublicKey.from_public_bytes(public).verify(
                    bytes(row["signature"]), row["canonical_json"].encode()
                )
            except InvalidSignature:
                findings.fail(
                    f"decision_records seq={seq} ({merchant_id}): signature does not verify"
                )
                break

            expected_prev = bytes(row["payload_hash"])

        # Gaps are REPORTED, not treated as breaks. FAIL_MATRIX.md records that a Postgres
        # outage produces denials that cannot be chained; absence must not read as a tamper.
        observed = [r["seq"] for r in rows]
        missing = sorted(set(range(observed[0], observed[-1] + 1)) - set(observed))
        if missing:
            findings.gaps[merchant_id] = missing

    findings.checked["decision_records.chain"] = total


def check_ledger_invariants(conn: psycopg.Connection, findings: Findings) -> None:
    negative = conn.execute(
        "SELECT count(*) AS n FROM budget_ledger WHERE balance_after < 0"
    ).fetchone()["n"]
    if negative:
        findings.fail(f"budget_ledger: {negative} entries with balance_after < 0")

    drift = conn.execute(
        "SELECT mandate_id, sum(delta_paise) AS total, "
        "       (array_agg(balance_after ORDER BY entry_id DESC))[1] AS tail "
        "FROM budget_ledger GROUP BY mandate_id"
    ).fetchall()
    for row in drift:
        if row["total"] != row["tail"]:
            findings.fail(
                f"budget_ledger {row['mandate_id']}: sum(deltas)={row['total']} != "
                f"balance={row['tail']}"
            )
    findings.checked["budget_ledger.mandates"] = len(drift)


def verify(dsn: str, *, merchant: str | None = None) -> Findings:
    findings = Findings()
    with _connect(dsn) as conn:
        check_columns_match_signed_form(conn, findings, merchant)
        check_chains(conn, findings, merchant)
        check_ledger_invariants(conn, findings)
    return findings


def _render(findings: Findings) -> str:
    lines = ["DWAAR CHAIN VERIFICATION", "─" * 68]
    for name, count in sorted(findings.checked.items()):
        lines.append(f"  {name:<34} {count:>8} rows")
    if findings.gaps:
        lines.append("")
        for merchant_id, missing in findings.gaps.items():
            shown = missing[:10]
            more = "" if len(missing) <= 10 else f" (+{len(missing) - 10} more)"
            lines.append(
                f"  NOTE {merchant_id}: {len(missing)} seq gap(s) at {shown}{more} — "
                "absence, not a break. See FAIL_MATRIX.md."
            )
    lines.append("─" * 68)
    if findings.ok:
        lines.append("  PASS — every record verifies against its signature and its columns")
    else:
        lines.append(f"  FAIL — {len(findings.failures)} problem(s):")
        lines.extend(f"    {failure}" for failure in findings.failures)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    from dwaar.config import get_settings

    parser = argparse.ArgumentParser(prog="dwaar-verify", description=__doc__.splitlines()[0])
    parser.add_argument("--dsn", default=None, help="defaults to DATABASE_URL_APP")
    parser.add_argument("--merchant", default=None, help="verify one merchant's chain")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    dsn = args.dsn or get_settings().database_url_app
    findings = verify(dsn, merchant=args.merchant)

    if args.json:
        print(
            json.dumps(
                {
                    "ok": findings.ok,
                    "checked": findings.checked,
                    "failures": findings.failures,
                    "gaps": findings.gaps,
                },
                indent=2,
            )
        )
    else:
        print(_render(findings))

    return 0 if findings.ok else 1


if __name__ == "__main__":
    sys.exit(main())
