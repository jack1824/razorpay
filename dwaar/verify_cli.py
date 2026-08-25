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
5. **The money invariant**, recomputed across every record: what the ledger moved equals
   what the decision stated, with the BOUND amount as the stated amount. This is F-038's
   structural fix — see ``dwaar/invariants.py``. It is not a tamper check; `budget_before`
   and `budget_after` are inside the signed payload and check 1 already covers editing
   them. It catches the application writing a row that was wrong when it was written, which
   no signature can detect: a signature attests that we said it, not that it was true.
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
from dwaar.invariants import AmountFacts, check_amount_conserved


@dataclass
class Findings:
    checked: dict[str, int] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)
    gaps: dict[str, list[int]] = field(default_factory=dict)

    legacy: dict[str, int] = field(default_factory=dict)
    """Invariant violations in records written BEFORE the invariant was enforced, counted
    by code.

    Reported and not forgiven. `migrations/0017` records a per-chain watermark, so "before"
    is a fact in the database rather than a judgement made here — a violation above the
    watermark is a failure. Without the watermark this check would have to either fail
    forever on history or treat the two known defect classes as permanently excused, and
    "permanently excused" means a reintroduction next month is reported as a note."""

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


AMOUNT_INVARIANT = "amount_conserved"


def check_amount_conservation(
    conn: psycopg.Connection, findings: Findings, merchant: str | None = None
) -> None:
    """Recompute the money invariant over every record. F-038's structural fix.

    One query rather than one per merchant: the demo database carries 265 chains and a
    per-chain round trip would make the verifier slower than the thing it verifies.

    The rule itself is NOT written here. It lives in `dwaar/invariants.py` and the write
    path calls the same function, because two hand-written copies of a money rule drift and
    the drift is money moving without anyone noticing — which is the defect this exists to
    close, reintroduced by the fix for it.
    """
    try:
        baselines = {
            row["merchant_id"]: row["max_seq"]
            for row in conn.execute(
                "SELECT merchant_id, max_seq FROM invariant_baselines WHERE invariant = %s",
                (AMOUNT_INVARIANT,),
            ).fetchall()
        }
    except psycopg.errors.UndefinedTable:
        # Say so rather than skip. A verifier that quietly drops a check on an older schema
        # prints the same PASS as one that ran it — F-014's failure mode, in the one tool
        # whose entire value is that its report can be trusted.
        conn.rollback()
        findings.fail(
            "invariant_baselines is missing: this database predates migration 0017, so the "
            "money invariant cannot be checked against it"
        )
        return

    sql = (
        "SELECT merchant_id, seq, decision, amount_paise, bounded_amount_paise, "
        "       budget_before, budget_after "
        "FROM decision_records"
    )
    params: tuple = ()
    if merchant is not None:
        sql += " WHERE merchant_id = %s"
        params = (merchant,)

    rows = conn.execute(sql, params).fetchall()
    findings.checked["decision_records.amount"] = len(rows)

    for row in rows:
        violation = check_amount_conserved(
            AmountFacts(
                decision=row["decision"],
                requested_paise=row["amount_paise"],
                stated_paise=row["bounded_amount_paise"],
                budget_before=row["budget_before"],
                budget_after=row["budget_after"],
            )
        )
        if violation is None:
            continue
        watermark = baselines.get(row["merchant_id"])
        if watermark is not None and row["seq"] <= watermark:
            findings.legacy[violation.code] = findings.legacy.get(violation.code, 0) + 1
            continue
        findings.fail(
            f"decision_records seq={row['seq']} ({row['merchant_id']}): {violation}"
        )


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
        check_amount_conservation(conn, findings, merchant)
        check_ledger_invariants(conn, findings)
    return findings


def _render(findings: Findings) -> str:
    lines = ["DWAAR CHAIN VERIFICATION", "─" * 68]
    for name, count in sorted(findings.checked.items()):
        lines.append(f"  {name:<34} {count:>8} rows")
    if findings.legacy:
        lines.append("")
        total = sum(findings.legacy.values())
        lines.append(
            f"  NOTE {total} record(s) below the migration-0017 watermark do not conserve "
            "money."
        )
        for code, count in sorted(findings.legacy.items()):
            lines.append(f"       {count:>6}  {code}")
        lines.append(
            "       Written before the invariant was enforced. FAILURES.md F-038 and F-043."
        )
        lines.append(
            "       A violation ABOVE the watermark is a failure, not a note."
        )
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
                    "legacy": findings.legacy,
                },
                indent=2,
            )
        )
    else:
        print(_render(findings))

    return 0 if findings.ok else 1


if __name__ == "__main__":
    sys.exit(main())
