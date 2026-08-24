"""Policy compiler — English in, a tested and human-approved ruleset out.

    python -m dwaar.policy.compiler compile --merchant mch_x --file policy.txt
    python -m dwaar.policy.compiler show    --policy pol_x
    python -m dwaar.policy.compiler approve --policy pol_x --by "arpit"

**OFFLINE. CLI only.** This module imports an LLM client and is therefore unreachable from
`dwaar.api` and `dwaar.authorize` by construction — asserted by
`tests/test_hot_path_purity.py`, which fails the build if that ever changes.

── This is the LLM's best use, and the argument is worth making precisely ──────────────

The model does not decide anything about money. It performs a **translation**, once, from
English into a closed DSL — and the translation is then checked three ways before it can
affect a request:

1. It must **parse** against the closed operator and variable sets in ``dsl.py``. A rule
   referencing a variable that does not exist is a compile error, not a rule that silently
   never fires.
2. Its **generated property tests must pass**. The model writes cases it believes should
   allow and deny; they are executed against the real evaluator. A ruleset that does not
   do what its own author predicted does not ship.
3. A **human approves a diff**. `approved_by IS NULL` means not live, enforced by a `WHERE`
   clause and by a database CHECK, not by convention.

Compile knowledge once, execute deterministically forever. That is the only place in this
system where a language model is the right tool, and it is off the request path.

── Ambiguity is surfaced, never resolved silently ──────────────────────────────────────

When the model reports that the English is ambiguous, the CLI **prints it as a question and
records it in `ambiguities`**. It also compiles the *more restrictive* reading in the
meantime. A compiler that quietly picked the permissive interpretation of "block large
international payments" would be inventing authority nobody granted — and the merchant
would only find out from the transaction that got through.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row

from dwaar.policy import dsl, engine
from dwaar.policy.dsl import NAMESPACE, OPERATORS, VALID_ACTIONS, PolicyError

MAX_ATTEMPTS = 3

# Gemini enforces this, so the DSL's shape is guaranteed on the first response rather than
# coaxed out of prose across a retry loop. The retry loop below therefore exists only for
# SEMANTIC failures — rules that parse but do not do what the model predicted.
RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "description": {"type": "string"},
                    "when": {"type": "string", "description": "JSON expression, serialised"},
                    "action": {"type": "string", "enum": sorted(VALID_ACTIONS)},
                    "reason_code": {"type": "string"},
                    "bound_to_paise": {"type": "integer"},
                },
                "required": ["id", "description", "when", "action", "reason_code"],
            },
        },
        "tests": {
            "type": "array",
            "description": "Cases the author believes this ruleset should produce.",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "namespace": {"type": "string", "description": "JSON object, serialised"},
                    "expect_rule_id": {"type": "string"},
                    "expect_action": {"type": "string", "enum": sorted(VALID_ACTIONS)},
                },
                "required": ["name", "namespace", "expect_action"],
            },
        },
        "ambiguities": {
            "type": "array",
            "description": (
                "Anything the English did not settle. Report it rather than guessing; the "
                "compiler will use the more restrictive reading and ask the merchant."
            ),
            "items": {
                "type": "object",
                "properties": {
                    "question": {"type": "string"},
                    "restrictive_reading": {"type": "string"},
                    "permissive_reading": {"type": "string"},
                },
                "required": ["question", "restrictive_reading", "permissive_reading"],
            },
        },
    },
    "required": ["rules", "tests", "ambiguities"],
}


PROMPT = """You are compiling a merchant's English spending policy into a closed rule DSL.

You are NOT deciding anything. You are translating, once, into a form that will then be
executed deterministically for every request. Your output is reviewed by a human before it
can affect any money.

THE DSL
Expressions are single-key objects. The operator set is CLOSED:
{operators}

Variables are also CLOSED. Referencing one outside this list is a compile error:
{namespace}

Examples:
  {{"in": [{{"var": "request.category"}}, {{"var": "mandate.deny_categories"}}]}}
  {{"and": [{{"==": [{{"var": "agent.verified"}}, {{"lit": false}}]}},
            {{">": [{{"var": "request.amount_paise"}}, {{"lit": 200000}}]}}]}}

RULES
- Evaluated IN ORDER; the first match wins. Order them so the most specific comes first.
- action is one of: {actions}
- action "bound" requires bound_to_paise, a positive integer in PAISE.
- Money is ALWAYS integer paise. Rupees 5,000 is 500000. Never use a decimal.
- `id` appears in the audit trail as the reason a request was denied. Make it a short,
  specific, lowercase identifier a human would recognise in a dispute.
- Emit `when` as a JSON STRING containing the expression object.

TESTS
Write cases that would catch a mistake in YOUR OWN rules, not cases that confirm them.
Include at least one case per rule that should FIRE and one nearby case that should NOT —
a boundary just under a threshold is worth more than a value far from it. Emit `namespace`
as a JSON STRING containing an object of dotted variable names.

AMBIGUITIES
If the English does not settle something, say so. Do not guess. For each, give the
restrictive reading and the permissive one. The compiler will apply the RESTRICTIVE one and
ask the merchant.

Being wrong here means a merchant's money moves on a rule nobody intended, so an unanswered
question is a better outcome than a confident guess.

THE MERCHANT'S POLICY
{policy}
"""


@dataclass
class CompileResult:
    ruleset: dsl.Ruleset
    raw: dict[str, Any]
    tests: list[dict[str, Any]]
    ambiguities: list[dict[str, str]]
    model: str
    attempts: int
    test_failures: list[str] = field(default_factory=list)

    @property
    def tests_passed(self) -> bool:
        return not self.test_failures


def _parse_embedded_json(value: Any, what: str) -> Any:
    """`when` and `namespace` arrive as JSON strings.

    Nested free-form objects cannot be expressed in a response schema strict enough to be
    worth having, so they are carried as strings and parsed here — where a malformed one is
    a compile error rather than something that reaches a request.
    """
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PolicyError(f"{what} is not valid JSON: {value!r}") from exc


def build_ruleset(payload: dict[str, Any]) -> dsl.Ruleset:
    document = {
        "rules": [
            {**rule, "when": _parse_embedded_json(rule["when"], f"rule {rule.get('id')!r} when")}
            for rule in payload.get("rules", [])
        ]
    }
    return dsl.parse(document)


def run_generated_tests(ruleset: dsl.Ruleset, tests: list[dict[str, Any]]) -> list[str]:
    """Execute the model's own predictions against the real evaluator.

    Not a formality: a ruleset that does not do what its author expected is exactly the
    ruleset a human reviewer would approve by mistake, because it reads correctly.
    """
    failures: list[str] = []
    for case in tests:
        name = case.get("name", "<unnamed>")
        try:
            namespace = _parse_embedded_json(case["namespace"], f"test {name!r} namespace")
        except PolicyError as exc:
            failures.append(f"{name}: {exc}")
            continue

        unknown = set(namespace) - set(NAMESPACE)
        if unknown:
            failures.append(f"{name}: test references unknown variables {sorted(unknown)}")
            continue

        full = dict.fromkeys(NAMESPACE)
        full.update(namespace)

        verdict = engine.evaluate(ruleset, full)
        expected_action = case.get("expect_action")
        expected_rule = case.get("expect_rule_id")

        if verdict.action != expected_action:
            failures.append(
                f"{name}: expected action {expected_action!r}, got {verdict.action!r} "
                f"(rule {verdict.rule_id!r})"
            )
        elif expected_rule and verdict.rule_id != expected_rule:
            failures.append(
                f"{name}: expected rule {expected_rule!r}, got {verdict.rule_id!r}"
            )
    return failures


async def compile_policy(policy_text: str, *, max_attempts: int = MAX_ATTEMPTS) -> CompileResult:
    """Compile, run the generated tests, and retry on SEMANTIC failure.

    Schema conformance comes from the API, so the loop is not there to coax valid JSON out
    of the model — it is there for rulesets that parse and then fail their own tests.
    """
    from dwaar.llm import client

    prompt = PROMPT.format(
        operators=", ".join(sorted(OPERATORS)),
        namespace="\n".join(f"  {name}" for name in sorted(NAMESPACE)),
        actions=", ".join(sorted(VALID_ACTIONS)),
        policy=policy_text,
    )

    last_error: str | None = None
    for attempt in range(1, max_attempts + 1):
        attempt_prompt = prompt
        if last_error:
            attempt_prompt += (
                f"\n\nYOUR PREVIOUS ATTEMPT FAILED ITS OWN TESTS:\n{last_error}\n"
                "Fix the RULES if they are wrong. Fix the TESTS only if the test was wrong "
                "about what the English asked for."
            )

        payload, model = await client.complete_json(attempt_prompt, schema=RESPONSE_SCHEMA)

        try:
            ruleset = build_ruleset(payload)
        except PolicyError as exc:
            last_error = f"the ruleset did not parse: {exc}"
            continue

        tests = payload.get("tests", [])
        failures = run_generated_tests(ruleset, tests)
        result = CompileResult(
            ruleset=ruleset,
            raw=payload,
            tests=tests,
            ambiguities=payload.get("ambiguities", []),
            model=model,
            attempts=attempt,
            test_failures=failures,
        )
        if not failures:
            return result
        last_error = "\n".join(failures)

    return result


# ── persistence ─────────────────────────────────────────────────────────────────────

async def store_compiled(
    dsn: str,
    *,
    merchant_id: str,
    source_nl: str,
    result: CompileResult,
) -> tuple[str, int]:
    """Insert as the next version, UNAPPROVED. Returns ``(policy_id, version)``.

    Deliberately never approves. Auto-promotion is the one thing that would collapse the
    whole argument for using a model here: the safety comes from a human looking at a diff,
    and a compiler that could skip that step has removed its own justification.
    """
    from dwaar.ids import new_id

    async with await psycopg.AsyncConnection.connect(dsn, row_factory=dict_row) as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT COALESCE(max(version), 0) + 1 AS next FROM policies WHERE merchant_id = %s",
                (merchant_id,),
            )
            version = (await cur.fetchone())["next"]

            policy_id = new_id("pol")
            await cur.execute(
                "INSERT INTO policies (policy_id, merchant_id, version, source_nl, "
                " compiled_rules, generated_tests, tests_passed) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (
                    policy_id,
                    merchant_id,
                    version,
                    source_nl,
                    json.dumps(result.ruleset.to_json(), sort_keys=True),
                    json.dumps(
                        {
                            "tests": result.tests,
                            "ambiguities": result.ambiguities,
                            "model": result.model,
                            "attempts": result.attempts,
                        },
                        sort_keys=True,
                    ),
                    result.tests_passed,
                ),
            )
        await conn.commit()
    return policy_id, version


async def approve_policy(dsn: str, policy_id: str, *, approved_by: str) -> None:
    """The human gate. Signs the canonical form and marks it live.

    The database refuses to set `approved_by` on a policy whose generated tests have not
    passed (`policies_approved_implies_tested`), so the gate cannot be bypassed by an
    application that forgets to check.
    """
    from dwaar.config import get_settings
    from dwaar.crypto.signer import derive_signer
    from dwaar.db.repositories import policies as policy_repo

    settings = get_settings()
    signer = derive_signer(settings.signing_seed, keys_dir=settings.keys_dir)

    async with await psycopg.AsyncConnection.connect(dsn, row_factory=dict_row) as conn:
        existing = await policy_repo.get(conn, policy_id)
        if existing is None:
            raise SystemExit(f"unknown policy {policy_id}")

        from dwaar.crypto.integrity import POLICIES

        canonical = POLICIES.rebuild({**existing, "approved_by": approved_by})
        signature = signer.sign(canonical.encode())

        await policy_repo.approve(
            conn, policy_id, approved_by=approved_by, signature=signature
        )
        await conn.commit()


# ── CLI ─────────────────────────────────────────────────────────────────────────────

def _render_diff(result: CompileResult, previous: dict[str, Any] | None) -> str:
    """What the human actually reviews.

    A rule-by-rule listing rather than a JSON diff: the reviewer is checking whether the
    rules match the English, and a unified diff of nested JSON is the wrong shape for that
    question.
    """
    lines = ["COMPILED RULESET", "─" * 72]
    for index, rule in enumerate(result.ruleset.rules, start=1):
        lines.append(f"{index}. {rule.id}  →  {rule.action.upper()}")
        if rule.description:
            lines.append(f"     {rule.description}")
        lines.append(f"     when: {json.dumps(rule.when)}")
        if rule.bound_to_paise:
            lines.append(f"     bound to: {rule.bound_to_paise} paise")
        lines.append("")

    lines.append("GENERATED TESTS")
    lines.append("─" * 72)
    for case in result.tests:
        mark = "ok " if result.tests_passed else "  ?"
        lines.append(f"  [{mark}] {case.get('name')} → {case.get('expect_action')}")
    if result.test_failures:
        lines.append("")
        lines.append("  FAILURES:")
        lines.extend(f"    {failure}" for failure in result.test_failures)

    if result.ambiguities:
        lines.append("")
        lines.append("QUESTIONS FOR THE MERCHANT — the restrictive reading was applied")
        lines.append("─" * 72)
        for item in result.ambiguities:
            lines.append(f"  ? {item['question']}")
            lines.append(f"      applied:  {item['restrictive_reading']}")
            lines.append(f"      rejected: {item['permissive_reading']}")

    if previous is not None:
        lines.append("")
        lines.append(
            f"REPLACES version {previous['version']} "
            f"(approved by {previous['approved_by']})"
        )

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    from dwaar.config import get_settings

    parser = argparse.ArgumentParser(
        prog="dwaar-policy", description="Compile an English policy into a tested rule DSL."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    compile_cmd = sub.add_parser("compile", help="compile English into an UNAPPROVED version")
    compile_cmd.add_argument("--merchant", required=True)
    compile_cmd.add_argument("--file", type=Path, required=True)
    compile_cmd.add_argument("--dsn", default=None)

    show_cmd = sub.add_parser("show", help="print a compiled version for review")
    show_cmd.add_argument("--policy", required=True)
    show_cmd.add_argument("--dsn", default=None)

    approve_cmd = sub.add_parser("approve", help="THE HUMAN GATE — sign and make live")
    approve_cmd.add_argument("--policy", required=True)
    approve_cmd.add_argument("--by", required=True, help="the person taking responsibility")
    approve_cmd.add_argument("--dsn", default=None)

    args = parser.parse_args(argv)
    dsn = args.dsn or get_settings().database_url_migrate

    if args.command == "compile":
        text = args.file.read_text(encoding="utf-8")
        result = asyncio.run(compile_policy(text))
        print(_render_diff(result, None))
        print()

        if not result.tests_passed:
            print(
                f"REFUSED after {result.attempts} attempt(s): the ruleset does not do what "
                "its own tests predict. Nothing was stored."
            )
            return 1

        policy_id, version = asyncio.run(
            store_compiled(dsn, merchant_id=args.merchant, source_nl=text, result=result)
        )
        print(f"stored {policy_id} as version {version} — NOT LIVE")
        print(f"review it, then: python -m dwaar.policy.compiler approve --policy {policy_id} "
              f'--by "your name"')
        return 0

    if args.command == "show":
        async def _show():
            from dwaar.db.repositories import policies as policy_repo

            async with await psycopg.AsyncConnection.connect(dsn, row_factory=dict_row) as conn:
                return await policy_repo.get(conn, args.policy)

        row = asyncio.run(_show())
        if row is None:
            print(f"unknown policy {args.policy}", file=sys.stderr)
            return 1
        print(json.dumps(row["compiled_rules"], indent=2, sort_keys=True))
        print()
        print(f"version {row['version']}  tests_passed={row['tests_passed']}  "
              f"approved_by={row['approved_by'] or 'NULL — NOT LIVE'}")
        return 0

    if args.command == "approve":
        asyncio.run(approve_policy(dsn, args.policy, approved_by=args.by))
        print(f"{args.policy} approved by {args.by} and signed — now live")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
