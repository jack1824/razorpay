# Console

Three screens. React + Vite + TypeScript, no state library, no component library, no router.

**Built to be legible on a projector at 1080p.** Large type, high contrast, no animation
that competes with the numbers. When it is legible it is done.

It is also a debugging tool: a live decision feed makes building the risk model, the agent
zoo and the MCP proxy substantially faster than building them blind. That is why it exists
now rather than at the end.

## Running it locally

Docker is not available on this machine, so the console runs against a uvicorn on the host
and a locally-bootstrapped PostgreSQL. Four terminals, or four backgrounded commands.

```bash
# 1. Postgres and Redis (once)
brew services start postgresql@16
redis-server --daemonize yes --save '' --appendonly no

# 2. Database, from the repo root
make bootstrap-local          # creates dwaar_owner / dwaar_app, applies migrations

# 3. API
export DATABASE_URL_APP=postgresql://dwaar_app:app_pw@localhost:5432/dwaar
export DATABASE_URL_MIGRATE=postgresql://dwaar_owner:owner_pw@localhost:5432/dwaar
export REDIS_URL=redis://localhost:6379/0
.venv/bin/python -m uvicorn dwaar.api.app:app --host 127.0.0.1 --port 8080

# 4. Something to watch — seeds the six agents and drives the timeline's purchase beats
.venv/bin/python -m scripts.seed_db "$DATABASE_URL_APP" 3

# 5. The console
cd console && npm install && npm run dev      # http://localhost:5173
```

`vite.config.ts` proxies `/v1` and `/health` to `127.0.0.1:8080`, so nothing in the
frontend carries a base URL and the same build works unchanged behind a reverse proxy.

Verify the API first if a screen is empty:

```bash
curl -s localhost:8080/health | python -m json.tool
curl -s "localhost:8080/v1/console/agents" | python -m json.tool
```

## The three screens

**1 — Decision stream.** One row per decision, newest on top, over SSE. `rule_fired` sits
next to the decision chip because *"denied"* alone is not interesting and *"denied by
`mandate.max_per_txn`"* is the entire claim. Rules beginning `mandate.` are coloured
differently: that prefix means the principal's own grant refused the request, not a merchant
policy layered on top.

**2 — Agent roster.** One card per agent with a budget bar that **drains**. This is the most
intuitive visual in the project: when the budget-breacher is denied and its bar does not
move, the enforcement claim needs no explanation.

The numbers come from `budget_ledger` through the API, never from summing the decision
stream. The ledger is the enforcement record — a bar driven by anything else could show a
different number from the one that actually denied a request.

**3 — Decision detail**, on row click. Rule fired, feature values, chain position, and the
exact signed bytes.

A `NULL` risk score renders as **the literal word NULL**, styled distinctly, with *"the
model was never consulted"* beneath it. That is the headline artifact of the arithmetic
gate: a per-transaction breach is refused before anything is scored, and the NULL is the
audit-trail proof. A blank cell would read as *"we did not fill this in"*, which is the
opposite of the claim.

`stages_executed` sits beside it, because that is what distinguishes *the model was skipped*
from *the model was stubbed* — an empty feature set alone cannot.

## Deliberately not here

Chain-verifier panel, MCP panel, policy view, health as its own page. All 30 Aug. The
health severity already drives the header dot and the DEGRADED banner, which is what screen
2 needed from it.

Severity is **not decided here**. It comes from `/health`, which derives it from
`dwaar/components.py` — a transcription of the fail matrix. If the console had its own
mapping, the banner and the audit trail would eventually disagree, and the place that
surfaces is on stage.

## Auth

A static token, and it is a mock. It keeps a browser tab out of the decision path; it is not
an authentication system. `/v1/authorize` is signed, so a browser origin cannot forge one
either way.
