# `dwaar/mcp/` — the enforcement point

A proxy that sits in front of a Razorpay Remote MCP Server. It intercepts tool calls, maps
each tool to a delegated scope, evaluates the call against the mandate the principal signed,
and records the decision in the same hash chain as everything else.

## What we are and are not saying

**This is not a vulnerability report, and the distinction is not a courtesy.**

Razorpay's Remote MCP Server authenticates with a merchant token —
`base64(RAZORPAY_API_KEY:RAZORPAY_API_SECRET)` — and exposes 35+ tools including
`create_payment_link`, `create_refund`, `create_order` and `create_instant_settlement`. The
documented scoping controls are a `--read-only` flag and a `--toolsets` filter on the local
server. All of that is published, and all of it works exactly as documented.

A token doing what a token does is not a flaw. There is no bug here to report and we would
lose any argument that claimed otherwise.

The observation is narrower:

> A token carries **possession**. Delegating authority to something that makes its own
> decisions requires expressing **intent** — which principal, up to what amount, for which
> actions, until when. Toolset-level and read-only granularity exist. Per-principal
> delegation with monetary bounds does not.

That is a **missing abstraction**, not a defect. This directory is an attempt at the
abstraction rather than a report about its absence.

The difference matters practically as well as diplomatically. "Your product has a security
hole" is a claim we would have to defend and would lose on the merits. "Your product is
missing a primitive, here is one, here is what it costs" is a claim the code supports.

## What the proxy actually does

```
agent  ──tool call──▶  proxy  ──▶  resolve mandate
                                   map tool → required scope
                                   scope check          ← fails here, denies, chains it
                                   arithmetic gate      ← same gate as /v1/authorize
                                   ledger reservation   ← same ledger
                                   chained record       ← same chain, same verifier
                                   ──▶  upstream MCP server
```

Nothing in this directory is a second authorization system. Every decision goes through
`dwaar.authorize.pipeline`, so an MCP denial and an HTTP denial are the same kind of row in
the same chain. A proxy with its own rules would be a second place to get authority wrong.

## Scope and amount are different questions

    scope    MAY this agent take this KIND of action at all?
    amount   is THIS instance within what the principal allowed?

A mandate for ₹50,000 of collections does not authorise a ₹40,000 refund. The amount is fine.
The direction is not. Checking only the amount is what makes a spending limit look like a
delegation model, and it is the specific mistake this file exists to avoid.

## What bounds an MCP call, and what does not

    scope     ✅  the delegated action, checked first
    amount    ✅  the same per-transaction cap as any other request
    expiry    ✅  the same mandate expiry
    budget    ✅  the same ledger, the same reservation
    category  ❌  a tool call has no category

That last line is a genuine narrowing and it is stated here rather than left to be
discovered. Categories describe what is being *bought*. A tool call describes what *action*
is taken, and `create_order` has no category field in Razorpay's API — the concept is ours.
Requiring one would mean every MCP call denies on a field that does not exist.

So an MCP call is bounded by scope, amount, expiry and budget. A tool call that does carry a
category is still checked against the mandate's lists; the narrowing applies only where there
is genuinely nothing to check.

**The consequence, said plainly:** an agent delegated `collect.create` can create an order for
goods in a category its mandate would refuse over `/v1/authorize`. Closing that requires the
tool call to carry line items, which is a change to what the vendor's tool accepts and not
something a proxy can invent.

## Unlisted tools deny

`scope_map.json` sets `default_action: deny` and `dwaar/mcp/scopes.py` refuses to load a map
that says anything else.

A proxy in front of a vendor's tool list whose default is permissive stops enforcing the day
the vendor ships a tool nobody mapped — and vendors ship tools without telling their
integrators, because that is what a vendor does. The failure mode of default-deny is a
support ticket. The failure mode of default-allow is an agent moving money through an
unmapped tool.

A tool being absent from the map is **not** a statement that it is safe. It is a statement
that nobody has decided.

## The limitation, stated first rather than last

**An agent holding the raw merchant token bypasses this proxy entirely.** There is no
cryptography here that prevents it. The proxy is an enforcement point for an agent that was
given a *mandate* instead of a *token*.

That is exactly why this belongs in a payments platform, where the credential can be scoped
at the moment it is issued, rather than as a third-party product that asks to be routed
through. A bolt-on enforcement layer that the thing under enforcement can decline to use is
a convention, not a control.

`DEFENSE.md` entry 9 is the longer version.

## Running it

```bash
# The upstream. Defaults to the stub, which speaks the same tool names.
MCP_UPSTREAM_MODE=stub            # or live
MCP_UPSTREAM_URL=https://mcp.razorpay.com/mcp

curl -X POST localhost:8080/v1/mcp/call \
  -H 'Content-Type: application/json' \
  -H "$(dwaar-sign ...)" \
  -d '{"agent_id":"agt_...","mandate_id":"mnd_...","tool":"create_refund",
       "arguments":{"payment_id":"pay_test","amount":4000000},
       "idempotency_key":"..."}'
```

The demo call is `create_refund` for ₹40,000 against a mandate carrying
`["read", "collect.create"]`. It is denied with `scope_not_delegated`, and the denial is in
the chain with `risk_score = NULL` — refused on the mandate's own terms, with no model
consulted.

The same call with a raw merchant token succeeds. That is the gap, and it is a gap in the
primitive rather than in the implementation.
