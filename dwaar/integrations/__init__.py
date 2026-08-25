"""Outbound integrations. Everything that leaves this process lives here.

One rule: **an integration is called AFTER a decision, never during one.** Nothing in this
package can influence whether a request is authorised — it acts on what was already decided,
bounded by what the ledger already reserved.

That keeps the request path's failure surface bounded to components we run. A payment
provider being slow must not be able to turn into an authorization outage, and it cannot,
because the authorization already happened.
"""
