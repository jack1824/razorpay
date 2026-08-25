"""The MCP enforcement point.

Sits in front of a Razorpay Remote MCP Server, maps each tool to a delegated scope, and
evaluates it against the mandate the principal signed — through the same pipeline, the same
ledger and the same chain that `/v1/authorize` uses.

**This is not a vulnerability claim about Razorpay's MCP server.** See `dwaar/mcp/README.md`
and `dwaar/mcp/scopes.py`: a merchant token doing what a merchant token does is not a flaw,
and saying otherwise would be both wrong and a bad way to talk about someone's product. The
claim is that a token is the wrong primitive for delegating authority to something that makes
its own decisions, because a token carries possession and delegation requires intent.
"""
