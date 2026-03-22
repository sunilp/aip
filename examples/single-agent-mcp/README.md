# Single-Agent MCP Example

This example demonstrates an agent authenticating to an MCP tool server
using an AIP compact token (JWT signed with Ed25519).

## What it shows

1. An MCP server that requires AIP authentication on its tool endpoints
2. An agent that generates an Ed25519 keypair and issues itself a compact token
3. The server verifying the token signature, expiry, and scope before granting access
4. A successful authenticated tool call, followed by a failed call with the wrong scope

## Trust model

This example uses a **pre-shared public key** approach: the server knows the
agent's public key at startup. In production, you would resolve the agent's
identity document from its AIP identifier (e.g., fetching
`https://agent.example/.well-known/aip.json`) to obtain the public key
dynamically.

## Flow

```
Agent                          MCP Server
  |                                |
  |-- Generate Ed25519 keypair --->|
  |   (server knows agent pubkey)  |
  |                                |
  |-- POST /tools/search           |
  |   X-AIP-Token: <compact JWT>  |
  |                                |
  |   Server: verify signature,    |
  |   check scope, check expiry    |
  |                                |
  |<-- 200 OK (search results) ----|
  |                                |
  |-- POST /tools/search           |
  |   X-AIP-Token: <wrong scope>  |
  |                                |
  |   Server: scope mismatch       |
  |                                |
  |<-- 403 Forbidden --------------|
```

## Prerequisites

- Python 3.10+
- Install the AIP SDK dependencies:

```bash
cd python/
pip install -e .
```

Or, if you prefer not to install, the example scripts add `python/` to
`sys.path` automatically so the imports resolve.

## How to run

Open two terminal windows, both in the repository root.

**Terminal 1 -- start the server:**

```bash
python examples/single-agent-mcp/server.py
```

The server prints its startup message including the port (8340) and
instructions for providing the agent's public key.

**Terminal 2 -- run the client:**

Copy the `AGENT_PUBLIC_KEY_HEX` value printed by the client and export it
for the server, or let both scripts auto-coordinate by running the client
first to obtain the key, then restarting the server with that key set.

Simplest approach (two-step):

```bash
# 1. Run client to see its public key hex
python examples/single-agent-mcp/client.py
# Note the AGENT_PUBLIC_KEY_HEX value printed

# 2. Restart the server with that key
AGENT_PUBLIC_KEY_HEX=<paste-hex-here> python examples/single-agent-mcp/server.py

# 3. Run client again (same keypair via env var, or generate fresh)
AGENT_PRIVATE_KEY_HEX=<paste-hex-here> python examples/single-agent-mcp/client.py
```

Or, for a fully automated demo, use the included coordination: run the
server without `AGENT_PUBLIC_KEY_HEX` and it generates a keypair that acts
as the "known agent" -- printing both the public and private key hex so you
can feed the private key to the client.

## What to expect

The client makes two requests:

1. **Successful call** -- token has `scope: ["tool:search"]`, server accepts
   and returns search results with HTTP 200.
2. **Failed call** -- token has `scope: ["tool:email"]`, server rejects with
   HTTP 403 and an `aip_scope_insufficient` error.
