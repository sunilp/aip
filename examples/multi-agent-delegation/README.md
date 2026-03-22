# Multi-Agent Delegation Example

This example demonstrates a **3-hop delegation chain** using AIP chained
tokens (Biscuit-based). An orchestrator creates an authority token with broad
permissions, delegates a narrowed subset to a specialist, and the specialist
calls a tool server that verifies the entire chain before granting access.

## What it shows

1. Creating an authority (root) chained token with multiple scopes
2. Delegating to a specialist with attenuated scope and reduced budget
3. Sending the chained token to a tool server over HTTP
4. The tool server verifying the full delegation chain and checking scope
5. A denied request when the specialist tries to use a scope that was not
   delegated to it

## The delegation chain

```
Human/System
    |
    |-- Create authority token
    |   scopes: [search, browse, email]
    |   budget: $5.00, max_depth: 3
    |
    v
Orchestrator
    |
    |-- Delegate to Specialist
    |   scopes: [search]  (attenuated)
    |   budget: $1.00, context: "research task"
    |
    v
Specialist
    |
    |-- Call Tool Server with chained token
    |   X-AIP-Token: <base64 biscuit>
    |
    v
Tool Server
    |-- Verify chain: root -> orchestrator -> specialist
    |-- Check scope: tool:search -> ALLOWED
    |-- Check scope: tool:email -> DENIED
```

The orchestrator holds broad authority (search, browse, email) but only
delegates the `search` scope to the specialist. When the specialist tries
to invoke `email` through the tool server, the request is denied because
the delegation block only permits `search`.

## Prerequisites

- Python 3.10+
- AIP SDK dependencies (from the `python/` directory):

```bash
cd python/
pip install -e .
```

- `biscuit-python` for chained token support:

```bash
pip install biscuit-python
```

If `biscuit-python` is not installed, both scripts print a clear error
message and exit.

## How to run

Open two terminal windows, both in the repository root.

**Terminal 1 -- start the tool server:**

```bash
python examples/multi-agent-delegation/tool_server.py
```

The server starts on port 8341 and prints its public key hex. It waits
for the orchestrator to provide the root public key via the first request.

**Terminal 2 -- run the orchestrator:**

```bash
python examples/multi-agent-delegation/orchestrator.py
```

The orchestrator generates a root keypair, creates the authority token,
delegates to a specialist, and makes two requests to the tool server:

1. A `search` request using the delegated token (should succeed)
2. An `email` request using the same delegated token (should be denied)

## Expected output

**Orchestrator (Terminal 2):**

```
============================================================
AIP Multi-Agent Delegation Example -- Orchestrator
============================================================

[step 1] Generating root Ed25519 keypair ...
  Root public key (hex): <32 bytes hex>

[step 2] Creating authority chained token ...
  Issuer:     orchestrator-001
  Scopes:     search, browse, email
  Budget:     500 cents ($5.00)
  Max depth:  3
  TTL:        3600 seconds
  Authority token created (depth=0).

[step 3] Delegating to specialist ...
  Delegator:  orchestrator-001
  Delegate:   specialist-search-01
  Scopes:     search  (attenuated from: search, browse, email)
  Budget:     100 cents ($1.00)
  Context:    research task
  Delegated token created (depth=1).

[step 4] Specialist calls tool server: scope=search (should succeed) ...
  POST http://127.0.0.1:8341/tools/search
  Response status: 200
  Response body:   { ... search results ... }

[step 5] Specialist calls tool server: scope=email (should be denied) ...
  POST http://127.0.0.1:8341/tools/search
  Response status: 403
  Response body:   { ... scope_insufficient or authorization failed ... }

============================================================
Done.
  Step 4 (search): Expected 200 -- PASS
  Step 5 (email):  Expected 403 -- PASS
============================================================
```

**Tool Server (Terminal 1):**

```
[tool-server] Listening on http://127.0.0.1:8341
[tool-server] Waiting for requests... (Ctrl+C to stop)

[tool-server] POST /tools/search -- verifying chained token for scope "search" ...
[tool-server] Authorization succeeded. Returning results.
[tool-server] POST /tools/search -- verifying chained token for scope "email" ...
[tool-server] Authorization failed: ...
```
