# Delegation Chains

This guide covers chained (Biscuit-based) delegation in AIP: how tokens flow through multi-agent systems, how scope narrows at each hop, and how to use policy profiles.

## What are delegation chains?

A delegation chain is a sequence of cryptographic handoffs:

```
orchestrator -> specialist -> tool
```

Each hop appends a new block to the token. That block can only narrow scope, never widen it. The orchestrator starts with broad permissions, delegates a subset to a specialist, and the specialist delegates an even smaller subset when calling a tool. Every block is cryptographically bound to the chain, so tampering or scope escalation is impossible.

Key properties:
- **Attenuation only.** Each delegate receives at most the permissions of its delegator.
- **Depth limits.** The authority token sets `max_depth`, capping how many hops are allowed.
- **Budget tracking.** Budget is expressed in integer cents (Biscuit has no native float support). Each hop can set a lower budget ceiling.
- **Context required.** Every delegation must include a non-empty context string explaining why the delegation exists.

## Creating a delegation chain in Python

### 1. Create the authority token

The orchestrator creates the root token with its full set of permissions:

```python
from aip_core.crypto import KeyPair
from aip_token.chained import ChainedToken

root_kp = KeyPair.generate()
token = ChainedToken.create_authority(
    issuer="aip:web:myorg.com/orchestrator",
    scopes=["tool:search", "tool:email"],
    budget_cents=500,
    max_depth=3,
    ttl_seconds=3600,
    keypair=root_kp,
)
```

This produces a Biscuit token with an authority block containing:
- The issuer identity
- Two scope rights (`tool:search` and `tool:email`)
- A 500-cent budget ceiling
- A maximum delegation depth of 3
- A 1-hour expiry check

### 2. Delegate to a specialist

The orchestrator delegates a narrower set of permissions to a specialist:

```python
delegated = token.delegate(
    delegator="aip:web:myorg.com/orchestrator",
    delegate="aip:web:myorg.com/specialist",
    scopes=["tool:search"],  # narrowed from [search, email]
    budget_cents=100,         # narrowed from 500
    context="research task for user query",
)
```

The delegated token now has two blocks: the original authority block plus a new block that restricts scope to `tool:search` only and caps budget at 100 cents.

### 3. Authorize before calling a tool

Before the specialist actually calls the tool, it authorizes the token against the requested action:

```python
delegated.authorize("tool:search", root_kp.public_key_bytes())
```

`authorize()` re-verifies the entire chain from serialized form, injects the current time and requested tool as facts, and runs the Biscuit authorizer. It raises on failure.

## Scope attenuation

Each delegation hop can only narrow scope. This is enforced cryptographically by Biscuit's block model:

```
Authority block:  right("tool:search"), right("tool:email"), budget(500)
Block 1:          check if right("tool:search"); check if budget($b), $b <= 100
Block 2:          check if right("tool:search"); check if budget($b), $b <= 50
```

If block 2 tried to check for `right("tool:email")`, the authorization would fail because block 1 already restricted to `tool:search` only. The chain cannot escalate.

## Policy profiles

The `SimplePolicy` class generates Datalog checks automatically, so you do not need to write Biscuit Datalog by hand:

```python
from aip_token.policy import SimplePolicy

policy = SimplePolicy(
    tools=["tool:search", "tool:email"],
    budget_cents=500,
    max_depth=3,
    ttl_seconds=3600,
)
print(policy.to_datalog())
```

This outputs Datalog checks like:

```
check if tool($tool), ["tool:search", "tool:email"].contains($tool);
check if budget($b), $b <= 500;
check if depth($d), $d <= 3;
check if time($t), $t <= 2026-03-22T12:00:00Z;
```

AIP defines three policy profile tiers:
- **Simple** -- generates Datalog automatically from a short parameter list (shown above)
- **Standard** -- allows custom Datalog checks alongside generated ones
- **Advanced** -- full hand-written Datalog for complex authorization logic

For most use cases, Simple is sufficient.

## Budget as integer cents

Biscuit's Datalog engine does not support floating-point numbers. AIP represents budget as integer cents throughout the chained token API:

```python
budget_cents=500   # $5.00
budget_cents=100   # $1.00
budget_cents=1     # $0.01
```

This avoids rounding errors and keeps authorization checks exact.

## Common patterns

### Orchestrator to specialist to tool

The most common pattern. An orchestrator receives a user request, delegates to a specialist agent with narrowed scope, and the specialist calls a tool:

```
human request
  -> orchestrator (full scope, $5 budget)
    -> specialist (tool:search only, $1 budget)
      -> tool server (verifies chain, executes search)
```

### Human to agent to sub-agent

A human-in-the-loop pattern where the human's identity anchors the chain:

```
human (root authority)
  -> primary agent (tool:read, tool:write, $10 budget)
    -> sub-agent (tool:read only, $2 budget)
```

The human creates the authority token (or has a system create it on their behalf), and each agent in the chain receives an attenuated copy.

### Serialization for transport

Tokens serialize to URL-safe base64 for transport over HTTP, MCP headers, or A2A messages:

```python
# Serialize
b64 = delegated.to_base64()

# Deserialize and verify
restored = ChainedToken.from_base64(b64, root_kp.public_key_bytes())
print(f"Issuer: {restored.issuer()}")
print(f"Depth: {restored.current_depth()}")
```

## Next steps

- [Quickstart](quickstart.md) -- compact and chained token basics
- [Specification](../SPEC.md) -- full protocol details
- [Single-agent MCP example](../examples/single-agent-mcp/) -- working MCP integration
