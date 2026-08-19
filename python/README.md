# agent-identity-protocol

Verifiable cryptographic identity and delegation for AI agents, across MCP and A2A.

Python reference implementation of the [Agent Identity Protocol](https://github.com/sunilp/aip) (AIP), specified in [draft-prakash-aip-01](https://datatracker.ietf.org/doc/draft-prakash-aip/).

## Install

```bash
pip install agent-identity-protocol
```

Framework adapters for CrewAI, Google ADK, and LangChain live in the separate `aip-agents` package.

## What it does

Agents get an Ed25519 keypair and a verifiable identifier. Authority is delegated in chains where each hop can only narrow scope, budget, and expiry, never widen them. Any party can verify a chain offline from the token and the issuer's published key, with no callback to the originating organization.

Two token modes:

- **Compact** (JWT) for single-hop calls where no delegation is needed.
- **Chained** (Biscuit) for multi-hop delegation with per-hop attenuation.

## Quickstart

```python
from aip_core.crypto import KeyPair
from aip_token.chained import ChainedToken

root = KeyPair.generate()

authority = ChainedToken.create_authority(
    issuer="aip:web:example.com/agents/orchestrator",
    scopes=["tool:search", "tool:browse"],
    budget_cents=500,
    max_depth=3,
    ttl_seconds=3600,
    keypair=root,
)

# Narrow on the way down. Widening is refused.
delegated = authority.delegate(
    delegator="aip:web:example.com/agents/orchestrator",
    delegate="aip:web:example.com/agents/researcher",
    scopes=["tool:search"],
    budget_cents=100,
    context="research subtask for quarterly report",
)

delegated.authorize("tool:search", root.public_key_bytes())   # ok
delegated.authorize("tool:browse", root.public_key_bytes())   # raises
```

## Verification

`authorize()` runs the algorithm in [draft-prakash-aip-01 Section 4](https://datatracker.ietf.org/doc/draft-prakash-aip/): it re-verifies every block signature from the serialized form, walks the chain confirming each hop narrows its parent across scope, budget, expiry and principal, requires a non-empty delegation context, and then evaluates policy.

An AIP token is a bearer credential. Verification establishes what authority the chain conveys and that no hop exceeded its predecessor. It does not establish that the presenting party is the one the token was issued to; that requires binding the token to a key at the transport or message layer.

## Documentation

- Protocol specification: [github.com/sunilp/aip](https://github.com/sunilp/aip/blob/master/SPEC.md)
- MCP proxy, framework guides, security model: [sunilprakash.com/aip](https://sunilprakash.com/aip/)
- Paper: [arXiv:2603.24775](https://arxiv.org/abs/2603.24775) (preprint)

## License

Apache-2.0
