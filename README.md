# Agent Identity Protocol (AIP)

[![PyPI - agent-identity-protocol](https://img.shields.io/pypi/v/agent-identity-protocol?label=agent-identity-protocol)](https://pypi.org/project/agent-identity-protocol/)
[![PyPI - aip-agents](https://img.shields.io/pypi/v/aip-agents?label=aip-agents)](https://pypi.org/project/aip-agents/)
[![Downloads](https://img.shields.io/pypi/dm/agent-identity-protocol)](https://pypi.org/project/agent-identity-protocol/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

**Verifiable identity and scoped delegation for AI agents across MCP and A2A.**

[IETF Internet-Draft](https://datatracker.ietf.org/doc/draft-prakash-aip/) | [arXiv Paper](https://arxiv.org/abs/2603.24775) | [Project Hub](https://sunilprakash.com/aip/) | [Quickstart](https://sunilprakash.com/aip/quickstart/)

## The problem

MCP has no authentication. A2A has self-declared identities with no attestation. Your agents call tools anonymously, delegate to other agents without verification, and leave no audit trail. When something goes wrong, you have no way to trace who authorized what.

```
  Agent A            Agent B            MCP Server
  ───────            ───────            ──────────
     │                  │                   │
     │  AIP Token       │                   │
     │  (signed,        │                   │
     │   scoped)        │                   │
     ├─────────────────▶│                   │
     │                  │  Delegated Token  │
     │                  │  (narrowed scope, │
     │                  │   chained sig)    │
     │                  ├──────────────────▶│
     │                  │                   │ Verify chain
     │                  │                   │ Check scope
     │                  │                   │ Audit trail ✓
     │                  │       200 OK      │
     │                  │◀──────────────────┤
```

## Why not OAuth / UCAN / Macaroons?

| Approach | Limitation for agents |
|----------|----------------------|
| **OAuth 2.1** | Client-to-server only. Tokens are opaque to intermediaries, so delegation context is lost in multi-hop chains. Requires centralized auth server per domain. |
| **UCAN** | DID dependency inherits key management complexity. Nested JWTs create token bloat in deep chains. No policy language beyond capability URIs. |
| **Macaroons** | Shared-secret verification (HMAC) means the verifier holds the root secret. Single point of compromise. Caveats too simple for complex policies. |
| **SPIFFE/SPIRE** | Heavy infrastructure (SPIRE server). X.509 rotation complexity. Not designed for ephemeral agent creation. |
| **IETF AIMS/WIMSE** | AIMS has no token format or delegation semantics. WIMSE is two-party only (no multi-hop A to B to C). |

AIP uses Ed25519 + Biscuit with Datalog policies. Public-key verification (no shared secrets), holder-attenuable scope (each hop can only narrow, never widen), and DNS-based identity (no blockchain). [Full comparison](docs/competitive-analysis.md)

## Get started

```bash
pip install aip-agents[crewai]
```

```python
from aip_agents.adapters.crewai import CrewAIPlugin

plugin = CrewAIPlugin(app_name="my-app")
plugin.setup(crew)  # every agent gets a cryptographic identity
headers = plugin.get_auth_headers("researcher")  # signed token for tool calls
```

That's it. Every agent now has an Ed25519 identity, scoped delegation tokens, and MCP-compatible auth headers.

### Google ADK

```bash
pip install aip-agents[adk]
```

```python
from aip_agents.adapters.adk import ADKPlugin

plugin = ADKPlugin(app_name="my-app")
plugin.setup(root_agent)  # walks the agent tree, assigns identities
headers = plugin.get_auth_headers("specialist")
```

### LangChain

```bash
pip install aip-agents[langchain]
```

```python
from aip_agents.adapters.langchain import LangChainPlugin

plugin = LangChainPlugin(app_name="my-app")
plugin.register(executor, name="researcher")
headers = plugin.get_auth_headers("researcher")
```

## What this gives you

- **Cryptographic identity** -- every agent gets an Ed25519 keypair and an AIP identifier
- **Scoped delegation** -- when agents delegate, each hop can only narrow scope, never widen
- **MCP auth headers** -- signed `X-AIP-Token` headers that any MCP server can verify
- **Audit trail** -- every token records who authorized what, through which agents, with what scope
- **Two token modes** -- compact (JWT) for single-hop, chained (Biscuit) for multi-agent delegation

## Performance

Benchmarked on compact and chained token operations (1000 iterations):

| Operation | Python | Rust |
|-----------|--------|------|
| Token create (compact) | 0.086 ms | 0.018 ms |
| Token verify (compact) | 0.189 ms | 0.049 ms |
| Delegation append (chained) | 0.042 ms | 0.073 ms |
| Verify 5-hop chain | 0.447 ms | 0.744 ms |
| Token size (compact) | 356 bytes | 356 bytes |
| Token growth per hop | +340 bytes | +388 bytes |

End-to-end overhead for a 2-hop delegation: AIP adds ~2.3 ms vs OAuth's ~20 ms (token exchange simulation). 100% rejection rate on unauthorized token operations across 100 attack scenarios. 129 tests passing across both languages.

Full benchmark code in `paper/benchmarks/`.

## Multi-agent delegation

When agents delegate to other agents, each hop cryptographically narrows scope:

```python
from aip_core.crypto import KeyPair
from aip_token.chained import ChainedToken

root_kp = KeyPair.generate()

# Orchestrator: broad authority
token = ChainedToken.create_authority(
    issuer="aip:web:myorg.com/orchestrator",
    scopes=["tool:search", "tool:email"],
    budget_cents=500,
    max_depth=3,
    ttl_seconds=3600,
    keypair=root_kp,
)

# Delegate to specialist: only search, lower budget
delegated = token.delegate(
    delegator="aip:web:myorg.com/orchestrator",
    delegate="aip:web:myorg.com/specialist",
    scopes=["tool:search"],
    budget_cents=100,
    context="research task for user query",
)

# Specialist can search, but not email
delegated.authorize("tool:search", root_kp.public_key_bytes())  # passes
delegated.authorize("tool:email", root_kp.public_key_bytes())   # raises
```

## MCP Auth Proxy

Protect any MCP server with one command:

```bash
pip install agent-identity-protocol
aip-proxy --upstream http://localhost:3000 --port 8080 --trust-key z6Mkf...
```

The proxy verifies every request's AIP token, runs a security self-audit (TTL, scope, budget, chain depth), and forwards to your MCP server. Rejects anything unauthorized. Zero changes to your server code.

[MCP proxy guide](https://sunilprakash.com/aip/guides/mcp-proxy/) | [Security model](https://sunilprakash.com/aip/security/)

## Installation

```bash
# Core library (if building directly on the protocol)
pip install agent-identity-protocol

# Framework adapters (recommended)
pip install aip-agents[crewai]    # CrewAI
pip install aip-agents[adk]       # Google ADK
pip install aip-agents[langchain] # LangChain
pip install aip-agents[all]       # all frameworks
```

PyPI: [agent-identity-protocol](https://pypi.org/project/agent-identity-protocol/) | [aip-agents](https://pypi.org/project/aip-agents/)

Rust reference implementation available in `rust/`.

## Documentation

- **[sunilprakash.com/aip/](https://sunilprakash.com/aip/)** -- project hub with guides and tutorials
- [Quickstart](https://sunilprakash.com/aip/quickstart/) -- 5 minutes to your first AIP token
- [Delegation guide](docs/guide-delegation.md) -- chained tokens, scope attenuation, policy profiles
- [Competitive analysis](docs/competitive-analysis.md) -- AIP vs OAuth, DID, UCAN, Macaroons, Biscuit, SPIFFE
- [Specification](SPEC.md) -- full protocol spec

## Examples

- [Single-agent MCP](examples/single-agent-mcp/) -- agent authenticates to MCP tool server
- [Multi-agent delegation](examples/multi-agent-delegation/) -- orchestrator delegates to specialist, calls tool server

## Paper & Standards

> Sunil Prakash. **AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A.** arXiv preprint arXiv:2603.24775, 2026.
> [https://arxiv.org/abs/2603.24775](https://arxiv.org/abs/2603.24775)

- **IETF Internet-Draft:** [draft-prakash-aip-00](https://datatracker.ietf.org/doc/draft-prakash-aip/) (expires 2026-09-28)
- **NIST:** Under evaluation for the NCCoE agent identity demonstration project

```bibtex
@article{prakash2026aip,
  title={AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A},
  author={Prakash, Sunil},
  journal={arXiv preprint arXiv:2603.24775},
  year={2026}
}
```

### Related papers

AIP is part of a multi-agent trust stack:

| Layer | Paper | arXiv |
|-------|-------|-------|
| **Identity** | AIP: Verifiable Delegation Across MCP and A2A | [2603.24775](https://arxiv.org/abs/2603.24775) |
| **Provenance** | The Provenance Paradox in Multi-Agent LLM Routing | [2603.18043](https://arxiv.org/abs/2603.18043) |
| **Protocol** | LDP: An Identity-Aware Protocol for Multi-Agent LLM Systems | [2603.08852](https://arxiv.org/abs/2603.08852) |
| **Reasoning** | DCI: Structured Collective Reasoning with Typed Epistemic Acts | [2603.11781](https://arxiv.org/abs/2603.11781) |

## Tests

```bash
cd python && pytest tests/ -v
```

## License

Apache 2.0
