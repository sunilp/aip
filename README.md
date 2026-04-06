# Agent Identity Protocol (AIP)

[![PyPI - agent-identity-protocol](https://img.shields.io/pypi/v/agent-identity-protocol?label=agent-identity-protocol)](https://pypi.org/project/agent-identity-protocol/)
[![PyPI - aip-agents](https://img.shields.io/pypi/v/aip-agents?label=aip-agents)](https://pypi.org/project/aip-agents/)
[![Downloads](https://img.shields.io/pypi/dm/agent-identity-protocol)](https://pypi.org/project/agent-identity-protocol/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

**Add identity and auth to AI agents in 5 lines of code.**

## The problem

MCP has no authentication. A2A has self-declared identities with no attestation. Your agents call tools anonymously, delegate to other agents without verification, and leave no audit trail. When something goes wrong, you have no way to trace who authorized what.

## The fix

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

## Paper

> Sunil Prakash. **AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A.** arXiv preprint arXiv:2603.24775, 2026.
> [https://arxiv.org/abs/2603.24775](https://arxiv.org/abs/2603.24775)

IETF Internet-Draft: [draft-prakash-aip-00](https://datatracker.ietf.org/doc/draft-prakash-aip/)

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
