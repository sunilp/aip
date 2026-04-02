# Agent Identity Protocol (AIP)

[![PyPI - agent-identity-protocol](https://img.shields.io/pypi/v/agent-identity-protocol?label=agent-identity-protocol)](https://pypi.org/project/agent-identity-protocol/)
[![PyPI - aip-agents](https://img.shields.io/pypi/v/aip-agents?label=aip-agents)](https://pypi.org/project/aip-agents/)
[![Downloads](https://img.shields.io/pypi/dm/agent-identity-protocol)](https://pypi.org/project/agent-identity-protocol/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Verifiable, delegable identity for AI agents across MCP and A2A.

AIP gives every agent a cryptographic identity that flows across protocol boundaries. A single token answers: who authorized this, through which agents, with what scope at each hop, and what was the outcome. No blockchain, no wallet UX -- just Ed25519 keys and append-only token chains.

> **Tutorial**: [Add Cryptographic Identity to Your CrewAI Agents in 5 Minutes](https://sunilprakash.com/writing/agent-identity-crewai/)

## Why AIP

- MCP has no authentication layer. A2A has self-declared identities with no attestation.
- When Agent A delegates to Agent B, no identity verification happens.
- No existing protocol combines identity, delegation, and provenance in a single verifiable artifact.

AIP fills this gap.

## Quick Start (Python)

```bash
pip install agent-identity-protocol
```

```python
from aip_core.crypto import KeyPair
from aip_token.claims import AipClaims
from aip_token.compact import CompactToken
import time

# Generate identity
kp = KeyPair.generate()

# Create a compact token for MCP tool access
claims = AipClaims(
    iss="aip:key:ed25519:" + kp.public_key_multibase(),
    sub="aip:web:example.com/tools/search",
    scope=["tool:search"],
    budget_usd=1.0,
    max_depth=0,
    iat=int(time.time()),
    exp=int(time.time()) + 3600,
)
token = CompactToken.create(claims, kp)

# Send to MCP server
headers = {"X-AIP-Token": token}
```

## Multi-Agent Delegation

When agents delegate to other agents, each hop cryptographically narrows scope:

```python
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

# Specialist verifies before calling tool
delegated.authorize("tool:search", root_kp.public_key_bytes())  # passes
delegated.authorize("tool:email", root_kp.public_key_bytes())   # raises -- attenuated away
```

## Two Token Modes

**Compact** (JWT + EdDSA) -- single hop, drop-in for existing MCP servers. Standard JWT libraries can verify.

**Chained** (Biscuit) -- multi-hop delegation with append-only blocks. Each block can only narrow scope, never widen. Datalog policy evaluation at each hop.

Start with compact. Upgrade to chained when you need delegation. Same identity scheme, same protocol bindings.

## Features

- DNS-based (`aip:web:`) and self-certifying (`aip:key:`) identity schemes
- Ed25519 cryptography, no algorithm negotiation
- MCP, A2A, and HTTP protocol bindings
- MCP middleware for token verification
- Delegation chains with cryptographic scope attenuation
- Budget tracking in integer cents
- Policy profiles: Simple (templated), Standard (curated Datalog), Advanced (full Datalog)
- Identity document self-signatures (protects against domain compromise)

## Installation

### Python (primary SDK)

```bash
# Core library
pip install agent-identity-protocol

# Framework adapters (CrewAI, Google ADK, LangChain)
pip install aip-agents[crewai]    # CrewAI
pip install aip-agents[adk]       # Google ADK
pip install aip-agents[langchain] # LangChain
pip install aip-agents[all]       # all frameworks
```

PyPI: [agent-identity-protocol](https://pypi.org/project/agent-identity-protocol/) | [aip-agents](https://pypi.org/project/aip-agents/)

For development from source:

```bash
cd python && pip install -e ".[dev]"
```

### Rust (reference implementation)

```toml
[dependencies]
aip-core = { path = "rust/aip-core" }
aip-token = { path = "rust/aip-token" }
aip-mcp = { path = "rust/aip-mcp" }
```

## Tests

```bash
# Python
cd python && pytest tests/ -v

# Rust
cd rust && cargo test

# Cross-language interop
python -m pytest tests/conformance/ -v
```

## Documentation

- [Quickstart](docs/quickstart.md) -- 5 minutes to your first AIP token
- [Delegation guide](docs/guide-delegation.md) -- chained tokens, scope attenuation, policy profiles
- [Competitive analysis](docs/competitive-analysis.md) -- AIP vs OAuth, DID, UCAN, Macaroons, Biscuit, SPIFFE
- [Specification](SPEC.md) -- full protocol spec

## Examples

- [Single-agent MCP](examples/single-agent-mcp/) -- agent authenticates to MCP tool server
- [Multi-agent delegation](examples/multi-agent-delegation/) -- orchestrator delegates to specialist, calls tool server

## Paper

The protocol design, experiments, and adversarial evaluation are described in:

> Sunil Prakash. **AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A.** arXiv preprint arXiv:2603.24775, 2026.
> [https://arxiv.org/abs/2603.24775](https://arxiv.org/abs/2603.24775)

### Citing

```bibtex
@article{prakash2026aip,
  title={AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A},
  author={Prakash, Sunil},
  journal={arXiv preprint arXiv:2603.24775},
  year={2026}
}
```

### Related Papers

AIP is part of a multi-agent trust stack. Each paper addresses a different layer:

| Layer | Paper | arXiv |
|-------|-------|-------|
| **Identity** | AIP: Verifiable Delegation Across MCP and A2A | [2603.24775](https://arxiv.org/abs/2603.24775) |
| **Provenance** | The Provenance Paradox in Multi-Agent LLM Routing | [2603.18043](https://arxiv.org/abs/2603.18043) |
| **Protocol** | LDP: An Identity-Aware Protocol for Multi-Agent LLM Systems | [2603.08852](https://arxiv.org/abs/2603.08852) |
| **Reasoning** | DCI: Structured Collective Reasoning with Typed Epistemic Acts | [2603.11781](https://arxiv.org/abs/2603.11781) |

## License

Apache 2.0
