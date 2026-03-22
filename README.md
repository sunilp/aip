# Agent Identity Protocol (AIP)

AIP is a protocol for verifiable, delegable identity for AI agents that works across MCP and A2A. It combines identity, attenuated authorization, and provenance binding in a single token chain. Two token modes: compact (JWT, single-hop) and chained (Biscuit, multi-hop delegation). Ed25519 cryptography throughout.

## Status

Early development. The specification is being written alongside reference implementations in Python and Rust.

## Features

- Two token modes: Compact (JWT) and Chained (Biscuit)
- DNS-based and self-certifying identity schemes
- Ed25519 cryptography
- MCP, A2A, and HTTP protocol bindings
- Delegation chains with cryptographic scope attenuation
- Provenance binding via completion blocks
- Policy profiles (Simple, Standard, Advanced)

## Quick Example

```python
from aip_core.crypto import KeyPair
from aip_token.claims import AipClaims
from aip_token.compact import CompactToken
import time

# Generate an Ed25519 keypair
kp = KeyPair.generate()

# Create a compact token (JWT with EdDSA signature)
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

# Verify the token
verified = CompactToken.verify(token, kp.public_key_bytes())
print(f"Issuer: {verified.claims.iss}")
print(f"Has search scope: {verified.has_scope('tool:search')}")
```

## Installation

### Python

```bash
cd python
pip install -e ".[dev]"
```

### Rust

Add the workspace crates as path dependencies in your `Cargo.toml`:

```toml
[dependencies]
aip-core = { path = "rust/aip-core" }
aip-token = { path = "rust/aip-token" }
```

## Tests

```bash
# Rust
cd rust && cargo test

# Python
cd python && pytest tests/ -v
```

## Specification

See [SPEC.md](SPEC.md) for the specification overview and links to individual spec documents in the [spec/](spec/) directory.

## Documentation

- [Quickstart guide](docs/quickstart.md) -- get running in 5 minutes
- [Competitive analysis](docs/competitive-analysis.md) -- how AIP compares to OAuth, DID, UCAN, Macaroons, and other approaches

## Examples

- [Single-agent MCP](examples/single-agent-mcp/) -- an agent authenticating to an MCP tool server with AIP compact tokens

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.
