# Agent Identity Protocol (AIP)

AIP is a protocol for verifiable, delegable identity for AI agents that works across MCP and A2A. It combines identity, attenuated authorization, and provenance binding in a single token chain. Two token modes: compact (JWT, single-hop) and chained (Biscuit, multi-hop delegation). Ed25519 cryptography throughout.

## Status

Early development. The specification is being written and reference implementations have not yet been started.

## Features

- Two token modes: Compact (JWT) and Chained (Biscuit)
- DNS-based and self-certifying identity schemes
- Ed25519 cryptography
- MCP, A2A, and HTTP protocol bindings
- Delegation chains with cryptographic scope attenuation
- Provenance binding via completion blocks
- Policy profiles (Simple, Standard, Advanced)

## Specification

See [SPEC.md](SPEC.md) for the specification overview and links to individual spec documents in the [spec/](spec/) directory.

## Documentation

Additional documentation is available in the [docs/](docs/) directory.

## Installation

### Rust

Coming soon.

### Python

Coming soon.

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.
