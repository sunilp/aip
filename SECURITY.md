# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in AIP, please report it privately.

**Email**: sunil@sunilprakash.com

**Do not** open a public GitHub issue for security vulnerabilities.

Please include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact

I will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Cryptographic Design Principles

AIP makes deliberate, conservative choices in its cryptographic design:

- **Ed25519 only.** No algorithm negotiation. Algorithm agility is a recurring source of downgrade attacks. AIP uses Ed25519 for all signatures (compact and chained tokens).
- **No shared secrets.** Compact tokens use public-key signatures (EdDSA). Chained tokens use Biscuit's append-only block structure with per-block Ed25519 signatures. Verifiers never hold signing keys.
- **Append-only delegation.** Chained tokens can only narrow scope, never widen it. Each delegation block is signed independently. Removing or reordering blocks invalidates the chain.
- **No custom cryptography.** AIP relies on established libraries: `cryptography` (Python), `ed25519-dalek` (Rust), `biscuit-auth` (Biscuit tokens), `PyJWT` (compact tokens).
- **Datalog policy evaluation.** Scope checks use Biscuit's Datalog engine, not custom parsing. Policy logic is declarative and auditable.

## Scope

This policy covers the `agent-identity-protocol` and `aip-agents` Python packages, the Rust reference implementation, and the protocol specification.

## Dependencies

AIP depends on third-party cryptographic libraries. If a vulnerability is found in a dependency (e.g., `cryptography`, `biscuit-python`), AIP will release a patch updating the minimum required version.
