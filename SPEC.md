# AIP Specification Overview

This document provides an overview of the Agent Identity Protocol (AIP) specification and links to the individual spec documents that define each component of the protocol.

## Design Principles

1. **No blockchain required.** AIP uses standard DNS infrastructure and self-certifying identifiers. There is no distributed ledger, no consensus mechanism, and no on-chain state. Identity resolution relies on DNS TXT records and well-known URIs that any organization can deploy today.

2. **Agents manage their own keys.** Each agent generates and holds its own Ed25519 key pair. There is no central key server or certificate authority that must be trusted. Identity documents bind a public key to an agent identifier, and the agent proves possession of the corresponding private key when it creates tokens.

3. **Scope can only narrow, never widen.** Every delegation in a token chain must be a subset of the scope granted by the previous block. A delegated agent cannot grant itself or others more permissions than it was given. This property is enforced cryptographically and is verifiable by any party in the chain.

4. **Cross-protocol identity.** A single AIP identity works across MCP tool calls, A2A task messages, and plain HTTP requests. The same token format and verification logic apply regardless of the transport protocol. Protocol bindings define where tokens are carried, but the identity layer is uniform.

5. **Prefer short-lived tokens over revocation infrastructure.** Tokens carry an expiration time and are designed to be short-lived. This reduces the need for revocation lists, OCSP responders, or other infrastructure to track invalidated credentials. When a token expires, the agent simply requests a new one.

6. **Start simple, upgrade seamlessly.** AIP defines three policy profiles (Simple, Standard, Advanced) so that adopters can begin with minimal infrastructure and graduate to full delegation chains and provenance binding as their needs grow. The token formats are designed so that a Simple deployment can later adopt Chained tokens without changing its identity scheme.

## Spec Documents

### [spec/aip-core.md](spec/aip-core.md) -- Identity

Defines the AIP identity scheme, including agent identifiers, identity documents, and resolution mechanisms. Covers DNS-based identifiers that use TXT records and well-known URIs, as well as self-certifying identifiers derived from Ed25519 public keys. Specifies the structure of identity documents and how verifiers resolve an identifier to its corresponding public key.

### [spec/aip-tokens.md](spec/aip-tokens.md) -- Tokens

Defines the two token formats used in AIP. Compact tokens are JWTs signed with Ed25519, suitable for single-hop authentication where no delegation is needed. Chained tokens use the Biscuit format to support multi-hop delegation with cryptographic scope attenuation. Also defines the three policy profiles (Simple, Standard, Advanced) and the verification rules for each.

### [spec/aip-delegation.md](spec/aip-delegation.md) -- Delegation

Specifies the rules for delegation chains, including how an agent appends a new block to a chained token that narrows the granted scope. Covers ephemeral grants for short-lived, tightly scoped delegations and defines the full delegation lifecycle from initial grant through chain extension to expiration. Includes formal rules for scope attenuation validation.

### [spec/aip-bindings-mcp.md](spec/aip-bindings-mcp.md) -- MCP Binding

Defines how AIP tokens are carried in MCP (Model Context Protocol) interactions. Specifies the header and metadata fields used to attach identity tokens to MCP tool calls and responses. Covers both the Streamable HTTP transport and the stdio transport, with rules for token propagation across tool invocations.

### [spec/aip-bindings-a2a.md](spec/aip-bindings-a2a.md) -- A2A Binding

Defines how AIP tokens are carried in A2A (Agent-to-Agent) protocol messages. Specifies how identity tokens attach to A2A task requests and responses, including mapping AIP fields to the A2A authentication extension points. Covers token propagation rules for multi-turn A2A conversations and task delegation.

### [spec/aip-bindings-http.md](spec/aip-bindings-http.md) -- HTTP Binding

Defines the generic HTTP binding for AIP tokens, used when agents communicate over plain HTTP outside of MCP or A2A. Specifies the Authorization header format, query parameter fallback, and response header fields. This binding serves as the foundation that the MCP and A2A bindings extend.

### [spec/aip-provenance.md](spec/aip-provenance.md) -- Provenance

Defines completion blocks that allow an agent to cryptographically attest to the output it produced while acting under a delegated scope. Covers the bridge to the Linked Data Proofs (LDP) provenance framework, enabling AIP tokens to serve as provenance evidence in audit trails. Specifies the structure of audit tokens that bind an agent's identity and scope to a specific output hash.
