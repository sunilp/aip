# AIP Competitive Analysis & Design Rationale

**Date:** 2026-03-22
**Status:** Pre-design analysis
**Author:** Sunil Prakash

## Context

Agent Identity Protocol (AIP) addresses the unsolved agent identity gap in the MCP/A2A stack. This document captures the competitive landscape analysis, alternative approaches considered, and rationale for design decisions.

## The Problem

No identity flows across MCP and A2A protocol boundaries:
- MCP has no authentication layer (Knostic scanned ~2,000 MCP servers, all lacked auth)
- A2A has self-declared identities with no attestation binding
- When Agent A delegates to Agent B, no identity verification happens
- IETF's most ambitious draft (AIMS, March 2026) has "TODO Security" in its authorization section

## Existing Solutions & Why They're Insufficient

### W3C DID (Decentralized Identifiers)

**Status:** DID v1.1 hit Candidate Recommendation (March 5, 2026). Adoption disappointing.

**Failures:**
- 34% of early adopters had users locked out in 6 months
- 62% of non-technical users find wallet management confusing
- Block killed "Web5" DID initiative in late 2024
- Only 37% of jurisdictions have clear rules for blockchain identity
- Core problem: key management too hard for humans, trust bootstrapping is circular, chicken-and-egg between issuers/verifiers

**Key insight for AIP:** Agents are software -- key management is trivial for them. DID's UX problems don't apply. But blockchain dependency and resolution complexity do.

### OAuth 2.1

**Status:** MCP spec now includes OAuth 2.1 with PKCE. A2A supports RFC 8693 token exchange.

**Limitations:**
- Solves client-to-server auth, not agent-to-agent across trust boundaries
- Tokens are opaque to intermediaries -- delegation context lost when A->B->tool
- Requires centralized authorization server per trust domain
- No scope attenuation by token holder (only auth server can narrow scopes)

**AIP relationship:** AIP tokens CAN wrap OAuth tokens. Block 0 can contain an OAuth access token as root credential. AIP adds what OAuth lacks: holder-attenuable delegation chains, cross-domain verification, provenance binding. AIP is the delegation layer ON TOP of OAuth.

### IETF Drafts (AIMS, WIMSE, Agentic JWT, SCIM)

| Draft | What it does | Gap |
|---|---|---|
| draft-klrc-aiagent-auth (AIMS) | Composes WIMSE + SPIFFE + OAuth into conceptual model | No token format, no delegation semantics, authorization = "TODO Security" |
| draft-ni-wimse-ai-agent-identity | Dual-Identity Credential (agent + owner) | Two-party only, no multi-hop delegation (A->B->C) |
| draft-goswami-agentic-jwt | JWT with agent claims | JWTs immutable after signing, can't attenuate per hop |
| SCIM for agents | Provisioning lifecycle for agents | Not runtime auth, complementary |

**AIP relationship:** AIP can be the concrete token format these specs reference. AIMS defines conceptual model; AIP provides implementation primitive. WIMSE's dual-identity can map to Block 0's authority block. Agentic JWT claims map to Biscuit authority facts.

### Macaroons / Google DeepMind DCTs

**Status:** DeepMind's "Intelligent AI Delegation" paper (Feb 2026, arXiv:2602.11865) proposes Delegation Capability Tokens based on macaroons.

**Strengths:**
- Holder can reduce own authority and pass downstream (attenuation without coordination)
- Simple, fast (HMAC)
- DeepMind validation lends credibility

**Limitations:**
- Shared-secret verification (HMAC) -- verifier needs root secret, single point of compromise
- Third-party caveats fragile in practice
- Simple caveats too simple for complex policies
- DCTs are conceptual -- no complete protocol shipped

**AIP relationship:** AIP acknowledges DeepMind's insight (attenuation is the right primitive) but uses stronger crypto (public-key > shared-secret) and more expressive policy (Datalog > key-value caveats).

### Biscuit Tokens

**Status:** Eclipse Foundation project. Rust-native. Ed25519 + Datalog.

**Strengths:**
- Public-key verification (no shared secrets)
- Datalog policy language (expressive)
- Append-only block chain (natural delegation)
- Rust implementation (fits JamJet stack)

**Limitations:**
- Token format, not identity protocol -- no discovery, resolution, or protocol bindings
- Datalog verifier complexity is an attack surface
- No provenance binding concept
- No MCP/A2A integration

**AIP relationship:** AIP uses Biscuit as the cryptographic primitive. Biscuit is to AIP what Ed25519 is to SSH -- the crypto layer, not the protocol.

### UCAN (User Controlled Authorization Networks)

**Status:** Active W3C-adjacent working group. Used by Storacha/web3.storage.

**Strengths:**
- Decentralized delegation philosophy
- DID-based identity
- Capability URIs

**Limitations:**
- DID dependency inherits all DID complexity
- Nested JWTs create token bloat in deep chains
- Web3/JS-centric ecosystem
- No policy language (flat capability URIs)

**AIP relationship:** AIP takes UCAN's philosophy (user-controlled delegation) but better primitives (Biscuit blocks over nested JWTs, Datalog over capability URIs, DNS over DIDs).

### SPIFFE/SPIRE

**Status:** Production-proven at Uber, Stripe, Netflix. HashiCorp pushing for agent use.

**Strengths:**
- Battle-tested infrastructure
- mTLS built-in
- IETF backing

**Limitations:**
- Requires running SPIRE infrastructure (heavy)
- X.509 cert model complex (rotation, CRL, OCSP)
- Not designed for ephemeral/dynamic agent creation
- Doesn't solve MCP/A2A binding

**AIP relationship:** Enterprises already running SPIFFE can use SPIFFE SVIDs as the root credential in AIP Block 0.

### Other Emerging Projects

| Project | Focus | Gap |
|---|---|---|
| Mastercard Verifiable Intent | Crypto audit trail for agent commerce | Commerce-only |
| AstraCipher | DID + VC SDK for agents (post-quantum) | New, no adoption |
| OpenAgents AgentID | W3C DID for agents | Platform-coupled |

## Token Format Comparison

| Concern | OAuth 2.1 | AIMS/WIMSE | Biscuit raw | Macaroons | UCAN | **AIP** |
|---|---|---|---|---|---|---|
| Multi-hop delegation | No | Partial | No protocol | Yes (HMAC) | Yes (nested JWT) | **Yes (append blocks)** |
| Public-key verification | Via OIDC | Via SPIFFE | Yes | No (shared secret) | Yes (DID) | **Yes (Ed25519)** |
| Expressive policies | Scopes only | Undefined | Datalog | Key-value | Capability URI | **Datalog with profiles** |
| MCP/A2A bindings | MCP only | Undefined | None | None | None | **First-class** |
| Provenance binding | No | No | No | No | No | **Yes (completion blocks)** |
| No blockchain required | Yes | Yes | Yes | Yes | No (needs DID) | **Yes** |
| Agent lifecycle aware | No | Partial | No | No | No | **Yes (ephemeral grants)** |

## Novel Contribution: Invocation-Bound Capability Tokens (IBCTs)

AIP's core innovation fuses identity, authorization, and provenance into a single token that evolves through the delegation chain:

- **Block 0 (Authority):** Root identity + initial capabilities, signed by human/system
- **Block N (Delegation):** Each agent attenuates scope AND records delegation context
- **Block N+1 (Completion):** Final block binds result provenance back to token

Single token answers: "Who authorized this? Through which agents? With what scope at each hop? And what was the outcome?"

## Policy Profile System (Mitigating Datalog Complexity)

- **Profile: Simple** -- pre-defined templates for common patterns (tool allowlist, budget, time limit, depth). Users fill values, not Datalog. Covers 90% of cases.
- **Profile: Standard** -- curated Datalog subset (no recursion, bounded evaluation). Safe for production.
- **Profile: Advanced** -- full Datalog for complex enterprise policies. Opt-in.

## Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Trust anchor | DNS-based primary, self-certifying fallback | Avoids blockchain. DNS works today. Self-certifying for ephemeral agents. |
| Cryptographic primitive | Biscuit (Ed25519 + Datalog) | Public-key verification, expressive policies, Rust-native, append-only |
| Scope | Identity + Authentication + Inline Policy (v1), External Policy Engines (v2) | Identity without auth is useless (DID's mistake). Inline policy profiles (simple/standard/advanced Datalog) are in v1. External policy decision points and federated policy registries deferred to v2. |
| Repo structure | Standalone `aip` repo | Protocol-level concern, not product feature. LDP/JamJet are first integrators. |
| LDP relationship | Complementary, linked via `aip_id` | AIP = "who is this, can I trust it" (crypto). LDP = "what can it do, how well" (capability metadata). |
| Target audience | Protocol designers > Platform builders > Enterprise deployers | Spec-first for standardization, with reference implementation |

## Integration Points

### Existing Stack

- **JamJet:** AIP tokens flow through MCP adapter and A2A adapter. OAuth token exchange (already implemented) can produce AIP Block 0.
- **LDP:** Identity cards add `aip_id` field. Provenance records linked via completion blocks.
- **Governance Framework:** AIP delegation policies implement the "cross-agent action validation" the framework mandates but doesn't define.

### Protocol Bindings

- **MCP:** `X-AIP-Token` header on tool calls
- **A2A:** `aip_identity` field in agent card + `aip_token` in task submission metadata
- **HTTP:** `Authorization: AIP <token>` header

## References

- [W3C DID v1.1 Candidate Recommendation](https://www.w3.org/news/2026/w3c-invites-implementations-of-decentralized-identifiers-dids-v1-1/)
- [Google DeepMind "Intelligent AI Delegation" (arXiv:2602.11865)](https://arxiv.org/html/2602.11865v1)
- [IETF AIMS draft-klrc-aiagent-auth-00](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/)
- [IETF WIMSE AI Agent Identity](https://datatracker.ietf.org/doc/draft-ni-wimse-ai-agent-identity/)
- [IETF Agentic JWT](https://datatracker.ietf.org/doc/draft-goswami-agentic-jwt/)
- [Biscuit Authorization](https://www.biscuitsec.org/)
- [Biscuit Specification](https://github.com/biscuit-auth/biscuit/blob/master/SPECIFICATIONS.md)
- [UCAN Specification](https://ucan.xyz/specification/)
- [Macaroons (Google Research)](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/)
- [MCP OAuth 2.1 Authorization](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)
- [SPIFFE for Agent Identity](https://www.solo.io/blog/agent-identity-and-access-management---can-spiffe-work)
- [Zero-Trust Identity for Agentic AI (arXiv)](https://arxiv.org/html/2505.19301v1)
- [Okta: Agent Delegation Chain Security](https://www.okta.com/blog/ai/agent-security-delegation-chain/)
- [AI Agent Identity Crisis (Strata)](https://www.strata.io/blog/agentic-identity/the-ai-agent-identity-crisis-new-research-reveals-a-governance-gap/)
- [Knostic MCP Server Security Scan](https://ragaboutit.com/the-ai-agent-identity-crisis-why-mcps-security-gap-threatens-your-enterprise-rag-system/)
