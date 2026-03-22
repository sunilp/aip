# AIP Provenance Bridge and Audit

**Version:** 0.1.0-draft
**Status:** Draft
**Date:** 2026-03-22

---

## 1. Introduction

This document defines AIP completion blocks, the trust model for completion data, integration with the Layered Disclosure Protocol (LDP), governance framework mapping, and the audit token concept.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 2. Completion Blocks

### 2.1 Overview

When work finishes, the executing agent appends a completion block to the token chain. Completion blocks bind the outcome of work back to the authorization chain that permitted it.

### 2.2 Completion Block Structure

A completion block contains 7 fields:

```
Block N (Completion) -- signed by executing agent
  status: "completed" | "failed" | "partial"
  result_hash: "sha256:e3b0c44298fc..."
  verification_status: "tool_verified"
  tokens_used: 1200
  cost_usd: 0.03
  duration_ms: 4500
  ldp_provenance_id: "ldp:provenance:uuid"  (optional)
```

### 2.3 Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `status` | string | REQUIRED | Outcome of the work. MUST be one of `"completed"`, `"failed"`, or `"partial"`. |
| `result_hash` | string | REQUIRED | SHA-256 hash of the result, formatted as `"sha256:<hex-digest>"`. Binds the token to a specific output. |
| `verification_status` | string | REQUIRED | How the result was verified. See Section 3 for trust model values. |
| `tokens_used` | integer | OPTIONAL | Number of LLM tokens consumed during execution. |
| `cost_usd` | number | OPTIONAL | Actual cost incurred in USD. For audit, not enforcement (see AIP Tokens budget semantics). |
| `duration_ms` | integer | OPTIONAL | Wall-clock execution time in milliseconds. |
| `ldp_provenance_id` | string | OPTIONAL | Back-link to an LDP provenance record. See Section 4 for LDP integration. |

### 2.4 When Completion Blocks Are Required

Completion blocks are OPTIONAL by default. They are REQUIRED only when:

1. The delegation policy includes `require_provenance: true`.
2. The token will be used as audit evidence.
3. LDP provenance bridging is active (see Section 4).

### 2.5 Requirements

1. Completion blocks MUST be signed by the executing agent (the agent that performed the work).
2. The `status` field MUST be one of the three defined values: `"completed"`, `"failed"`, or `"partial"`.
3. The `result_hash` MUST use SHA-256 and the format `"sha256:<hex-digest>"`.
4. The completion block MUST be appended as the final block in the token chain.
5. Only one completion block is permitted per token chain (excluding verification and attestation blocks defined in Section 3).

---

## 3. Trust Model

### 3.1 Overview

Completion blocks are signed by the executing agent -- the party whose work is being reported. This means completion blocks are **self-reported claims**, not independently verified proofs. Their trust properties:

- **Tamper-evident:** The block is cryptographically signed. It cannot be modified after creation without detection.
- **Attribution-bound:** The signature proves which agent made the claim. A fraudulent claim is attributable.
- **Not independently verified (by default):** The executing agent could misrepresent `result_hash` or `cost_usd`.

### 3.2 Trust Levels

AIP defines three trust escalation levels for completion blocks:

#### Level 1: Self-Reported (Default)

The agent reports its own results. No independent verification.

- `verification_status`: implementation-defined (e.g., `"self_reported"` or `"unverified"`)
- Sufficient for internal, trusted environments.
- No additional blocks required.

#### Level 2: Counter-Signed

The delegator (parent agent) independently verifies the result and appends a counter-signature block.

The counter-signature adds one block after the completion block:

```
Block N+1 (Verification) -- signed by delegator
  verified: true
  verifier: <delegator_aip_id>
```

- `verification_status` in the completion block: `"tool_verified"` or equivalent.
- The delegator has independently checked the result.

#### Level 3: Third-Party Attested

An external verifier (LDP peer verification, human reviewer, or audit service) signs an attestation block.

- The `verification_status` field maps to LDP's verification enum when LDP integration is active.
- `"peer_verified"`: verified by an LDP peer.
- `"human_verified"`: verified by a human reviewer.

### 3.3 Requirements

1. Consumers of completion blocks SHOULD check the `verification_status` field and weight their trust accordingly.
2. `"tool_verified"` or `"peer_verified"` completion blocks carry more weight than unverified self-reports.
3. Counter-signature blocks (Level 2) MUST be signed by the delegator identified in the preceding delegation block.
4. Third-party attestation blocks (Level 3) MUST include the attester's AIP identifier.

---

## 4. LDP Integration

### 4.1 Overview

When both AIP and the Layered Disclosure Protocol (LDP) are in use, they provide complementary guarantees:

- **AIP:** Authorization chain -- who was authorized, through which agents, with what scope.
- **LDP:** Provenance and quality evidence -- what was produced, how it was verified, what metadata accompanies it.

Neither protocol depends on the other. They are linked when both are present.

### 4.2 Bidirectional Linking

**AIP to LDP (forward link):**

The LDP provenance record includes an `aip_token_hash` field, binding "what was produced" to "who was authorized to produce it."

**LDP to AIP (back-link):**

The AIP completion block includes an `ldp_provenance_id` field, linking the authorization chain back to the full provenance record.

Together, the forward and back links create a bidirectional binding between authorization (AIP) and provenance (LDP).

### 4.3 Requirements

1. When LDP integration is active, the AIP completion block SHOULD include the `ldp_provenance_id` field.
2. When LDP integration is active, the LDP provenance record SHOULD include the `aip_token_hash` field.
3. The `aip_token_hash` in LDP records MUST be the SHA-256 hash of the serialized AIP token (before the completion block is appended).
4. The `ldp_provenance_id` MUST be a valid LDP provenance record identifier.
5. Implementations MUST NOT require LDP to be present for AIP to function. LDP integration is OPTIONAL.

---

## 5. Governance Framework Mapping

AIP directly addresses common governance requirements for AI agent systems:

| Governance Requirement | AIP Implementation |
|---|---|
| Each agent uses own service account and authentication | Each agent has its own AIP identity and keypair. |
| Cross-agent action validation | Receiving agent verifies the full AIP token chain. |
| No privilege escalation | Scope attenuation enforced cryptographically at each delegation hop. |
| Principle of least privilege | Policy profiles constrain capabilities per delegation. |
| Audit trail with correlation IDs | Token chain traces the full path from human to outcome. |
| Incident forensics attribution | Completion blocks and provenance enable full reconstruction. |

---

## 6. Audit Token

### 6.1 Concept

A completed chained token (with a completion block appended) is a self-contained audit artifact. It answers five key questions without requiring any external database:

```
Who authorized?     -> Block 0 (root identity + initial scope)
Through whom?       -> Blocks 1..N-1 (delegation chain with context)
What constraints?   -> Datalog policies in each block
What happened?      -> Completion block (result hash, cost, duration)
Was it verified?    -> verification_status + ldp_provenance_id link
```

### 6.2 Properties

1. **Self-contained:** No central audit database is needed. The token itself is the evidence.
2. **Tamper-evident:** Every block is cryptographically signed. Modification of any block invalidates the chain.
3. **Non-repudiable:** Each signer's identity is bound to their block. Signers cannot deny their participation.
4. **Verifiable offline:** Given the public keys (from identity documents), the entire chain can be verified without network access to any central authority.

### 6.3 Requirements

1. Audit tokens MUST be complete chained mode tokens with at least Block 0 (authority) and one completion block.
2. All blocks in an audit token MUST pass signature verification.
3. All delegation blocks MUST have non-empty `context` fields.
4. Implementations SHOULD provide tooling to render audit tokens in a human-readable format for forensic review.
5. Audit tokens SHOULD be retained according to the organization's data retention policies.
