# AIP Binding: Agent-to-Agent Protocol (A2A)

**Version:** 0.1.0-draft
**Status:** Draft
**Date:** 2026-03-22

---

## 1. Introduction

This document defines how AIP tokens are transported, verified, and enforced within the Agent-to-Agent (A2A) protocol. It covers the agent card extension, token metadata field, and the 6-step verification flow.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 2. Agent Card Extension: `aip_identity`

### 2.1 Overview

A2A agents that support AIP MUST declare their AIP identity in their agent card using the `aip_identity` extension field.

### 2.2 Format

```json
{
  "name": "Research Analyst",
  "skills": ["..."],
  "aip_identity": {
    "id": "aip:web:jamjet.dev/agents/research-analyst",
    "document_url": "https://jamjet.dev/.well-known/aip/agents/research-analyst.json"
  }
}
```

### 2.3 Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `aip_identity` | object | REQUIRED (if AIP-enabled) | AIP identity extension in the agent card. |
| `aip_identity.id` | string | REQUIRED | The agent's AIP identifier. MUST be a valid AIP identifier as defined in the AIP Core specification. |
| `aip_identity.document_url` | string | REQUIRED for `aip:web:` identifiers | HTTPS URL pointing to the agent's AIP identity document. |

### 2.4 Requirements

1. A2A agents that support AIP MUST include the `aip_identity` field in their agent card.
2. The `aip_identity.id` MUST be a valid AIP identifier.
3. For `aip:web:` identifiers, `aip_identity.document_url` MUST be provided and MUST use HTTPS.
4. For `aip:key:` identifiers, `aip_identity.document_url` is OPTIONAL (the public key is embedded in the identifier itself).

---

## 3. Token Transport: `aip_token` Metadata Field

### 3.1 Overview

AIP tokens are transmitted in A2A task submissions via the `metadata.aip_token` field.

### 3.2 Format

```json
{
  "jsonrpc": "2.0",
  "method": "tasks/send",
  "params": {
    "task_id": "uuid",
    "message": {
      "role": "user",
      "parts": [{"text": "Research X"}]
    },
    "metadata": {
      "aip_token": "<chained token with delegation block appended>"
    }
  }
}
```

### 3.3 Requirements

1. The AIP token MUST be placed in the `metadata.aip_token` field of the A2A task submission.
2. The token SHOULD be a chained mode token with a delegation block appended for the receiving agent.
3. Compact mode tokens MAY be used for single-hop A2A interactions.
4. The `metadata` object MUST be preserved across A2A task forwarding.

---

## 4. Verification Flow

When an A2A agent receives a task with an AIP token, it MUST perform the following 6-step verification flow:

### Step 1: Discover Agent Card

Agent A discovers Agent B's agent card, which includes the `aip_identity` extension.

If the agent card does not include `aip_identity` and the receiving agent requires AIP, the task MUST be rejected.

### Step 2: Resolve Identity Document

Agent A resolves Agent B's AIP identity document using the `document_url` from the agent card (for `aip:web:` identifiers) or constructs it from the key (for `aip:key:` identifiers).

Agent A MUST verify the identity document's `document_signature` and confirm the document has not expired.

### Step 3: Append Delegation Block

Agent A appends a delegation block to its token, attenuating scope for Agent B's task:

- The delegation block MUST contain a `delegate` fact with Agent B's AIP identifier.
- The delegation block MUST attenuate capabilities to only those needed for the delegated task.
- The delegation block MUST include a non-empty `context` field.
- The delegation block MUST be signed by Agent A's private key.

### Step 4: Send Task with Token

Agent A sends the task to Agent B with the token (including the new delegation block) in the `metadata.aip_token` field.

### Step 5: Verify Full Chain

Agent B verifies the full token chain:

1. **Root authority:** Verify Block 0 signature and resolve the root identity.
2. **Delegation chain:** For each delegation block (Block 1..N), verify:
   - The block's signature against the delegator's public key.
   - Scope attenuation (capabilities are a subset of the parent block).
   - The `context` field is non-empty.
   - The delegation depth does not exceed `max_depth`.
3. **Final delegation:** Verify the last delegation block delegates to Agent B's own AIP identifier.
4. **Expiry:** Verify no block in the chain has expired.
5. **Budget:** Verify the declared budget is non-negative.

If any verification step fails, the task MUST be rejected with an appropriate error.

### Step 6: Further Delegation (Optional)

Agent B MAY further delegate by appending another delegation block if `max_depth` allows. All scope attenuation rules apply. If the current chain depth equals `max_depth`, further delegation MUST NOT be permitted.

---

## 5. Error Handling

A2A agents SHOULD use the same error codes defined in the AIP MCP Binding specification (Section 4.2 of `aip-bindings-mcp.md`). Errors SHOULD be returned as A2A task error responses with the AIP error code included in the error metadata.

---

## 6. Mutual Authentication

A2A interactions support optional mutual authentication:

1. **Caller proves identity:** Agent A includes an AIP token in the task submission.
2. **Receiver proves identity:** Agent A resolves Agent B's identity document before sending and verifies TLS certificate matches the domain in Agent B's `aip:web:` identifier.

Mutual authentication for self-certifying identities (`aip:key:`) is deferred to v2 (requires a challenge-response sub-protocol).

**Requirements:**

1. Caller-only authentication is the default.
2. Mutual authentication is OPTIONAL and opt-in for high-security scenarios.
3. When mutual authentication is used with `aip:web:` identifiers, the caller MUST verify the TLS certificate matches the domain before sending the task.
