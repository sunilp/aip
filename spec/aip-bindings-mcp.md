# AIP Binding: Model Context Protocol (MCP)

**Version:** 0.1.0-draft
**Status:** Draft
**Date:** 2026-03-22

---

## 1. Introduction

This document defines how AIP tokens are transported, verified, and enforced within the Model Context Protocol (MCP). It covers the token header, server-side verification steps, error response format, error codes, and the `require_aip` server capability.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 2. Token Transport

### 2.1 X-AIP-Token Header

AIP tokens MUST be transmitted in the `X-AIP-Token` HTTP header on MCP tool call requests.

```
POST /mcp/v1/tools/search
X-AIP-Token: <compact or chained token>
Content-Type: application/json

{"query": "latest research on agent identity"}
```

### 2.2 Token-by-Reference

For large tokens (exceeding 4KB), the client MAY use the `X-AIP-Token-Ref` header instead:

```
X-AIP-Token-Ref: https://issuer.example/.well-known/aip/tokens/<token-id>
```

**Requirements:**

1. Clients MUST send the AIP token in the `X-AIP-Token` header, or a reference URL in the `X-AIP-Token-Ref` header.
2. If both `X-AIP-Token` and `X-AIP-Token-Ref` are present, the server MUST use `X-AIP-Token` and ignore `X-AIP-Token-Ref`.
3. The `X-AIP-Token-Ref` URL MUST use HTTPS.
4. Servers MUST fetch and fully verify the token from the reference URL before processing the request.

---

## 3. Server-Side Verification

When an MCP server receives a request with an AIP token, it MUST perform the following 5-step verification:

### Step 1: Extract Token

Extract the token from the `X-AIP-Token` header. If the header is absent, check for `X-AIP-Token-Ref` and fetch the full token from the referenced URL.

If neither header is present and the server has `require_aip: true`, return error `aip_token_missing`.

### Step 2: Verify Signatures

Verify the token's cryptographic signature(s) against the identity document resolved from the issuer identity (`iss` claim in compact mode, Block 0 `identity` fact in chained mode).

- For compact mode: verify the single JWT signature against the issuer's public key.
- For chained mode: verify the signature on every block against the respective signer's public key.

If signature verification fails, return error `aip_signature_invalid`.
If the issuer's identity document cannot be resolved, return error `aip_identity_unresolvable`.

### Step 3: Check Policy

Determine whether the token authorizes the requested tool call:

- Check that the requested tool is included in the token's `scope` (compact) or `right` facts (chained).
- If the token does not authorize the operation, return error `aip_scope_insufficient`.

### Step 4: Check Chain Constraints (Chained Mode)

For chained mode tokens, perform additional checks at each block in the chain:

1. **Delegation depth:** Verify the chain does not exceed `max_depth`. If exceeded, return error `aip_depth_exceeded`.
2. **Budget ceiling:** Verify the declared budget is non-negative. If the budget is insufficient for the declared operation cost, return error `aip_budget_exceeded`.
3. **Expiry:** Verify that no block in the chain has expired. If any block has expired, return error `aip_token_expired`.
4. **Scope attenuation:** Verify that each delegation block's capabilities are a subset of its parent block.
5. **Context:** Verify that each delegation block has a non-empty `context` field.
6. **Key revocation:** If the identity document includes a revocation endpoint, check whether any signing key has been revoked. If revoked, return error `aip_key_revoked`.

### Step 5: Inject Verified Identity

Inject the verified identity information into the request context, making it available to the tool implementation. The tool implementation MAY use the identity for authorization decisions, logging, or audit.

---

## 4. Error Responses

### 4.1 Error Format

When AIP verification fails, MCP servers MUST return a structured error response:

```json
{
  "error": {
    "code": "aip_<error_type>",
    "message": "Human-readable description"
  }
}
```

**Requirements:**

1. The `code` field MUST be one of the defined AIP error codes (Section 4.2).
2. The `message` field MUST contain a human-readable description of the error.
3. The `message` field SHOULD provide enough detail for debugging without leaking sensitive information.

### 4.2 Error Codes

The following 9 error codes are defined:

| Error Code | HTTP Status | Category | Description |
|---|---|---|---|
| `aip_token_missing` | 401 | Authentication | No token provided and server requires AIP. |
| `aip_token_malformed` | 401 | Authentication | Token cannot be parsed (invalid JWT, invalid Biscuit bytes). |
| `aip_signature_invalid` | 401 | Authentication | Signature verification failed against the resolved identity document. |
| `aip_identity_unresolvable` | 401 | Authentication | Cannot resolve the issuer's identity document (DNS failure, HTTP error, invalid document). |
| `aip_token_expired` | 401 | Authentication | The token or any block in the chain has expired. |
| `aip_scope_insufficient` | 403 | Authorization | Token does not authorize the requested operation. |
| `aip_budget_exceeded` | 403 | Authorization | Declared budget ceiling is insufficient for the operation. |
| `aip_depth_exceeded` | 403 | Authorization | Delegation chain exceeds the declared `max_depth`. |
| `aip_key_revoked` | 401 | Authentication | A signing key in the chain has been revoked. |

### 4.3 HTTP Status Mapping

1. HTTP 401 (Unauthorized) MUST be used for identity and authentication failures: `aip_token_missing`, `aip_token_malformed`, `aip_signature_invalid`, `aip_identity_unresolvable`, `aip_token_expired`, `aip_key_revoked`.
2. HTTP 403 (Forbidden) MUST be used for authorization and scope failures: `aip_scope_insufficient`, `aip_budget_exceeded`, `aip_depth_exceeded`.

---

## 5. Server Capability: `require_aip`

### 5.1 Overview

MCP servers MAY declare AIP support and requirements in their identity document.

### 5.2 Identity Document Extension

```json
{
  "aip": "1.0",
  "id": "aip:web:example.com/tools/search-api",
  "public_keys": [{"id": "key-1", "type": "Ed25519", "public_key_multibase": "z6Mk..."}],
  "protocols": {
    "mcp": {
      "require_aip": true,
      "minimum_policy_profile": "simple"
    }
  },
  "document_signature": "<signature>"
}
```

### 5.3 Fields

| Field | Type | Description |
|---|---|---|
| `require_aip` | boolean | If `true`, the server rejects anonymous calls (calls without a valid AIP token). Default is `false`. |
| `minimum_policy_profile` | string | Minimum policy profile required for chained mode tokens. One of `"simple"`, `"standard"`, `"advanced"`. OPTIONAL. |

### 5.4 Requirements

1. When `require_aip` is `true`, the server MUST return error `aip_token_missing` (HTTP 401) for any request that does not include a valid AIP token.
2. When `require_aip` is `false` or absent, the server MAY accept anonymous requests but SHOULD still verify AIP tokens when present.
3. When `minimum_policy_profile` is set, chained mode tokens MUST include policies at or above the specified profile level. Simple < Standard < Advanced.
