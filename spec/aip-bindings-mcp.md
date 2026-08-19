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

An MCP server extracts the token from the `X-AIP-Token` header, or fetches it from the URL in `X-AIP-Token-Ref`, and then verifies it according to [AIP Verification](aip-verification.md).

If neither header is present and the server has `require_aip: true`, it returns error `aip_token_missing`.

The verification steps are not restated here. The algorithm is binding-independent, and an MCP server that verifies tokens differently from an A2A agent is a source of exactly the divergence the algorithm exists to prevent.

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
