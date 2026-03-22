# AIP Binding: HTTP / Mutual Authentication

**Version:** 0.1.0-draft
**Status:** Draft
**Date:** 2026-03-22

---

## 1. Introduction

This document defines the generic HTTP binding for AIP tokens, including the `Authorization: AIP` header, mutual authentication, and token-by-reference via the `X-AIP-Token-Ref` header. This binding applies to any HTTP-based API that is not covered by the MCP or A2A bindings.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 2. Authorization Header

### 2.1 Format

AIP tokens MUST be transmitted using the standard HTTP `Authorization` header with the `AIP` scheme:

```
GET /api/data
Authorization: AIP <token>
```

The `<token>` value is the base64url-encoded compact (JWT) or chained (Biscuit) token.

### 2.2 Scheme Registration

The `AIP` authorization scheme is used to identify AIP tokens in the `Authorization` header.

### 2.3 Compatibility

APIs that do not understand the `AIP` scheme will ignore the `Authorization` header or return a standard HTTP 401 response. APIs that support AIP can verify caller identity and scope from the token.

### 2.4 Requirements

1. Clients MUST use the `Authorization: AIP <token>` format for generic HTTP API calls.
2. The `<token>` MUST be a valid AIP token (compact or chained mode).
3. Servers that support AIP MUST recognize the `AIP` scheme in the `Authorization` header.
4. Servers that do not support AIP SHOULD ignore the `AIP` scheme gracefully (standard HTTP behavior).
5. The `Authorization: AIP` header and the `X-AIP-Token` header (from the MCP binding) carry the same token format. The choice of header depends on the protocol context.

---

## 3. Token-by-Reference

### 3.1 X-AIP-Token-Ref Header

For tokens that exceed practical inline size limits (4KB recommended threshold), clients MAY use the `X-AIP-Token-Ref` header to provide a URL from which the server can fetch the full token:

```
GET /api/data
Authorization: AIP <token-reference-indicator>
X-AIP-Token-Ref: https://issuer.example/.well-known/aip/tokens/<token-id>
```

### 3.2 Requirements

1. The `X-AIP-Token-Ref` URL MUST use HTTPS.
2. The response at the reference URL MUST include the full, self-authenticating token (with its complete signature chain).
3. No additional trust beyond the token's own cryptographic signatures is required to verify a token fetched by reference.
4. If both `Authorization: AIP <token>` (with an inline token) and `X-AIP-Token-Ref` are present, the server MUST use the inline token and ignore the reference.
5. Servers MUST fetch and fully verify the referenced token before processing the request.
6. Servers SHOULD enforce a timeout on reference URL fetches (RECOMMENDED: 5 seconds).
7. Servers SHOULD reject reference URLs that do not match expected domain patterns to prevent SSRF attacks.

---

## 4. Mutual Authentication

### 4.1 Overview

All AIP HTTP bindings support optional mutual authentication, where both the caller and receiver prove their identity.

### 4.2 Caller Authentication (Default)

The caller proves identity by including an AIP token in the request. This is the default mode for all AIP-enabled HTTP interactions.

### 4.3 Receiver Authentication

The caller verifies the receiver's identity before sending the request.

**v1: DNS-based TLS only.**

For receivers with `aip:web:` identifiers:

1. The caller resolves the receiver's AIP identity document.
2. The caller verifies the TLS certificate of the receiver's domain matches the domain in the receiver's AIP identifier.
3. Standard HTTPS certificate validation provides receiver authentication.

This leverages existing PKI infrastructure. No additional challenge-response protocol is needed for DNS-based identities.

**v2 (deferred): Self-certifying mutual authentication.**

Mutual authentication for self-certifying identities (`aip:key:`) requires a challenge-response sub-protocol that is out of scope for v1. This will be defined in a future version of this specification.

### 4.4 Requirements

1. Caller-only authentication (sending an AIP token) is the default. No additional configuration is required.
2. Mutual authentication is OPTIONAL and opt-in for high-security scenarios.
3. In v1, receiver authentication MUST use DNS-based TLS verification only.
4. Implementations MUST NOT attempt mutual authentication with `aip:key:` identifiers in v1.
5. When mutual authentication is active, the caller MUST resolve the receiver's identity document and verify the TLS certificate matches the domain BEFORE sending the request.

---

## 5. Verification

HTTP servers that support AIP SHOULD follow the same 5-step verification process defined in the AIP MCP Binding specification (Section 3 of `aip-bindings-mcp.md`):

1. Extract token from `Authorization: AIP` header (or `X-AIP-Token-Ref`).
2. Verify signature(s) against the resolved identity document.
3. Check policy: does the token authorize this operation?
4. If chained mode: check delegation depth, budget ceiling, expiry at each block.
5. Inject verified identity into request context.

The same error codes and HTTP status mappings defined in the MCP binding (Section 4 of `aip-bindings-mcp.md`) apply to the generic HTTP binding.
