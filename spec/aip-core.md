# AIP Core: Identity Scheme and Resolution

**Version:** 0.1.0-draft
**Status:** Draft
**Date:** 2026-03-22

---

## 1. Introduction

This document defines the AIP identity scheme, identity document format, self-signature mechanism, resolution algorithm, and version compatibility rules. All identifiers, documents, and resolution behavior described here are normative.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 2. Identifier Format

AIP defines two identifier schemes: DNS-based identifiers for long-lived agents and self-certifying identifiers for ephemeral agents.

### 2.1 ABNF Grammar

The identifier format is defined using ABNF ([RFC 5234](https://www.rfc-editor.org/rfc/rfc5234)):

```abnf
aip-identifier  = aip-web-id / aip-key-id

aip-web-id      = "aip:web:" domain "/" path
domain          = 1*( ALPHA / DIGIT / "-" / "." )
path            = segment *( "/" segment )
segment         = 1*( ALPHA / DIGIT / "-" / "_" )

aip-key-id      = "aip:key:" algorithm ":" multibase-key
algorithm       = "ed25519"          ; v1 supports Ed25519 only
multibase-key   = "z" 1*BASE58CHAR  ; multibase with base58btc prefix
BASE58CHAR      = %x31-39 / %x41-48 / %x4A-4E / %x50-5A
                / %x61-6B / %x6D-7A
                ; 1-9, A-H, J-N, P-Z, a-k, m-z (no 0, I, O, l)
```

### 2.2 DNS-Based Identifiers (`aip:web:`)

DNS-based identifiers are for long-lived agents with stable domain-backed identities.

**Format:**
```
aip:web:<domain>/<path>
```

**Example:**
```
aip:web:jamjet.dev/agents/research-analyst
```

**Requirements:**

1. The `domain` component MUST be a valid DNS hostname.
2. The `path` component MUST contain at least one segment.
3. Implementations MUST resolve `aip:web:` identifiers via HTTPS as defined in Section 5.

### 2.3 Self-Certifying Identifiers (`aip:key:`)

Self-certifying identifiers are for ephemeral agents. The identifier IS the public key. No resolution is needed; verification is immediate.

**Format:**
```
aip:key:ed25519:<multibase-encoded-public-key>
```

**Example:**
```
aip:key:ed25519:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP
```

**Requirements:**

1. The algorithm component MUST be `ed25519` in v1.
2. The multibase-key MUST use base58btc encoding (prefix `z`).
3. The decoded key MUST be exactly 32 bytes (Ed25519 public key length).
4. Implementations MUST NOT attempt DNS resolution for `aip:key:` identifiers.

---

## 3. Identity Document

An AIP identity document describes an agent's identity, public keys, delegation preferences, protocol support, and extensions.

### 3.1 JSON Schema

Identity documents MUST conform to the following structure:

```json
{
  "aip": "1.0",
  "id": "aip:web:jamjet.dev/agents/research-analyst",
  "public_keys": [
    {
      "id": "key-1",
      "type": "Ed25519",
      "public_key_multibase": "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
      "valid_from": "2026-03-01T00:00:00Z",
      "valid_until": "2026-06-01T00:00:00Z"
    }
  ],
  "name": "Research Analyst",
  "delegation": {
    "max_depth": 3,
    "allow_ephemeral_grants": true
  },
  "protocols": {
    "mcp": { "header": "X-AIP-Token" },
    "a2a": { "agent_card_field": "aip_identity" }
  },
  "revocation": {
    "endpoint": "https://jamjet.dev/.well-known/aip/revocations",
    "method": "crl"
  },
  "extensions": {
    "ldp": "aip:web:jamjet.dev/agents/research-analyst#ldp",
    "oauth": { "issuer": "https://auth.jamjet.dev", "client_id": "research-analyst" }
  },
  "document_signature": "<Ed25519 signature of canonical document by key-1>",
  "expires": "2026-06-22T00:00:00Z"
}
```

### 3.2 Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `aip` | string | REQUIRED | Protocol version as `major.minor`. MUST be `"1.0"` for this specification. |
| `id` | string | REQUIRED | The AIP identifier of the agent. MUST match the `aip-identifier` grammar (Section 2.1). |
| `public_keys` | array | REQUIRED | One or more public key objects. MUST contain at least one entry. |
| `public_keys[].id` | string | REQUIRED | A locally-unique key identifier (e.g., `"key-1"`). |
| `public_keys[].type` | string | REQUIRED | Key algorithm. MUST be `"Ed25519"` in v1. |
| `public_keys[].public_key_multibase` | string | REQUIRED | The public key in multibase base58btc encoding. |
| `public_keys[].valid_from` | string | REQUIRED | ISO 8601 UTC timestamp indicating when this key becomes valid. |
| `public_keys[].valid_until` | string | REQUIRED | ISO 8601 UTC timestamp indicating when this key expires. |
| `name` | string | OPTIONAL | Human-readable agent name. |
| `delegation` | object | OPTIONAL | Delegation preferences. |
| `delegation.max_depth` | integer | OPTIONAL | Maximum delegation chain depth. Default is 3. |
| `delegation.allow_ephemeral_grants` | boolean | OPTIONAL | Whether this agent permits ephemeral sub-agent grants. Default is `true`. |
| `protocols` | object | OPTIONAL | Protocol-specific configuration. |
| `protocols.mcp` | object | OPTIONAL | MCP binding configuration. |
| `protocols.mcp.header` | string | OPTIONAL | Header name for AIP tokens. Default is `"X-AIP-Token"`. |
| `protocols.mcp.require_aip` | boolean | OPTIONAL | If `true`, the server rejects anonymous calls. |
| `protocols.mcp.minimum_policy_profile` | string | OPTIONAL | Minimum policy profile required (`"simple"`, `"standard"`, `"advanced"`). |
| `protocols.a2a` | object | OPTIONAL | A2A binding configuration. |
| `protocols.a2a.agent_card_field` | string | OPTIONAL | Field name in agent card. Default is `"aip_identity"`. |
| `revocation` | object | OPTIONAL | Revocation configuration. |
| `revocation.endpoint` | string | OPTIONAL | URL for the revocation list. MUST be HTTPS. |
| `revocation.method` | string | OPTIONAL | Revocation method. MUST be `"crl"` in v1. CRL format is deferred to v2. |
| `extensions` | object | OPTIONAL | Extension fields for LDP, OAuth, or any future protocol. |
| `document_signature` | string | REQUIRED | Ed25519 signature over the canonical document (see Section 4). |
| `expires` | string | REQUIRED | ISO 8601 UTC timestamp. The document MUST NOT be trusted after this time. |

### 3.3 Self-Certifying Identity Documents

For `aip:key:` identifiers, the identity document is self-constructed by the agent rather than fetched via DNS. The document MUST contain:

- `aip`: `"1.0"`
- `id`: the full `aip:key:ed25519:<multibase-key>` identifier
- `public_keys`: a single entry derived from the identifier itself
- `document_signature`: signed by the embedded key
- `expires`: REQUIRED

All other fields are OPTIONAL.

---

## 4. Self-Signature Mechanism

### 4.1 Canonicalization

Identity documents MUST be canonicalized using [RFC 8785 JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785) before signing. JCS produces a deterministic byte representation by:

1. Sorting all object keys lexicographically by Unicode code point.
2. Using no whitespace between tokens.
3. Applying deterministic number serialization.

### 4.2 Signing Process

1. Construct the identity document with all fields populated EXCEPT `document_signature`.
2. Serialize the document using RFC 8785 JCS canonicalization.
3. Sign the canonical byte sequence using the Ed25519 private key corresponding to one of the listed `public_keys`.
4. Set `document_signature` to the base64url-encoded (no padding) Ed25519 signature.

### 4.3 Verification Process

1. Parse the identity document.
2. Remove the `document_signature` field from the parsed object.
3. Re-canonicalize the remaining fields using RFC 8785 JCS.
4. Verify the `document_signature` against the canonical bytes using each `public_keys` entry whose `valid_from` <= current time <= `valid_until`.
5. If any currently-valid key produces a successful verification, the document is authentic.

**Requirements:**

1. Identity documents MUST include a `document_signature` field.
2. Verifiers MUST check the document signature before trusting any fields in the document.
3. If the signature does not verify against any currently-valid key, the document MUST be rejected.

### 4.4 Security Properties

The self-signature provides content authentication independent of transport security. Even if the hosting domain is compromised (DNS hijack, CDN compromise), an attacker cannot forge a valid identity document without the private key. HTTPS authenticates the transport; the signature authenticates the content.

---

## 5. Resolution Algorithm

### 5.1 `aip:web:` Resolution

To resolve a DNS-based AIP identifier:

1. Parse the identifier to extract `<domain>` and `<path>`.
2. Construct the resolution URL: `https://<domain>/.well-known/aip/<path>.json`
3. Fetch the URL via HTTPS GET.
4. Parse the response as JSON.
5. Verify the `aip` version field (see Section 6).
6. Verify the `document_signature` (see Section 4.3).
7. Verify that `expires` is in the future.
8. Verify that at least one key in `public_keys` is currently valid (`valid_from` <= now <= `valid_until`).
9. Return the verified identity document.

**Example:**

Identifier: `aip:web:jamjet.dev/agents/research-analyst`

Resolves via:
```
GET https://jamjet.dev/.well-known/aip/agents/research-analyst.json
```

**Requirements:**

1. Resolution MUST use HTTPS. HTTP MUST NOT be accepted.
2. Implementations SHOULD cache resolved identity documents. Cache TTL SHOULD NOT exceed 5 minutes.
3. If resolution fails (network error, non-200 status, invalid JSON, signature failure), the identifier MUST be treated as unresolvable.

### 5.2 `aip:key:` Resolution

Self-certifying identifiers require no network resolution:

1. Parse the identifier to extract the algorithm and multibase-encoded public key.
2. Decode the public key from multibase.
3. Construct a minimal identity document with the extracted key.
4. The identity is immediately usable for signature verification.

**Requirements:**

1. Implementations MUST NOT perform any network request for `aip:key:` identifiers.
2. The decoded public key MUST be validated (correct length for the algorithm).

---

## 6. Version Compatibility

### 6.1 Version Field

The `aip` field in identity documents uses a `major.minor` format (e.g., `"1.0"`).

### 6.2 Rules

1. Implementations MUST parse the `aip` field as a semver `major.minor` string.
2. An implementation MUST reject documents with a higher major version than it supports.
3. An implementation MAY accept documents with a higher minor version than it implements, provided the major version matches.
4. Unknown fields in identity documents MUST be ignored (forward compatibility).
5. This allows the spec to add optional fields in minor versions without breaking existing implementations.

---

## 7. Design Decisions

1. **Ed25519 only for v1.** Fast, small signatures, widely supported. No algorithm negotiation complexity.
2. **Extensions field.** LDP, OAuth, or any future protocol can link here without polluting the core schema.
3. **Expires field.** Forces rotation. No permanent identities.
4. **Multiple keys with validity windows.** Enables zero-downtime key rotation.
5. **Document self-signature.** Protects against domain compromise. HTTPS authenticates the transport; the signature authenticates the content.
