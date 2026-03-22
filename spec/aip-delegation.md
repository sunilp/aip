# AIP Delegation and Lifecycle

**Version:** 0.1.0-draft
**Status:** Draft
**Date:** 2026-03-22

---

## 1. Introduction

This document defines AIP delegation rules, scope attenuation, bounded depth, delegation context requirements, ephemeral agent grants, key rotation, and revocation mechanisms.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 2. Scope Attenuation Rules

### 2.1 Fundamental Rule

**Scope can only narrow, never widen.** Each delegation block MUST represent a subset of the capabilities granted by its parent block. This is enforced cryptographically: each block is signed by the delegator, and the verifier checks attenuation at every hop.

### 2.2 Attenuation Dimensions

Attenuation applies along all capability dimensions:

| Dimension | Attenuation Rule |
|---|---|
| Tools | Child block tool set MUST be a subset of parent block tool set. |
| Budget | Child block budget MUST be less than or equal to parent block budget. |
| Domains | Child block domain set MUST be a subset of parent block domain set. |
| Time | Child block expiration MUST be less than or equal to parent block expiration. |

### 2.3 Example

```
Block 0: tools:[*], budget:5.00, domains:[*]
  Block 1: tools:[search,browse], budget:0.50, domains:[research]
    Block 2: tools:[search], budget:0.10, domains:[research]
```

In this chain:
- Block 1 narrows tools from `[*]` to `[search, browse]`, budget from `5.00` to `0.50`, and domains from `[*]` to `[research]`.
- Block 2 further narrows tools to `[search]` only and budget to `0.10`.

### 2.4 Requirements

1. Each delegation block MUST contain capabilities that are a subset of its parent block's capabilities.
2. Attempting to widen scope (adding tools, increasing budget, expanding domains, extending expiration) MUST cause verification to fail.
3. Verifiers MUST check attenuation at every hop in the delegation chain.
4. A wildcard capability (`*`) in a parent block permits any specific capability in child blocks.
5. A specific capability in a parent block MUST NOT be widened to a wildcard in a child block.

---

## 3. Bounded Depth

### 3.1 Depth Limit

Block 0 declares the maximum delegation chain depth via the `max_depth` field.

### 3.2 Default Depth

The default `max_depth` is **3**. This means up to 3 delegation blocks may be appended after Block 0 (the authority block), for a total of 4 blocks before the optional completion block.

### 3.3 Compact Mode Depth

In compact mode, `max_depth: 0` means the token holder MUST NOT delegate further. This is a constraint on the holder, not a counter of hops taken.

### 3.4 Requirements

1. Block 0 MUST include a `max_depth` field.
2. If `max_depth` is absent, implementations MUST use the default value of 3.
3. Delegation beyond the declared `max_depth` MUST be rejected by verifiers.
4. Each delegation block increments the effective depth by 1. The depth of Block N (where Block 0 has depth 0) is N.
5. If the current depth equals `max_depth`, further delegation MUST NOT be permitted.

---

## 4. Delegation Context

### 4.1 Context Requirement

Each delegation block MUST include a non-empty `context` field describing why the delegation is happening. This is required for audit trail integrity.

### 4.2 Requirements

1. The `context` field MUST be a non-empty string.
2. Verifiers MUST reject tokens where any delegation block has a missing or empty `context` field.
3. The `context` field SHOULD be a human-readable description of the delegation purpose (e.g., `"research subtask for query X"`, `"spawned for search subtask"`).
4. The `context` field is not constrained to any particular format, but it MUST NOT be an empty string or whitespace-only string.

---

## 5. Ephemeral Agent Grants

### 5.1 Overview

When an agent spawns a short-lived sub-agent, it can issue an ephemeral grant using a self-certifying (`aip:key:`) identity for the sub-agent.

### 5.2 Grant Flow

1. Parent agent generates an Ed25519 keypair for the sub-agent.
2. Sub-agent's identity is `aip:key:ed25519:<pubkey>` (self-certifying, no DNS needed).
3. Parent appends a delegation block with scoped capabilities and short TTL.
4. Sub-agent uses the token for its work.
5. Token auto-expires.

### 5.3 Ephemeral Grant Block

```
Block N (Ephemeral Grant) -- signed by parent
  delegate: aip:key:ed25519:z6Mkf...
  attenuate: [tool:search, budget:0.10]
  expires: 2026-03-22T10:05:00Z  (5 minutes)
  ephemeral: true
  context: "spawned for search subtask"
```

### 5.4 Requirements

1. Ephemeral grants MUST delegate to an `aip:key:` identifier.
2. Ephemeral grants SHOULD have short TTLs (5 minutes or less is RECOMMENDED).
3. The `ephemeral` field MUST be set to `true` for ephemeral grants.
4. All scope attenuation rules (Section 2) apply equally to ephemeral grants.
5. The `context` field MUST be non-empty (Section 4).
6. The parent agent's identity document `delegation.allow_ephemeral_grants` field, if set to `false`, MUST prevent ephemeral grants from being issued.

---

## 6. Key Rotation

### 6.1 DNS-Based Identities (`aip:web:`)

DNS-based identity documents support zero-downtime key rotation through multiple keys with validity windows.

**Rotation procedure:**

1. Publish a new key in the identity document with a `valid_from` timestamp set to the desired activation time.
2. Wait for propagation (identity document caches to expire).
3. Both old and new keys are valid during the overlap window.
4. After the old key's `valid_until` passes, it is no longer accepted for new token verification.
5. Retire the old key by removing it from the identity document.

**Requirements:**

1. Identity documents MAY list multiple keys with overlapping or adjacent validity windows.
2. Tokens signed with any currently-valid key (where `valid_from` <= now <= `valid_until`) MUST be accepted.
3. The recommended rotation period is 90 days.
4. Implementations SHOULD cache identity documents with a maximum TTL of 5 minutes to ensure timely key rotation propagation.

### 6.2 Self-Certifying Identities (`aip:key:`)

For self-certifying identities, the key IS the identity. Rotation produces a new identity.

**Requirements:**

1. Key rotation for `aip:key:` identifiers MUST be treated as identity replacement, not key update.
2. This is acceptable because `aip:key:` identifiers are intended for ephemeral agents.
3. Existing tokens signed by the old key remain valid until their expiration.

---

## 7. Revocation

### 7.1 General Stance

AIP prefers short-lived tokens over revocation infrastructure. This reduces operational complexity and avoids the latency and availability problems inherent in revocation checking.

### 7.2 Compact Mode

Compact mode tokens SHOULD have a lifetime of less than 1 hour. With short-lived tokens, revocation is generally unnecessary: the token will expire before revocation infrastructure could propagate the revocation.

### 7.3 Chained Mode

Chained mode supports two revocation mechanisms:

**Key revocation:**
1. Remove the key from the identity document.
2. All tokens signed by that key become unverifiable on next identity document fetch.
3. Verifiers SHOULD cache identity documents with a maximum TTL of 5 minutes.

**Token-specific revocation (optional):**
1. The identity document MAY include a `revocation` object with an HTTPS endpoint and method.
2. The only supported method in v1 is `"crl"` (Certificate Revocation List).
3. The CRL format is deferred to v2. Implementations SHOULD NOT depend on CRL availability in v1.

### 7.4 Requirements

1. Compact mode tokens SHOULD have lifetimes of less than 1 hour.
2. Verifiers SHOULD cache identity documents with a maximum TTL of 5 minutes to enable timely key revocation.
3. Token-specific revocation via CRL is OPTIONAL in v1.
4. The CRL format definition is deferred to v2. The `revocation` field in identity documents is reserved for forward compatibility.
