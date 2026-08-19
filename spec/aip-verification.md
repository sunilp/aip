# AIP Verification Algorithm

**Version:** 0.2.0-draft
**Status:** Draft
**Date:** 2026-08-19

---

## 1. Introduction

This document defines the normative algorithm a verifier performs on an AIP token. It corresponds to Section 4 of [draft-prakash-aip-01](https://datatracker.ietf.org/doc/draft-prakash-aip/).

A verifier presented with an AIP token MUST perform steps V1 through V7 in the order given before treating any identity or capability asserted by the token as established. The ordering matters: no step that reads block content is permitted before chain integrity is established in V1.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 2. V1: Chain Integrity

The verifier MUST deserialize the token from its wire form and verify the signature on every block against the root public key. In chained mode this means verifying the full signature chain from block 0 through block N, not the signature on the presented leaf alone.

Verification MUST be performed against the serialized form as received. An implementation that holds a token in a parsed in-memory representation MUST re-serialize and re-verify before relying on it, rather than trusting the state of its own parsed object.

A verifier MUST NOT accept any fact, check, or claim from a block that it has not verified as part of a chain rooted at the issuer's key.

**Failure:** `aip_signature_invalid`

---

## 3. V2: Root Binding

The verifier MUST extract the issuer from the `identity` fact in block 0 and confirm that the root public key used in V1 is the key bound to that identifier:

- For `aip:web:` identifiers, by resolving the identity document as defined in [AIP Core](aip-core.md) and comparing the published key.
- For `aip:key:` identifiers, by decoding the key from the identifier itself and comparing.

A verifier MUST NOT infer the root key from the token.

**Failure:** `aip_identity_unresolvable`

---

## 4. V3: Depth

The verifier MUST confirm that the number of delegation blocks does not exceed the `max_depth` declared in block 0.

**Failure:** `aip_depth_exceeded`

---

## 5. V4: Structural Attenuation Walk

The verifier MUST walk the chain from block 1 to block N and confirm, for each block i, that every capability dimension is narrower than or equal to the corresponding dimension in block i-1.

| Dimension | Rule | Failure |
|---|---|---|
| Scope | The allowlist in block i MUST be a subset of the allowlist in block i-1. | `aip_scope_insufficient` |
| Budget | A declared `budget_ceiling` MUST be non-negative and MUST NOT exceed the nearest ancestor that declares one. | `aip_budget_exceeded` |
| Time | A declared expiry MUST NOT be later than the nearest ancestor's, and no block's expiry may be in the past. | `aip_token_expired` |
| Domains | The domain set in block i MUST be a subset of block i-1's. | `aip_scope_insufficient` |
| Principal | If an ancestor declares a `principal`, no later block may declare a different one. | `aip_token_malformed` |

A dimension absent from block i inherits the value of its nearest ancestor. A wildcard in an ancestor permits any specific value in a descendant. A specific value in an ancestor MUST NOT widen to a wildcard in a descendant.

A verifier determines a block's scope from its check statement, not from its `right` facts. The check is what constrains authorization; the facts are descriptive. A block carrying a permissive check and no matching facts would otherwise read as declaring nothing.

### 5.1 Why the Container Does Not Establish This

This step is REQUIRED and is not satisfied by the container format.

A verifier MUST NOT rely on the semantics of an append-only token container to establish attenuation. Container-level signature chaining establishes that blocks were appended in order by successive keyholders, which is a different property: it prevents a block from being substituted, reordered, or forged, but it does not establish that the capabilities asserted in block i are a subset of those held by block i-1.

Attenuation is a property of the capability content and MUST be checked as such, in addition to V1. The two properties are independent, and a verifier performing only signature verification will accept a chain in which a delegation widened its own authority.

---

## 6. V5: Delegation Context

Every delegation block MUST carry a non-empty `context` fact. A verifier MUST reject a chain in which any delegation block omits it or supplies an empty value.

**Failure:** `aip_token_malformed`

---

## 7. V6: Policy Evaluation

The verifier MUST evaluate the token's policies with the ambient facts `tool`, `time`, and `depth` bound to the request under consideration, and MUST require that every check in every block passes.

The verifier MUST NOT introduce ambient facts beyond those named above. In particular it MUST NOT supply a `budget` fact: supplying one causes any budget check in the chain to evaluate against verifier-chosen data rather than against the token, which makes the check meaningless. Budget is handled in V4.

**Failure:** `aip_scope_insufficient`

---

## 8. V7: Revocation with Bounded Staleness

If the issuer's identity document advertises a revocation endpoint, the verifier MUST check whether any key in the chain has been revoked. Revocation data MAY be cached.

A verifier MUST be configurable with a maximum acceptable staleness for cached revocation data, and MUST fail closed when its cached data is older than that bound rather than proceeding on stale information.

Revocation responses MUST be signed by the issuer so that their authenticity is verifiable without a trusted transport to the revocation endpoint.

**Failure:** `aip_key_revoked`

---

## 9. Verification Result

A token that passes V1 through V7 establishes:

- the identity of the issuer,
- the identity of each delegator and delegate in the chain,
- the capabilities available at the leaf, and
- that no hop in the chain exceeded the authority of its predecessor.

It does NOT establish that the presenting party is the party the leaf was issued to. An AIP token as specified is a bearer credential. A captured or relayed token is usable by whoever holds it, within the scope, time, and budget the chain permits.

Deployments requiring proof of possession MUST bind the token to a key at the transport or message layer. Mutual TLS, HTTP message signatures, and workload proof tokens are all suitable. Implementations MUST NOT describe AIP verification as authenticating the presenter.
