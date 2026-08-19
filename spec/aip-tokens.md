# AIP Tokens: Compact and Chained Token Formats

**Version:** 0.1.0-draft
**Status:** Draft
**Date:** 2026-03-22

---

## 1. Introduction

This document defines the two AIP token formats -- compact mode (JWT wire format) and chained mode (Biscuit wire format) -- their structure, mode detection, claim mapping, budget semantics, policy profiles, and token size guidance.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 2. Token Modes Overview

AIP supports two token modes:

| Property | Compact Mode | Chained Mode |
|---|---|---|
| Wire format | JWT ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)) | Biscuit ([Biscuit specification](https://www.biscuitsec.org/)) |
| Delegation hops | One hop only | Multi-hop with append-only blocks |
| Scope attenuation | Static at issuance | Per-block attenuation |
| Provenance binding | Not supported | Completion blocks |
| Library requirements | Standard JWT libraries | Biscuit libraries |
| Use when | Single-agent setups, MCP server auth, quick integration | Multi-agent orchestration, cross-org delegation, audit requirements |

Both modes use the same transport mechanism: `X-AIP-Token` header or `Authorization: AIP <token>`.

---

## 3. Compact Mode (JWT Wire Format)

### 3.1 JWT Header

Compact mode tokens MUST use the following JWT header:

```json
{
  "alg": "EdDSA",
  "typ": "aip+jwt"
}
```

**Requirements:**

1. The `alg` field MUST be `"EdDSA"` (Ed25519 signatures).
2. The `typ` field MUST be `"aip+jwt"` to distinguish AIP tokens from other JWTs.

### 3.2 JWT Claims

The payload MUST include the following registered and private claims:

```json
{
  "iss": "aip:web:jamjet.dev/agents/orchestrator",
  "sub": "aip:web:jamjet.dev/agents/research-analyst",
  "scope": ["tool:search", "tool:browse"],
  "budget_usd": 0.50,
  "max_depth": 0,
  "iat": 1711100000,
  "exp": 1711103600
}
```

### 3.3 Claim Definitions

| Claim | Type | Required | Description |
|---|---|---|---|
| `iss` | string | REQUIRED | AIP identifier of the token issuer. MUST be a valid AIP identifier. |
| `sub` | string | REQUIRED | AIP identifier of the token holder (the agent authorized to use this token). |
| `scope` | array of strings | REQUIRED | List of authorized capabilities. Each entry is a capability string (e.g., `"tool:search"`, `"tool:*"`). |
| `budget_usd` | number | OPTIONAL | Per-token authorization ceiling in USD. See Section 6 for budget semantics. |
| `max_depth` | integer | REQUIRED | Maximum further delegation depth. `0` means the holder MUST NOT delegate further. |
| `iat` | integer | REQUIRED | Issued-at timestamp (seconds since Unix epoch, per RFC 7519). |
| `exp` | integer | REQUIRED | Expiration timestamp (seconds since Unix epoch, per RFC 7519). |

**Requirements:**

1. `iss` and `sub` MUST be valid AIP identifiers as defined in the AIP Core specification.
2. `scope` MUST contain at least one entry.
3. `max_depth` of `0` means the token holder MUST NOT delegate further. This is a constraint on the holder, not a counter of hops taken.
4. `exp` SHOULD be set to a short duration. Compact mode tokens SHOULD have a lifetime of less than 1 hour.

---

## 4. Chained Mode (Biscuit Wire Format)

### 4.1 Overview

Chained mode uses the [Biscuit](https://www.biscuitsec.org/) token format: an append-only block chain where each block is signed with Ed25519. This enables multi-hop delegation with scope attenuation at each hop and provenance binding via completion blocks.

### 4.2 Block Structure

A chained mode token consists of an ordered sequence of blocks:

**Block 0 (Authority)** -- signed by the root identity (human or system):

```
Block 0 (Authority) -- signed by root (human/system)
  identity: aip:web:jamjet.dev/agents/orchestrator
  capabilities: [tool:*, delegate:*, budget:5.00]
  max_depth: 3
  expires: 2026-03-22T12:00:00Z
```

**Block 1..N-1 (Delegation)** -- each signed by the delegator:

```
Block 1 (Delegation) -- signed by orchestrator
  delegator: aip:web:jamjet.dev/agents/orchestrator
  delegate: aip:web:jamjet.dev/agents/research-analyst
  attenuate: [tool:search, tool:browse, budget:0.50]
  context: "research subtask for query X"
```

**Block N (Completion)** -- signed by the executing agent (see AIP Provenance specification):

```
Block N (Completion) -- signed by ephemeral sub-agent
  status: completed
  result_hash: sha256:abc123...
  verification_status: tool_verified
  tokens_used: 1200
  cost_usd: 0.03
```

### 4.3 Block 0 (Authority) Facts

Block 0 MUST contain the following Biscuit facts:

| Fact | Description |
|---|---|
| `identity($id)` | AIP identifier of the root authority. |
| `principal($id)` | OPTIONAL. The on-behalf-of principal. Invariant along the chain. |
| `right($capability)` | One fact per authorized capability (e.g., `right("tool:search")`). Descriptive. |
| `budget_ceiling($cents)` | OPTIONAL. Authorization ceiling in integer cents. |
| `max_depth($depth)` | Maximum delegation chain depth. |

Block 0 MUST also carry the scope check and the expiry check defined in Section 7.1.

The `right` facts are descriptive metadata. The scope check is what constrains
authorization, and verifiers determine a block's scope from that check rather
than from the `right` facts. A block carrying a permissive check and no
matching facts would otherwise read as declaring nothing.

### 4.4 Delegation Block Facts

Each delegation block (Block 1..N-1) MUST contain:

| Fact | Description |
|---|---|
| `delegator($id)` | AIP identifier of the delegating agent. |
| `delegate($id)` | AIP identifier of the receiving agent. |
| `context($text)` | Non-empty string describing the delegation reason. |
| `principal($id)` | OPTIONAL. MUST match the principal declared by an ancestor. |
| `budget_ceiling($cents)` | OPTIONAL. MUST NOT exceed the nearest ancestor's ceiling. |

Each delegation block MUST also carry the scope check defined in Section 7.1, and MAY carry an expiry check no later than its parent's.

**Requirements:**

1. Each delegation block MUST be signed by the delegator.
2. The `context` field MUST be non-empty. Verifiers MUST reject tokens with missing or empty context fields.
3. Scope narrowing follows from conjunction: every block contributes a scope check and all checks in all blocks MUST pass, so the authorized set is the intersection of the per-block allowlists. Naming a capability absent from an ancestor's allowlist produces an empty intersection and authorizes nothing.
4. Verifiers MUST additionally perform the structural attenuation walk in [AIP Verification](aip-verification.md) step V4. Conjunction prevents a widened block from being useful; the walk is what detects and reports it.

---

## 5. Mode Detection and Upgrade

### 5.1 Mode Detection

Receivers MUST detect the token mode by inspecting the token content:

1. **Compact mode:** Token decodes as a JWT with header `typ: "aip+jwt"`.
2. **Chained mode:** Token begins with Biscuit magic bytes.

Implementations MUST support both detection methods.

### 5.2 Compact-to-Chained Mapping

When upgrading from compact to chained mode, the issuer creates a new chained token (Block 0) using the same key and equivalent claims. The compact JWT claims map to Biscuit authority facts as follows:

| JWT Claim | Biscuit Authority Fact |
|---|---|
| `iss` | `identity($iss)` |
| `sub` | `delegate($sub)` |
| `scope` (each entry) | `right($scope_item)` |
| `budget_usd` | `budget($budget_usd)` |
| `max_depth` | `max_depth($max_depth)` |
| `exp` | `expires($exp)` |

**Requirements:**

1. Upgrade from compact to chained REQUIRES re-issuance. The original compact JWT is NOT embedded in the chained token.
2. The new chained token MUST be signed by the same key that signed the compact JWT.
3. All claims from the compact token MUST be faithfully represented in the chained token's Block 0 facts.

---

## 6. Budget Semantics

Budget fields (`budget_usd` in compact mode, `budget_ceiling` facts in chained mode) represent **per-token authorization ceilings**, not running balances.

### 6.1 Declared and Verified

A ceiling is both declared and verified, and these are distinct operations:

- **Declared** as a `budget_ceiling` fact, in integer cents, in the block that establishes it.
- **Verified** structurally at every hop. A verifier MUST confirm each block's declared ceiling is non-negative and does not exceed the nearest ancestor that declares one. A block declaring no ceiling inherits its nearest ancestor's. This is step V4 of [AIP Verification](aip-verification.md).

### 6.2 Budget Is Not a Datalog Check

Implementations MUST NOT express a budget ceiling as a Datalog check, and verifiers MUST NOT inject an ambient `budget` fact during policy evaluation.

A check of the form `check if budget($b), $b <= N` binds to whatever budget facts are in scope during evaluation, which is not the same question as whether this block's ceiling narrows its parent's. Encoding budget as a check therefore either rejects valid chains, or, if the verifier supplies a satisfying ambient fact, passes unconditionally. Both failure modes have been observed in practice between independent implementations of this specification.

### 6.3 What the Token Does Not Do

The token does not track cumulative spending. Nothing in a delegation chain records how much of a ceiling has been consumed, and a verifier evaluating a single request cannot know. Enforcement of actual spend against a ceiling is out of band and is the responsibility of the orchestration platform at dispatch time. Completion blocks record actual `cost_usd` for audit, which supports after-the-fact reconciliation but is not an authorization control.

Implementations MUST NOT present ceiling verification as spend enforcement. A chain that verifies establishes that no hop authorized more than it held. It does not establish that the authorized amount remains available.

### 6.4 Analogy

This is analogous to a credit card authorization: the token says "authorized up to $X", the merchant checks the limit, but the bank (runtime) tracks the running balance.

### 6.5 Requirements

1. Budget ceilings in delegation blocks MUST be less than or equal to the nearest ancestor's ceiling.
2. Verifiers MUST check that a declared ceiling is non-negative.
3. Implementations MUST NOT emit a `check` statement over `budget`.
4. Verifiers MUST NOT inject an ambient `budget` fact.
5. Verifiers MUST NOT track cumulative spend across invocations using the token alone.
6. Completion blocks SHOULD record actual `cost_usd` for audit purposes.

---

## 7. Policy Profiles (Chained Mode)

Datalog policies in chained mode blocks use one of three profiles. Policy profiles apply only to chained mode tokens.

### 7.1 Simple Profile

Templated rules requiring no Datalog knowledge. Users specify values and the library generates canonical Datalog. **The canonical forms are normative: implementations MUST emit exactly these patterns.** Interoperability depends on it, because two encodings that are individually defensible will not verify against each other.

**Authority block (block 0):**

```datalog
identity("<aip-identifier>");
principal("<identifier>");          ; OPTIONAL, on-behalf-of party
right("<scope>");                   ; one fact per granted scope
max_depth(<n>);
budget_ceiling(<cents>);            ; OPTIONAL, integer cents
check if tool($t), ["<scope>", ...].contains($t);
check if time($t), $t <= <expiry>;
```

**Delegation block (blocks 1 through N):**

```datalog
delegator("<aip-identifier>");
delegate("<aip-identifier>");
context("<non-empty string>");
principal("<identifier>");          ; OPTIONAL, MUST match ancestor
budget_ceiling(<cents>);            ; OPTIONAL, <= nearest ancestor
check if tool($t), ["<scope>", ...].contains($t);
check if time($t), $t <= <expiry>;  ; OPTIONAL, <= parent expiry
```

**Requirements:**

1. Implementations MUST generate exactly these patterns for Simple profile policies.
2. Users specify configuration values (e.g., `tools: [search, browse], budget: 50, max_depth: 3`) and the library generates the canonical Datalog.
3. Implementations MUST NOT emit a `check` statement over `budget`. See Section 6.2.
4. The Simple profile matches scopes by exact string equality. A scope containing `*` is matched literally and carries no pattern meaning in this profile. Deployments needing prefix matching MUST use the Standard profile.

### 7.2 Standard Profile

Curated Datalog subset. No recursion. Bounded evaluation. The Standard profile adds pattern matching over scopes while keeping the same block facts as Section 7.1.

**Scope patterns.** A scope ending in `*` is a prefix pattern. The canonical form joins an exact-match clause and one clause per pattern into a single check:

```datalog
check if tool($t), ["report:daily"].contains($t)
     or tool($t), $t.starts_with("tool:");
```

A bare `*` becomes the clause `tool($t)`, which matches any scope.

**Requirements:**

1. The exact-match clause, if any, MUST come first, followed by one clause per pattern in the order the scopes were supplied.
2. Standard profile policies MUST NOT use recursive rules.
3. Evaluation MUST be bounded.
4. **A block's scope constraint MUST be expressed as a single self-contained `check` statement.** Implementations MUST NOT encode scope as named rules shared across blocks.

Requirement 4 is a security requirement, not a style preference. Biscuit rules defined in the authority block remain in scope when later blocks are evaluated. A delegation block that defines a narrower rule under a name the authority block already uses does not replace the authority's rule; the two are unioned, and the broader authority rule then satisfies the delegation block's own check. Scope encoded this way does not attenuate. A self-contained check has no such interaction, because conjunction across blocks is what narrows the authorized set.

Other Standard profile policies may reference block facts directly:

```datalog
check if tool($tool), delegator($d),
  trust_domain($d, $domain),
  ["research", "internal"].contains($domain);
```

### 7.3 Advanced Profile

Full Datalog for enterprise policies. Opt-in, with evaluation depth limits.

**Requirements:**

1. Advanced profile is opt-in. Implementations MAY choose not to support it.
2. Evaluation MUST be limited to a maximum of 1000 iterations.
3. Implementations that support Advanced profile MUST enforce the iteration limit.

---

## 8. Token Size Considerations

### 8.1 Size Guidance

| Mode | Typical Size | Notes |
|---|---|---|
| Compact mode | 200-500 bytes | No size concern. |
| Chained mode | ~200-400 bytes per block | A 3-hop chain with simple policies and completion block is approximately 1.5KB. Fits within standard HTTP header limits (8KB). |

### 8.2 Token-by-Reference

For chains exceeding 4KB, implementations MAY use a token reference instead of inlining the full token:

```
X-AIP-Token-Ref: https://issuer.example/.well-known/aip/tokens/<token-id>
```

**Requirements:**

1. The reference URL MUST use HTTPS.
2. The response at the reference URL MUST include the token's self-authenticating signature chain. No additional trust beyond the token's own signatures is required.
3. Receivers MUST fetch and verify the full token from the reference URL before processing.

### 8.3 Recommended Chain Depth

The recommended maximum chain depth is 5 blocks (authority + 3 delegations + completion). This is a SHOULD, not a MUST. Implementations SHOULD warn when tokens approach this depth.
