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
| `right($capability)` | One fact per authorized capability (e.g., `right("tool:search")`). |
| `budget($amount)` | Authorization budget ceiling in USD. |
| `max_depth($depth)` | Maximum delegation chain depth. |
| `expires($timestamp)` | Expiration timestamp. |

### 4.4 Delegation Block Facts

Each delegation block (Block 1..N-1) MUST contain:

| Fact | Description |
|---|---|
| `delegator($id)` | AIP identifier of the delegating agent. |
| `delegate($id)` | AIP identifier of the receiving agent. |
| `right($capability)` | Attenuated capabilities (MUST be a subset of the parent block). |
| `budget($amount)` | Attenuated budget ceiling (MUST be <= parent budget). |
| `context($text)` | Non-empty string describing the delegation reason. |

**Requirements:**

1. Each delegation block MUST be signed by the delegator.
2. The `context` field MUST be non-empty. Verifiers MUST reject tokens with missing or empty context fields.
3. Scope attenuation is enforced cryptographically: each block's capabilities MUST be a subset of the parent block's capabilities.

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

Budget fields (`budget_usd` in compact mode, `budget` facts in chained mode) represent **per-token authorization limits**, not running balances.

### 6.1 Enforcement Model

Budget is enforced by the **delegator at delegation time** and the **verifier at invocation time**, not tracked across invocations:

1. **At delegation time:** When Agent A delegates to Agent B with `budget:0.50`, Agent A is asserting "I authorize B to spend up to $0.50 on this task." Agent A is responsible for partitioning its own budget across sub-delegations.

2. **At invocation time:** The verifier (MCP server, A2A receiver) checks that the declared budget in the token is non-negative. It does NOT track cumulative spend.

3. **At completion time:** The completion block records actual `cost_usd` spent. This is for audit, not enforcement.

4. **Aggregate enforcement** is the responsibility of the runtime (e.g., an orchestration platform's cost tracking), not the token. AIP tokens authorize a ceiling; runtimes enforce the floor.

### 6.2 Analogy

This is analogous to a credit card authorization: the token says "authorized up to $X", the merchant checks the limit, but the bank (runtime) tracks the running balance.

### 6.3 Requirements

1. Budget values in delegation blocks MUST be less than or equal to the parent block's budget.
2. Verifiers MUST check that the declared budget is non-negative.
3. Verifiers MUST NOT track cumulative spend across invocations using the token alone.
4. Completion blocks SHOULD record actual `cost_usd` for audit purposes.

---

## 7. Policy Profiles (Chained Mode)

Datalog policies in chained mode blocks use one of three profiles. Policy profiles apply only to chained mode tokens.

### 7.1 Simple Profile

Templated rules requiring no Datalog knowledge. Users specify values and the library generates canonical Datalog. The canonical Datalog templates are normative: implementations MUST generate exactly these patterns.

**Tool allowlist template:**
```datalog
check if tool($tool), ["search", "browse"].contains($tool);
```

**Budget ceiling template:**
```datalog
check if budget($b), $b <= 0.50;
```

**Delegation depth template:**
```datalog
check if depth($d), $d <= 3;
```

**Time expiry template:**
```datalog
check if time($t), $t <= 2026-03-22T12:00:00Z;
```

**Requirements:**

1. Implementations MUST generate exactly the canonical Datalog patterns shown above for Simple profile policies.
2. The templates are fixed across implementations to ensure interoperability.
3. Users specify configuration values (e.g., `tools: [search, browse], budget: 0.50, max_depth: 3`) and the library generates the canonical Datalog.

### 7.2 Standard Profile

Curated Datalog subset. No recursion. Bounded evaluation.

```datalog
check if tool($tool), delegator($d),
  trust_domain($d, $domain),
  ["research", "internal"].contains($domain);
```

**Requirements:**

1. Standard profile policies MUST NOT use recursive rules.
2. Evaluation MUST be bounded.

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
