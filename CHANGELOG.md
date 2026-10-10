# Changelog

All notable changes to AIP (Agent Identity Protocol) are documented here.

## [0.6.0] - Unreleased

Accompanies IETF draft-prakash-aip-02.

### Added

- JWT chain encoding: `aip_token.jwt_chain.JwtChain`, media type
  `application/aip-chain+jwt`, link `typ` `aip-link+jwt`.
- A shared, encoding-neutral chain model in `aip_token.chain_model`, so the
  Biscuit and JWT encodings run the same attenuation, expiry and authorization
  checks.
- Domain allowlists in both encodings. In Biscuit chains they are carried as
  facts only.
- `JwtChain.leaf_holder_key()`, the key a relying party needs for proof of
  possession.
- `TokenError.wire_code`.
- The MCP middleware, the MCP proxy and the A2A verifier accept JWT chains.

### Changed

Behaviour visible to callers:

- Biscuit `verify_chain` now enforces expiry structurally, so expired chains
  are rejected on requests that name no tool. A2A raises `ExpiryError` rather
  than `ScopeError` for expired tokens.
- An authority token with no tools is rejected. It previously authorized every
  tool.
- Empty `tools` or `domains` lists are malformed.
- Duplicate single-valued facts in a Biscuit block are malformed.
- Biscuit links missing identity, delegator or delegate are malformed.
- Compact tokens must carry `typ` `aip+jwt`.
- `cnf` keys must be strict base64url.
- `JwtChain.verify` requires a 32-byte `bytes` root key.
- Identity document signatures are decoded as base64url. Standard base64 is
  still accepted.

### Deprecated

- `CompactToken` and `typ` `aip+jwt`. They are still verified. Draft-02 folds
  compact mode into the one-link JWT chain.

### Known limitations

- JWT chains: any prefix of a valid chain also verifies and carries an earlier
  holder's wider authority. The MCP proxy and middleware do not verify proof of
  possession, so they treat JWT chains as bearer-equivalent to the root grant.
  Biscuit chains are not affected.
- The JWT verifier does not check that a link's `cnf` key belongs to its `sub`
  identifier.
- V7 revocation is not implemented.

## [0.5.0] - 2026-08-23

### Security

**The MCP auth proxy did not verify AIP tokens.** `aip_mcp/proxy.py` called
`ChainedToken.from_base64`, which is step V1 only, and then an audit function
whose `errors` list nothing ever wrote to, so `passed` was unconditionally
`True`. Steps V2 through V7 never ran. A chain with an out-of-scope tool, an
expired time check, a raised budget ceiling, an empty delegation context, or
depth past `max_depth` was forwarded upstream as verified so long as its
signatures chained. Anyone running `aip-proxy` should upgrade.

Demonstrated against 0.4.0, with a token granting only `tool:search`:

```
tools/call name="delete_everything"  -> HTTP 200 (forwarded)
expired chain, tools/call            -> HTTP 200 (forwarded)
```

Both now return 403 and 401 respectively.

- **V6 now runs.** The proxy reads the JSON-RPC method and, for `tools/call`,
  the tool name out of the request body, and evaluates the token's policy
  against the tool actually being invoked. It had no way to do this before
  because it forwarded raw HTTP without parsing MCP at all. Requests naming no
  tool (`initialize`, `tools/list`) now get V1 through V5 via the new
  `ChainedToken.verify_chain()`, rather than being waved through.
- **V2 (root binding) now runs.** The proxy previously tried each configured
  trust key until one verified, then trusted the token's self-declared
  identity. With two trusted issuers, a token signed by one could claim the
  identity of the other. `trust_keys` now accepts a mapping of issuer to key,
  and the key that verified a token must be the key configured for the issuer
  that token declares.
- **A JSON-RPC batch invoking more than one distinct tool is refused.** One
  policy evaluation cannot authorize two different tools.
- **Error status codes follow Section 6.1.** `scope_insufficient`,
  `budget_exceeded` and `depth_exceeded` return 403; the proxy previously
  hardcoded 401 for every verification failure, telling clients to
  re-authenticate when their credential was valid and simply insufficient.

### Fixed

- `audit_chained()` could never fail. It appended only to `warnings`, never to
  `errors`, so `AuditResult.passed` was always `True` and any caller treating
  it as a gate was gating on nothing. It now accepts `max_depth` and
  `max_budget_cents`, and exceeding either is an error. It remains a deployment
  policy check layered on top of verification, not a substitute for it.

### Added

- `ChainedToken.verify_chain()` runs V1, V3, V4 and V5 and returns the verified
  Biscuit, for relying parties that must establish what a chain conveys on a
  request that names no tool.
- `aip_mcp.request.parse_mcp_request()` extracts the MCP method and tool name
  from a JSON-RPC body.

### Breaking

- `trust_keys` given as a list of more than one key is now refused at startup.
  That form cannot support V2, and it is exactly the configuration in which one
  trusted issuer can impersonate another. Use the mapping form:

  ```toml
  [proxy.trust_keys]
  "aip:web:example.com" = "ed25519:..."
  ```

  A single-key list still works and logs a warning that V2 is not enforced.
- Requests the proxy previously forwarded are now correctly denied.

## [0.4.0] - 2026-08-23

### Security

Two authorization bypasses, both caused by building Biscuit Datalog with string
interpolation. Anyone running 0.3.0 or earlier should upgrade.

- **Authorizer injection in `ChainedToken.authorize()`.** The requested tool name
  was interpolated into the authorizer source. A tool name that closed its own
  string could append an in-allowlist `tool()` fact and `allow if true`, so a
  token granting only `tool:search` authorized any tool. This required no
  malicious token, no forged signature and no control of the issuer, only
  influence over the tool name being checked. In an MCP binding that name comes
  straight from the agent's JSON-RPC `params.name`. The tool is now validated and
  bound as a Datalog parameter rather than interpolated.
- **Block-encoder injection in `create_authority()` and `delegate()`.** The
  issuer, principal, scope, delegator, delegate and context values were
  interpolated into block Datalog, so a breakout in any of them injected facts
  into a block that was then signed. An injected `tool()` fact satisfied the
  authority block's own scope check for any tool, an injected `time()` fact
  defeated expiry, and an injected `max_depth()` ahead of the real one was what
  the depth check read. All six fields are now validated at the API boundary.

`aip_token.canonical.validate_term()` rejects the double quote, the backslash and
control characters, which are the only characters that can escape a Datalog
string context. Semicolons, parentheses, brackets, commas, `//`, spaces, colons
and non-ASCII characters remain valid, so ordinary identifiers and free-form
context strings are unaffected.

### Fixed

- `SimplePolicy.to_datalog()` emitted `check if budget($b), $b <= N` and
  `check if depth($d), $d <= N` in both the Python and Rust SDKs. Section 3.4.1
  of draft-prakash-aip-01 requires these as the facts `budget_ceiling(N)` and
  `max_depth(N)`, and states that implementations MUST NOT emit a check over
  budget: such a check binds to whatever budget facts are in scope at evaluation
  rather than to the block's own ceiling, so it either rejects valid chains or
  passes unconditionally. Both dimensions are verified structurally in step V4.
  The chained-token builders were already correct; only `SimplePolicy` was wrong.

### Changed

- The canonical Section 3.4.1 encoding now lives in one module per language
  (`aip_token.canonical`, `aip_token::canonical`). It had been implemented twice
  in each SDK, which is how `SimplePolicy` drifted from the chained builder.
- New cross-language conformance vectors compare the Rust and Python renderings
  byte for byte, and both SDKs now carry regression tests for the two bypasses.

### Breaking

- `SimplePolicy.to_datalog()` output has changed. It now emits the canonical
  Section 3.4.1 form. Callers embedding the old output in their own Datalog
  should re-render.
- Identifiers, scopes and context strings containing a double quote, a backslash
  or control characters are now rejected with `token_malformed`.

## [0.3.0] - 2026-05-08

### Added
- New `aip_a2a` module: AIP binding for the Agent-to-Agent (A2A) protocol.
  - `verify_a2a_task()` — verify chained tokens carried in A2A task `metadata.aip_token`
  - `append_delegation_block()` — extend a chain before forwarding a task
  - `A2AVerifyMiddleware` — framework-agnostic wrapper for A2A task handlers
  - `parse_aip_identity()` — extract and validate the `aip_identity` extension from agent cards
  - A2A-specific error types: `AudienceError`, `ScopeError`, `ChainError`, `ExpiryError`, `DepthError`
- Rendered specification at https://sunilprakash.com/aip/spec/.
- Interactive protocol page at https://sunilprakash.com/aip/paper/ (verification flow, chain viewer, attack simulator).

### Changed
- `agent-identity-protocol` package now ships four sub-packages: `aip_core`, `aip_token`, `aip_mcp`, `aip_a2a`.
- `ChainedToken.authorize()` now correctly handles delegated tokens with budget constraints (was previously failing on any chained token with `budget_cents` set on a delegation block) and explicitly enforces scope attenuation across delegation hops.

### Notes
- No breaking changes. All `aip_core`, `aip_token`, `aip_mcp` imports continue to work unchanged.

## [0.2.0] - 2026-04-13

### Added
- `aip-proxy` CLI: drop-in MCP authentication proxy that wraps any MCP server with AIP token verification
- `aip_mcp.audit` module: security self-audit for compact and chained tokens (token hygiene, scope safety, budget limits, chain integrity)
- `aip_mcp.config` module: TOML-based proxy configuration
- `aip_mcp.proxy` module: HTTP proxy server for MCP transports
- `__version__` attribute in `aip_core`
- Project hub site at sunilprakash.com/aip/ with quickstart tutorial, security model, and framework guides

### Changed
- README rewritten: problem-first structure with framework quickstart examples
- Added sitemap.xml for site SEO

## [0.1.1] - 2026-03-28

### Added
- LangChain adapter in `aip-agents`
- SECURITY.md with vulnerability reporting guidelines
- PyPI keywords and classifiers for discoverability

## [0.1.0] - 2026-03-27

### Added
- Core SDK: `aip_core` with Ed25519 key pairs, AIP identifiers (`aip:web:`, `aip:key:`), identity documents
- Compact token mode: `aip_token` with JWT+EdDSA invocation-bound capability tokens (IBCTs)
- MCP middleware: `aip_mcp` with token extraction, mode detection, request verification
- `aip-agents` package with CrewAI and Google ADK adapters
- Cross-language interop tests (Rust <-> Python)
- 63 tests passing
