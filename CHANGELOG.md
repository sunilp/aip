# Changelog

All notable changes to AIP (Agent Identity Protocol) are documented here.

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
