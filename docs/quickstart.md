# AIP Quickstart

Get up and running with the Agent Identity Protocol in 5 minutes.

## Python

### Install

```bash
cd python
pip install -e ".[dev]"
```

### 1. Generate a keypair

```python
from aip_core.crypto import KeyPair

kp = KeyPair.generate()
print(f"Public key: {kp.public_key_multibase()}")
```

### 2. Create a compact token

```python
from aip_token.claims import AipClaims
from aip_token.compact import CompactToken
import time

claims = AipClaims(
    iss="aip:key:ed25519:" + kp.public_key_multibase(),
    sub="aip:web:example.com/tools/search",
    scope=["tool:search"],
    budget_usd=1.0,
    max_depth=0,
    iat=int(time.time()),
    exp=int(time.time()) + 3600,
)
token = CompactToken.create(claims, kp)
print(f"Token: {token}")
```

The resulting token is a standard JWT with `{"alg": "EdDSA", "typ": "aip+jwt"}` header, signed with Ed25519.

### 3. Verify a token

```python
verified = CompactToken.verify(token, kp.public_key_bytes())
print(f"Issuer: {verified.claims.iss}")
print(f"Has search scope: {verified.has_scope('tool:search')}")
```

`verify()` checks the Ed25519 signature and token expiry. It raises `TokenError` on failure.

### 4. Use with MCP

Attach the token to outgoing HTTP requests via the `X-AIP-Token` header:

```python
headers = {"X-AIP-Token": token}
```

The MCP server extracts the header, verifies the signature against the agent's known public key, and checks that the token's scope covers the requested tool.

See the [single-agent-mcp example](../examples/single-agent-mcp/) for a complete working client and server.

### 5. Create a chained (delegated) token

Chained mode uses Biscuit tokens for multi-hop delegation. Each hop can only narrow scope.

```python
from aip_core.crypto import KeyPair
from aip_token.chained import ChainedToken

root_kp = KeyPair.generate()

# Create an authority token (the root of the chain)
token = ChainedToken.create_authority(
    issuer="aip:web:example.com/orchestrator",
    scopes=["tool:search", "tool:email"],
    budget_cents=500,
    max_depth=3,
    ttl_seconds=3600,
    keypair=root_kp,
)

# Delegate to a specialist with narrower scope
delegated = token.delegate(
    delegator="aip:web:example.com/orchestrator",
    delegate="aip:web:example.com/specialist",
    scopes=["tool:search"],
    budget_cents=100,
    context="research task for user query",
)

# Authorize before calling the tool
delegated.authorize("tool:search", root_kp.public_key_bytes())
```

Budget is always integer cents (e.g. `500` = $5.00). Biscuit has no float support.

You can also use `SimplePolicy` to generate Datalog checks automatically instead of writing them by hand:

```python
from aip_token.policy import SimplePolicy

policy = SimplePolicy(
    tools=["tool:search"],
    budget_cents=100,
    max_depth=2,
    ttl_seconds=1800,
)
print(policy.to_datalog())
```

For the full delegation guide, see [guide-delegation.md](guide-delegation.md).

## Rust

### Install

Add the workspace crates as path dependencies in your `Cargo.toml`:

```toml
[dependencies]
aip-core = { path = "../rust/aip-core" }
aip-token = { path = "../rust/aip-token" }
```

Adjust the paths relative to your crate.

### Example

```rust
use aip_core::crypto::KeyPair;
use aip_token::claims::AipClaims;
use aip_token::compact::CompactToken;
use chrono::Utc;

fn main() {
    // Generate a keypair
    let kp = KeyPair::generate();
    println!("Public key: {}", kp.public_key_multibase());

    // Create a compact token
    let now = Utc::now().timestamp();
    let claims = AipClaims {
        iss: format!("aip:key:ed25519:{}", kp.public_key_multibase()),
        sub: "aip:web:example.com/tools/search".into(),
        scope: vec!["tool:search".into()],
        budget_usd: Some(1.0),
        max_depth: 0,
        iat: now,
        exp: now + 3600,
    };
    let token = CompactToken::create(&claims, &kp).expect("token creation failed");
    println!("Token: {token}");

    // Verify
    let pk = kp.public_key_bytes();
    let verified = CompactToken::verify(&token, &pk).expect("verification failed");
    println!("Issuer: {}", verified.claims.iss);
    println!("Has search scope: {}", verified.has_scope("tool:search"));
}
```

## Running tests

```bash
# Rust
cd rust && cargo test

# Python
cd python && pytest tests/ -v
```

## Next steps

- Read the [delegation guide](guide-delegation.md) for chained token patterns and scope attenuation
- Read the [specification overview](../SPEC.md) for protocol details
- Browse the [single-agent-mcp example](../examples/single-agent-mcp/) for a working MCP integration
- See the [competitive analysis](competitive-analysis.md) for how AIP compares to OAuth, DID, UCAN, Macaroons, and other approaches
