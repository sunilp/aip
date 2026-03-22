use std::time::{Duration, SystemTime};

use biscuit_auth::{
    builder::{Algorithm, AuthorizerBuilder, BiscuitBuilder, BlockBuilder},
    Biscuit, KeyPair as BiscuitKeyPair, PrivateKey as BiscuitPrivateKey,
    PublicKey as BiscuitPublicKey,
};

use crate::error::TokenError;

/// A chained delegation token backed by a Biscuit.
///
/// The authority block contains Datalog facts for identity, scopes,
/// budget, max delegation depth, and an expiry check.
pub struct ChainedToken {
    biscuit: Biscuit,
    /// Cached issuer identity string.
    issuer_id: String,
    /// Cached max delegation depth.
    max_delegation_depth: u32,
}

impl ChainedToken {
    /// Create a new authority token (the root of a delegation chain).
    ///
    /// The authority block encodes:
    /// - `identity("aip:web:...")` -- the issuer identifier
    /// - `right("tool:search")` etc. -- one per scope entry
    /// - `budget(500)` -- integer cents (optional)
    /// - `max_depth(3)` -- delegation depth limit
    /// - expiry check: `check if time($t), $t <= {expiry}`
    pub fn create_authority(
        issuer: &str,
        scopes: &[&str],
        budget_cents: Option<i64>,
        max_depth: u32,
        ttl_seconds: u64,
        keypair: &aip_core::crypto::KeyPair,
    ) -> Result<Self, TokenError> {
        // Bridge aip KeyPair -> biscuit KeyPair
        let raw_bytes = keypair.private_key_bytes();
        let biscuit_private = BiscuitPrivateKey::from_bytes(&raw_bytes, Algorithm::Ed25519)
            .map_err(|e| TokenError::CreationFailed(format!("private key conversion: {e}")))?;
        let biscuit_kp = BiscuitKeyPair::from(&biscuit_private);

        // Assemble Datalog source for the authority block
        let mut datalog = String::new();

        // identity fact
        datalog.push_str(&format!("identity(\"{issuer}\");\n"));

        // right facts for each scope
        for scope in scopes {
            datalog.push_str(&format!("right(\"{scope}\");\n"));
        }

        // Scope check: the requested tool must be in the authority's allowed set.
        // The authorizer provides a `tool(...)` ambient fact for the tool being invoked.
        if !scopes.is_empty() {
            let set_items: Vec<String> = scopes.iter().map(|s| format!("\"{s}\"")).collect();
            datalog.push_str(&format!(
                "check if tool($t), [{items}].contains($t);\n",
                items = set_items.join(", ")
            ));
        }

        // budget fact (optional)
        if let Some(cents) = budget_cents {
            datalog.push_str(&format!("budget({cents});\n"));
        }

        // max_depth fact
        datalog.push_str(&format!("max_depth({max_depth});\n"));

        // expiry check
        let expiry = SystemTime::now() + Duration::from_secs(ttl_seconds);
        datalog.push_str(&format!(
            "check if time($t), $t <= {};\n",
            format_system_time(expiry)
        ));

        // BiscuitBuilder::code() consumes self and returns Result<Self, ...>
        let builder = BiscuitBuilder::new()
            .code(&datalog)
            .map_err(|e| TokenError::CreationFailed(format!("datalog parse: {e}")))?;

        // Build the biscuit
        let biscuit = builder
            .build(&biscuit_kp)
            .map_err(|e| TokenError::CreationFailed(format!("biscuit build: {e}")))?;

        Ok(Self {
            biscuit,
            issuer_id: issuer.to_string(),
            max_delegation_depth: max_depth,
        })
    }

    /// Deserialize a `ChainedToken` from raw bytes, verifying against the root public key.
    pub fn from_bytes(data: &[u8], root_public_key: &[u8; 32]) -> Result<Self, TokenError> {
        let biscuit_pubkey =
            BiscuitPublicKey::from_bytes(root_public_key, Algorithm::Ed25519)
                .map_err(|e| TokenError::VerificationFailed(format!("public key: {e}")))?;

        let biscuit = Biscuit::from(data, biscuit_pubkey)
            .map_err(|e| TokenError::VerificationFailed(format!("biscuit decode: {e}")))?;

        let (issuer_id, max_delegation_depth) = extract_authority_facts(&biscuit)?;

        Ok(Self {
            biscuit,
            issuer_id,
            max_delegation_depth,
        })
    }

    /// Serialize this token to raw bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TokenError> {
        self.biscuit
            .to_vec()
            .map_err(|e| TokenError::CreationFailed(format!("serialize: {e}")))
    }

    /// Deserialize a `ChainedToken` from a base64-encoded string.
    pub fn from_base64(s: &str, root_public_key: &[u8; 32]) -> Result<Self, TokenError> {
        let biscuit_pubkey =
            BiscuitPublicKey::from_bytes(root_public_key, Algorithm::Ed25519)
                .map_err(|e| TokenError::VerificationFailed(format!("public key: {e}")))?;

        let biscuit = Biscuit::from_base64(s, biscuit_pubkey)
            .map_err(|e| TokenError::VerificationFailed(format!("biscuit base64 decode: {e}")))?;

        let (issuer_id, max_delegation_depth) = extract_authority_facts(&biscuit)?;

        Ok(Self {
            biscuit,
            issuer_id,
            max_delegation_depth,
        })
    }

    /// Serialize this token to a base64-encoded string.
    pub fn to_base64(&self) -> Result<String, TokenError> {
        self.biscuit
            .to_base64()
            .map_err(|e| TokenError::CreationFailed(format!("base64 serialize: {e}")))
    }

    /// Return the issuer identity from the authority block.
    pub fn issuer(&self) -> String {
        self.issuer_id.clone()
    }

    /// Return the max delegation depth from the authority block.
    pub fn max_depth(&self) -> u32 {
        self.max_delegation_depth
    }

    /// Return the current delegation depth (0 for authority-only tokens).
    ///
    /// The authority block is block 0; each appended block adds one level.
    pub fn current_depth(&self) -> usize {
        self.biscuit.block_count() - 1
    }

    /// Append a delegation block to this token, producing a new attenuated token.
    ///
    /// The delegation block records `delegator`, `delegate`, and `context` as
    /// Datalog facts, and adds `check` rules that narrow the token's usable
    /// scopes and (optionally) budget.
    ///
    /// No keypair is required -- Biscuit generates an ephemeral key internally
    /// for the new block.
    pub fn delegate(
        &self,
        delegator: &str,
        delegate: &str,
        scopes: &[&str],
        budget_cents: Option<i64>,
        context: &str,
    ) -> Result<Self, TokenError> {
        // 1. Context must be non-empty.
        if context.is_empty() {
            return Err(TokenError::TokenMalformed(
                "context must be non-empty".into(),
            ));
        }

        // 2. Check depth limit.
        if self.current_depth() >= self.max_delegation_depth as usize {
            return Err(TokenError::DepthExceeded);
        }

        // 3. Build Datalog source for the delegation block.
        let mut datalog = String::new();

        // Facts for audit trail
        datalog.push_str(&format!("delegator(\"{delegator}\");\n"));
        datalog.push_str(&format!("delegate(\"{delegate}\");\n"));
        datalog.push_str(&format!("context(\"{context}\");\n"));

        // Scope check: the requested tool must be in this delegation's allowed set.
        // The authorizer provides a `tool(...)` ambient fact for the tool being invoked.
        if !scopes.is_empty() {
            let set_items: Vec<String> = scopes.iter().map(|s| format!("\"{s}\"")).collect();
            datalog.push_str(&format!(
                "check if tool($t), [{items}].contains($t);\n",
                items = set_items.join(", ")
            ));
        }

        // Budget check (if set): the authority budget must be >= this value.
        if let Some(cents) = budget_cents {
            datalog.push_str(&format!(
                "check if budget($b), $b >= {cents};\n"
            ));
        }

        // 4. Build the block and append it.
        let block_builder = BlockBuilder::new()
            .code(&datalog)
            .map_err(|e| TokenError::CreationFailed(format!("delegation datalog parse: {e}")))?;

        let new_biscuit = self
            .biscuit
            .append(block_builder)
            .map_err(|e| TokenError::CreationFailed(format!("delegation append: {e}")))?;

        // 5. Return a new ChainedToken wrapping the extended biscuit.
        Ok(Self {
            biscuit: new_biscuit,
            issuer_id: self.issuer_id.clone(),
            max_delegation_depth: self.max_delegation_depth,
        })
    }

    /// Authorize a tool invocation against this token chain.
    ///
    /// Provides ambient facts (`tool`, `time`, `depth`) and checks all block
    /// policies. The authority block and each delegation block contain scope
    /// checks of the form `check if tool($t), [allowed].contains($t)`. The
    /// authorizer supplies the requested tool as a `tool(...)` fact, so every
    /// block in the chain must agree the tool is permitted.
    pub fn authorize(&self, tool: &str, root_public_key: &[u8; 32]) -> Result<(), TokenError> {
        // 1. Construct biscuit PublicKey from root_public_key bytes
        let biscuit_pubkey = BiscuitPublicKey::from_bytes(root_public_key, Algorithm::Ed25519)
            .map_err(|e| TokenError::VerificationFailed(format!("public key: {e}")))?;

        // 2. Re-verify the token from serialized form (ensures chain integrity)
        let bytes = self
            .biscuit
            .to_vec()
            .map_err(|e| TokenError::VerificationFailed(format!("serialize for re-verify: {e}")))?;
        let verified = Biscuit::from(&bytes, biscuit_pubkey)
            .map_err(|e| TokenError::VerificationFailed(format!("re-verify: {e}")))?;

        // 3. Build the authorizer with ambient facts and an allow policy.
        //    - tool("tool:search")   -- the tool being requested
        //    - time(2026-03-22T...)  -- current UTC time
        //    - depth(1)             -- current delegation depth
        //    - allow if tool($t)    -- the allow policy (all block checks must pass first)
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
        let depth = self.current_depth();

        let authorizer_code = format!(
            "tool(\"{tool}\");\ntime({now});\ndepth({depth});\nallow if tool(\"{tool}\");\n",
        );

        let mut authorizer = AuthorizerBuilder::new()
            .code(&authorizer_code)
            .map_err(|e| {
                TokenError::ScopeInsufficient(format!("authorizer datalog parse: {e}"))
            })?
            .build(&verified)
            .map_err(|e| {
                TokenError::ScopeInsufficient(format!("authorizer build: {e}"))
            })?;

        // 4. Run authorizer -- evaluates all checks from all blocks + the allow policy
        authorizer.authorize().map_err(|e| {
            TokenError::ScopeInsufficient(format!("authorization denied: {e}"))
        })?;

        Ok(())
    }
}

/// Format a `SystemTime` as an RFC 3339 date-time string suitable for Biscuit Datalog.
fn format_system_time(t: SystemTime) -> String {
    let duration = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time before epoch");
    let secs = duration.as_secs();
    // Convert to a simple RFC 3339 timestamp
    let dt = chrono::DateTime::from_timestamp(secs as i64, 0).expect("valid timestamp");
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Extract the issuer identity and max_depth from the authority block source.
///
/// We parse the printed Datalog source of block 0 to recover these values,
/// which avoids needing a full Authorizer round-trip for simple field access.
fn extract_authority_facts(biscuit: &Biscuit) -> Result<(String, u32), TokenError> {
    let source = biscuit
        .print_block_source(0)
        .map_err(|e| TokenError::TokenMalformed(format!("cannot read authority block: {e}")))?;

    // Parse identity("...") fact
    let issuer = extract_string_fact(&source, "identity").ok_or_else(|| {
        TokenError::TokenMalformed("missing identity fact in authority block".to_string())
    })?;

    // Parse max_depth(...) fact
    let max_depth = extract_int_fact(&source, "max_depth").ok_or_else(|| {
        TokenError::TokenMalformed("missing max_depth fact in authority block".to_string())
    })?;

    Ok((issuer, max_depth as u32))
}

/// Extract a string value from a Datalog fact like `identity("aip:web:example.com/agent");`
fn extract_string_fact(source: &str, fact_name: &str) -> Option<String> {
    for line in source.lines() {
        let trimmed = line.trim();
        let prefix = format!("{fact_name}(\"");
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            if let Some(value) = rest.strip_suffix("\");") {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Extract an integer value from a Datalog fact like `max_depth(3);`
fn extract_int_fact(source: &str, fact_name: &str) -> Option<i64> {
    for line in source.lines() {
        let trimmed = line.trim();
        let prefix = format!("{fact_name}(");
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            if let Some(value_str) = rest.strip_suffix(");") {
                return value_str.parse::<i64>().ok();
            }
        }
    }
    None
}
