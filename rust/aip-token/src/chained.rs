use std::time::{Duration, SystemTime};

use biscuit_auth::{
    builder::{Algorithm, BiscuitBuilder},
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
