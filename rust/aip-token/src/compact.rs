use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use aip_core::crypto::KeyPair;

use crate::claims::AipClaims;
use crate::error::TokenError;

/// A verified compact token containing the decoded claims.
pub struct CompactToken {
    pub claims: AipClaims,
}

/// The JWT header used in AIP compact tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    pub alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
}

impl CompactToken {
    /// Create a compact token (JWT) from claims, signed with the given key pair.
    ///
    /// The token format is: base64url(header).base64url(payload).base64url(signature)
    /// Header: {"alg":"EdDSA","typ":"aip+jwt"}
    pub fn create(claims: &AipClaims, keypair: &KeyPair) -> Result<String, TokenError> {
        // 1. Create header JSON
        let header = Header {
            alg: "EdDSA".into(),
            typ: Some("aip+jwt".into()),
        };
        let header_json = serde_json::to_string(&header)
            .map_err(|e| TokenError::CreationFailed(format!("header serialization: {e}")))?;

        // 2. Create payload JSON from claims
        let payload_json = serde_json::to_string(claims)
            .map_err(|e| TokenError::CreationFailed(format!("claims serialization: {e}")))?;

        // 3. Base64url encode both
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        // 4. Sign "header.payload" bytes with keypair
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature_bytes = keypair.sign(signing_input.as_bytes());

        // 5. Base64url encode signature
        let signature_b64 = URL_SAFE_NO_PAD.encode(&signature_bytes);

        // 6. Return "header.payload.signature"
        Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
    }

    /// Verify a compact token against a public key, checking both signature and expiry.
    ///
    /// Returns the verified `CompactToken` with decoded claims on success.
    pub fn verify(token: &str, public_key: &[u8; 32]) -> Result<Self, TokenError> {
        // 1. Split token into 3 parts
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(TokenError::TokenMalformed(format!(
                "expected 3 parts, got {}",
                parts.len()
            )));
        }

        let header_b64 = parts[0];
        let payload_b64 = parts[1];
        let signature_b64 = parts[2];

        // 2. Base64url decode signature
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|e| TokenError::TokenMalformed(format!("signature decode: {e}")))?;

        // 3. Reconstruct VerifyingKey from public_key bytes
        let vk = VerifyingKey::from_bytes(public_key)
            .map_err(|_| TokenError::SignatureInvalid)?;

        // 4. Verify signature over "header.payload"
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| TokenError::TokenMalformed("signature must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&sig_array);
        vk.verify_strict(signing_input.as_bytes(), &sig)
            .map_err(|_| TokenError::SignatureInvalid)?;

        // 5. Parse claims from payload
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| TokenError::TokenMalformed(format!("payload decode: {e}")))?;
        let claims: AipClaims = serde_json::from_slice(&payload_bytes)
            .map_err(|e| TokenError::TokenMalformed(format!("claims parse: {e}")))?;

        // 6. Check expiry against current time
        let now = chrono::Utc::now().timestamp();
        if claims.exp <= now {
            return Err(TokenError::TokenExpired);
        }

        // 7. Return CompactToken with claims
        Ok(Self { claims })
    }

    /// Decode only the header from a compact token string without verifying.
    pub fn decode_header(token: &str) -> Result<Header, TokenError> {
        let header_b64 = token
            .split('.')
            .next()
            .ok_or_else(|| TokenError::TokenMalformed("empty token".into()))?;

        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| TokenError::TokenMalformed(format!("header decode: {e}")))?;

        serde_json::from_slice(&header_bytes)
            .map_err(|e| TokenError::TokenMalformed(format!("header parse: {e}")))
    }

    /// Check whether the verified token's claims include a given scope.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.claims.scope.iter().any(|s| s == scope)
    }
}
