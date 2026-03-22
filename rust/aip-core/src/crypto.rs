use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::error::AipError;

/// An Ed25519 key pair for signing and verification.
pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    /// Generate a new random Ed25519 key pair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Return the 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Return the public key encoded as a multibase z-prefix base58btc string.
    pub fn public_key_multibase(&self) -> String {
        let bytes = self.public_key_bytes();
        format!("z{}", bs58::encode(bytes).into_string())
    }

    /// Decode a multibase z-prefix base58btc string back to raw bytes.
    pub fn decode_multibase(s: &str) -> Result<Vec<u8>, AipError> {
        let rest = s.strip_prefix('z').ok_or_else(|| {
            AipError::InvalidIdentifier(format!(
                "expected multibase z-prefix, got: {}",
                s.chars().next().unwrap_or('?')
            ))
        })?;
        bs58::decode(rest)
            .into_vec()
            .map_err(|e| AipError::InvalidIdentifier(format!("base58btc decode failed: {e}")))
    }

    /// Return the raw 32-byte Ed25519 private key.
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Sign a message, returning the 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature = self.signing_key.sign(message);
        sig.to_bytes().to_vec()
    }
}

/// Verify an Ed25519 signature against a public key and message.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), AipError> {
    let vk_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| AipError::SignatureInvalid)?;
    let verifying_key =
        VerifyingKey::from_bytes(&vk_bytes).map_err(|_| AipError::SignatureInvalid)?;

    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| AipError::SignatureInvalid)?;
    let sig = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(message, &sig)
        .map_err(|_| AipError::SignatureInvalid)
}
