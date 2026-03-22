use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::{verify, KeyPair};
use crate::error::AipError;

/// An AIP identity document with self-signed integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityDocument {
    pub aip: String,
    pub id: String,
    pub public_keys: Vec<PublicKeyEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<DelegationConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
    pub document_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// Catch-all for unknown fields (forward compatibility).
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// A public key entry within an identity document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyEntry {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String,
    pub public_key_multibase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
}

/// Delegation configuration within an identity document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_ephemeral_grants: Option<bool>,
}

impl IdentityDocument {
    /// Deserialize an identity document from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, AipError> {
        let doc: IdentityDocument = serde_json::from_str(json).map_err(|e| {
            AipError::InvalidDocument(format!("failed to parse document JSON: {e}"))
        })?;

        // Validate required fields
        if doc.aip.is_empty() {
            return Err(AipError::InvalidDocument(
                "aip version field must not be empty".to_string(),
            ));
        }
        if doc.id.is_empty() {
            return Err(AipError::InvalidDocument(
                "id field must not be empty".to_string(),
            ));
        }
        if doc.public_keys.is_empty() {
            return Err(AipError::InvalidDocument(
                "public_keys must contain at least one key".to_string(),
            ));
        }
        if doc.document_signature.is_empty() {
            return Err(AipError::InvalidDocument(
                "document_signature must not be empty".to_string(),
            ));
        }

        Ok(doc)
    }

    /// Compute the canonical JSON representation of this document.
    ///
    /// This produces a JSON string with sorted keys, no whitespace, and the
    /// `document_signature` field removed. Null values are also stripped.
    pub fn canonical_json(&self) -> Result<String, AipError> {
        // Serialize self to a Value
        let val = serde_json::to_value(self).map_err(|e| {
            AipError::SerializationError(format!("failed to serialize document: {e}"))
        })?;

        // Remove document_signature and null values
        let cleaned = strip_signature_and_nulls(&val);

        serde_json::to_string(&cleaned).map_err(|e| {
            AipError::SerializationError(format!("failed to serialize canonical JSON: {e}"))
        })
    }

    /// Verify the document's self-signature against the first public key.
    pub fn verify_signature(&self) -> Result<(), AipError> {
        let first_key = self
            .public_keys
            .first()
            .ok_or_else(|| AipError::KeyNotFound("no public keys in document".to_string()))?;

        // Decode the public key from multibase
        let pub_bytes = KeyPair::decode_multibase(&first_key.public_key_multibase)?;

        // Decode the hex-encoded signature
        let sig_bytes = hex::decode(&self.document_signature)
            .map_err(|_| AipError::SignatureInvalid)?;

        // Compute canonical JSON
        let canonical = self.canonical_json()?;

        // Verify
        verify(&pub_bytes, canonical.as_bytes(), &sig_bytes)
    }

    /// Find the first public key that is valid at the given timestamp.
    ///
    /// A key is valid if `valid_from <= at` and `at < valid_until`.
    /// If `valid_from` is absent, the key is valid from the beginning of time.
    /// If `valid_until` is absent, the key is valid until the end of time.
    pub fn find_valid_key(&self, at: DateTime<Utc>) -> Option<&PublicKeyEntry> {
        self.public_keys.iter().find(|key| {
            let from_ok = match &key.valid_from {
                Some(from_str) => {
                    if let Ok(from) = DateTime::parse_from_rfc3339(from_str) {
                        at >= from.with_timezone(&Utc)
                    } else {
                        false
                    }
                }
                None => true,
            };

            let until_ok = match &key.valid_until {
                Some(until_str) => {
                    if let Ok(until) = DateTime::parse_from_rfc3339(until_str) {
                        at < until.with_timezone(&Utc)
                    } else {
                        false
                    }
                }
                None => true,
            };

            from_ok && until_ok
        })
    }

    /// Check that the document version is supported (major version must be 1).
    pub fn check_version(&self) -> Result<(), AipError> {
        let major = self
            .aip
            .split('.')
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| {
                AipError::VersionUnsupported(format!("cannot parse version: {}", self.aip))
            })?;

        if major > 1 {
            return Err(AipError::VersionUnsupported(format!(
                "major version {} is not supported (max: 1)",
                major
            )));
        }

        Ok(())
    }

    /// Check whether the document has expired as of the given timestamp.
    pub fn is_expired(&self, at: DateTime<Utc>) -> bool {
        match &self.expires {
            Some(expires_str) => {
                if let Ok(expires) = DateTime::parse_from_rfc3339(expires_str) {
                    at >= expires.with_timezone(&Utc)
                } else {
                    // If we cannot parse the date, treat as not expired
                    false
                }
            }
            None => false,
        }
    }
}

/// Remove the `document_signature` key and any null values from a JSON Value.
fn strip_signature_and_nulls(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (k, v) in map {
                if k == "document_signature" {
                    continue;
                }
                if v.is_null() {
                    continue;
                }
                new_map.insert(k.clone(), strip_signature_and_nulls(v));
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(strip_signature_and_nulls).collect()),
        other => other.clone(),
    }
}
