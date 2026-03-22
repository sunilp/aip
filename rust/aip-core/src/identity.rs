use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::AipError;

/// An AIP identifier, following the `aip:` URI scheme.
///
/// Two variants are supported:
/// - `Web` -- resolved via HTTPS (e.g. `aip:web:jamjet.dev/agents/research-analyst`)
/// - `Key` -- self-certifying, derived from a public key (e.g. `aip:key:ed25519:z6Mkf...`)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AipId {
    Web {
        domain: String,
        path: String,
    },
    Key {
        algorithm: String,
        public_key_multibase: String,
    },
}

impl FromStr for AipId {
    type Err = AipError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Must start with "aip:"
        let rest = s
            .strip_prefix("aip:")
            .ok_or_else(|| AipError::InvalidIdentifier(format!("must start with 'aip:': {s}")))?;

        if let Some(web_part) = rest.strip_prefix("web:") {
            // web_part is everything after "aip:web:"
            if web_part.is_empty() {
                return Err(AipError::InvalidIdentifier(
                    "web identifier must have a non-empty domain/path".to_string(),
                ));
            }

            // Split on first '/' to get domain and path
            if let Some(slash_pos) = web_part.find('/') {
                let domain = &web_part[..slash_pos];
                let path = &web_part[slash_pos + 1..];
                if domain.is_empty() || path.is_empty() {
                    return Err(AipError::InvalidIdentifier(
                        "web identifier must have non-empty domain and path".to_string(),
                    ));
                }
                Ok(AipId::Web {
                    domain: domain.to_string(),
                    path: path.to_string(),
                })
            } else {
                // Domain only, no path segment after '/'
                Ok(AipId::Web {
                    domain: web_part.to_string(),
                    path: String::new(),
                })
            }
        } else if let Some(key_part) = rest.strip_prefix("key:") {
            // key_part is everything after "aip:key:"
            // Format: algorithm:multibase
            let colon_pos = key_part.find(':').ok_or_else(|| {
                AipError::InvalidIdentifier(
                    "key identifier must have format algorithm:multibase".to_string(),
                )
            })?;
            let algorithm = &key_part[..colon_pos];
            let multibase = &key_part[colon_pos + 1..];
            if algorithm.is_empty() || multibase.is_empty() {
                return Err(AipError::InvalidIdentifier(
                    "key identifier must have non-empty algorithm and multibase".to_string(),
                ));
            }
            Ok(AipId::Key {
                algorithm: algorithm.to_string(),
                public_key_multibase: multibase.to_string(),
            })
        } else {
            Err(AipError::InvalidIdentifier(format!(
                "unknown method in identifier: {s}"
            )))
        }
    }
}

impl fmt::Display for AipId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AipId::Web { domain, path } => {
                if path.is_empty() {
                    write!(f, "aip:web:{domain}")
                } else {
                    write!(f, "aip:web:{domain}/{path}")
                }
            }
            AipId::Key {
                algorithm,
                public_key_multibase,
            } => {
                write!(f, "aip:key:{algorithm}:{public_key_multibase}")
            }
        }
    }
}

impl AipId {
    /// Returns the HTTPS resolution URL for Web identifiers.
    ///
    /// For `aip:web:domain/path`, the URL is
    /// `https://{domain}/.well-known/aip/{path}.json`.
    ///
    /// Key identifiers are self-certifying and have no resolution URL.
    pub fn resolution_url(&self) -> Option<String> {
        match self {
            AipId::Web { domain, path } => {
                Some(format!("https://{domain}/.well-known/aip/{path}.json"))
            }
            AipId::Key { .. } => None,
        }
    }
}

impl Serialize for AipId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AipId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        AipId::from_str(&s).map_err(serde::de::Error::custom)
    }
}
