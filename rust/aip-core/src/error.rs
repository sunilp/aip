use thiserror::Error;

#[derive(Debug, Error)]
pub enum AipError {
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),

    #[error("invalid document: {0}")]
    InvalidDocument(String),

    #[error("signature invalid")]
    SignatureInvalid,

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("document expired")]
    DocumentExpired,

    #[error("version unsupported: {0}")]
    VersionUnsupported(String),

    #[error("resolution failed: {0}")]
    ResolutionFailed(String),

    #[error("serialization error: {0}")]
    SerializationError(String),
}
