use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("token creation failed: {0}")]
    CreationFailed(String),
    #[error("token verification failed: {0}")]
    VerificationFailed(String),
    #[error("token expired")]
    TokenExpired,
    #[error("signature invalid")]
    SignatureInvalid,
    #[error("scope insufficient: {0}")]
    ScopeInsufficient(String),
    #[error("budget exceeded")]
    BudgetExceeded,
    #[error("depth exceeded")]
    DepthExceeded,
    #[error("token malformed: {0}")]
    TokenMalformed(String),
    #[error("identity unresolvable: {0}")]
    IdentityUnresolvable(String),
    #[error("key revoked")]
    KeyRevoked,
}

impl TokenError {
    pub fn error_code(&self) -> &str {
        match self {
            Self::CreationFailed(_) => "aip_token_malformed",
            Self::VerificationFailed(_) => "aip_signature_invalid",
            Self::TokenExpired => "aip_token_expired",
            Self::SignatureInvalid => "aip_signature_invalid",
            Self::ScopeInsufficient(_) => "aip_scope_insufficient",
            Self::BudgetExceeded => "aip_budget_exceeded",
            Self::DepthExceeded => "aip_depth_exceeded",
            Self::TokenMalformed(_) => "aip_token_malformed",
            Self::IdentityUnresolvable(_) => "aip_identity_unresolvable",
            Self::KeyRevoked => "aip_key_revoked",
        }
    }
}
