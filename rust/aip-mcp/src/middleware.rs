use aip_token::chained::ChainedToken;
use aip_token::compact::CompactToken;

use crate::error::{self, AipErrorResponse};

/// Extract the AIP token value from a slice of HTTP headers.
///
/// Performs a case-insensitive search for the `X-AIP-Token` header name.
pub fn extract_token(headers: &[(&str, &str)]) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-aip-token"))
        .map(|(_, v)| v.to_string())
}

/// Indicates whether a token string is a compact (JWT) or chained (Biscuit) token.
pub enum TokenMode {
    Compact,
    Chained,
}

/// Detect whether a token string is compact (JWT) or chained (Biscuit).
///
/// JWTs start with `eyJ` (the base64url encoding of `{"`), so any token
/// beginning with that prefix is treated as compact. Everything else is
/// assumed to be a Biscuit chained token.
pub fn detect_mode(token: &str) -> TokenMode {
    if token.starts_with("eyJ") {
        TokenMode::Compact
    } else {
        TokenMode::Chained
    }
}

/// Verify a compact (JWT) token against a public key and check that it
/// includes the required scope.
///
/// Returns the verified `CompactToken` on success, or an `AipErrorResponse`
/// describing the failure.
pub fn verify_compact(
    token: &str,
    public_key: &[u8; 32],
    required_scope: &str,
) -> Result<CompactToken, AipErrorResponse> {
    let verified = CompactToken::verify(token, public_key).map_err(|e| match e {
        aip_token::error::TokenError::TokenExpired => error::token_expired(),
        aip_token::error::TokenError::SignatureInvalid => error::signature_invalid(),
        _ => error::token_malformed(&e.to_string()),
    })?;

    if !verified.has_scope(required_scope) {
        return Err(error::scope_insufficient(required_scope));
    }

    Ok(verified)
}

/// Verify a chained (Biscuit) token against the root public key and
/// authorize the specified tool invocation.
///
/// Returns the verified `ChainedToken` on success, or an `AipErrorResponse`
/// describing the failure.
pub fn verify_chained(
    token: &str,
    root_public_key: &[u8; 32],
    required_tool: &str,
) -> Result<ChainedToken, AipErrorResponse> {
    let chained = ChainedToken::from_base64(token, root_public_key)
        .map_err(|_| error::signature_invalid())?;

    chained
        .authorize(required_tool, root_public_key)
        .map_err(|_| error::scope_insufficient(required_tool))?;

    Ok(chained)
}
