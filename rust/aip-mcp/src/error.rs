use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct AipErrorResponse {
    pub error: AipErrorBody,
}

#[derive(Serialize, Debug)]
pub struct AipErrorBody {
    pub code: String,
    pub message: String,
}

impl AipErrorResponse {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            error: AipErrorBody {
                code: code.to_string(),
                message: message.to_string(),
            },
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn http_status(&self) -> u16 {
        match self.error.code.as_str() {
            "aip_scope_insufficient" | "aip_budget_exceeded" | "aip_depth_exceeded" => 403,
            _ => 401, // all auth failures
        }
    }
}

/// Token missing from request headers.
pub fn token_missing() -> AipErrorResponse {
    AipErrorResponse::new("aip_token_missing", "X-AIP-Token header is missing")
}

/// Token present but structurally malformed.
pub fn token_malformed(detail: &str) -> AipErrorResponse {
    AipErrorResponse::new(
        "aip_token_malformed",
        &format!("token is malformed: {detail}"),
    )
}

/// Cryptographic signature verification failed.
pub fn signature_invalid() -> AipErrorResponse {
    AipErrorResponse::new("aip_signature_invalid", "token signature is invalid")
}

/// Token has expired (exp claim is in the past).
pub fn token_expired() -> AipErrorResponse {
    AipErrorResponse::new("aip_token_expired", "token has expired")
}

/// Token is valid but lacks the required scope.
pub fn scope_insufficient(scope: &str) -> AipErrorResponse {
    AipErrorResponse::new(
        "aip_scope_insufficient",
        &format!("token lacks required scope: {scope}"),
    )
}

/// Identity in the token could not be resolved.
pub fn identity_unresolvable(detail: &str) -> AipErrorResponse {
    AipErrorResponse::new(
        "aip_identity_unresolvable",
        &format!("identity unresolvable: {detail}"),
    )
}
