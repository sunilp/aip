use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AipClaims {
    pub iss: String,
    pub sub: String,
    pub scope: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_usd: Option<f64>,
    pub max_depth: u32,
    pub iat: i64,
    pub exp: i64,
}
