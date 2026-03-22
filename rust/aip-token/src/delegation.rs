/// Metadata for a delegation block (for inspection/audit).
pub struct DelegationBlock {
    pub delegator: String,
    pub delegate: String,
    pub scopes: Vec<String>,
    pub budget_cents: Option<i64>,
    pub context: String,
}
