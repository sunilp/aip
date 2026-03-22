use std::time::{Duration, SystemTime};
use chrono::{DateTime, Utc};

/// Simple policy profile -- generates canonical Datalog from user-specified values.
/// Budget is in integer cents (Biscuit Datalog has no float type).
pub struct SimplePolicy {
    pub tools: Vec<String>,
    pub budget_cents: Option<i64>,
    pub max_depth: Option<u32>,
    pub ttl_seconds: Option<u64>,
}

/// Policy profile enum for all supported profiles.
pub enum PolicyProfile {
    Simple(SimplePolicy),
    Standard(String),   // raw Datalog string
    Advanced(String),   // raw Datalog string
}

impl SimplePolicy {
    /// Generate canonical Datalog. These templates are normative per the AIP spec.
    /// Implementations MUST generate exactly these patterns.
    pub fn to_datalog(&self) -> String {
        let mut rules = Vec::new();

        if !self.tools.is_empty() {
            let tool_list = self.tools.iter()
                .map(|t| format!("\"{}\"", t))
                .collect::<Vec<_>>()
                .join(", ");
            rules.push(format!("check if tool($tool), [{}].contains($tool);", tool_list));
        }

        if let Some(cents) = self.budget_cents {
            rules.push(format!("check if budget($b), $b <= {};", cents));
        }

        if let Some(depth) = self.max_depth {
            rules.push(format!("check if depth($d), $d <= {};", depth));
        }

        if let Some(ttl) = self.ttl_seconds {
            let expiry: DateTime<Utc> = (SystemTime::now() + Duration::from_secs(ttl)).into();
            rules.push(format!("check if time($t), $t <= {};", expiry.format("%Y-%m-%dT%H:%M:%SZ")));
        }

        rules.join("\n")
    }
}

impl PolicyProfile {
    pub fn to_datalog(&self) -> String {
        match self {
            Self::Simple(p) => p.to_datalog(),
            Self::Standard(d) | Self::Advanced(d) => d.clone(),
        }
    }
}
