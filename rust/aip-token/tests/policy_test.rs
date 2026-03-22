use aip_token::policy::{PolicyProfile, SimplePolicy};

#[test]
fn test_simple_policy_tool_allowlist() {
    let policy = SimplePolicy {
        tools: vec!["search".into(), "browse".into()],
        budget_cents: None,
        max_depth: None,
        ttl_seconds: None,
    };
    let datalog = policy.to_datalog();
    assert!(datalog.contains(r#"check if tool($tool), ["search", "browse"].contains($tool)"#));
}

#[test]
fn test_simple_policy_budget() {
    let policy = SimplePolicy {
        tools: vec![],
        budget_cents: Some(50),
        max_depth: None,
        ttl_seconds: None,
    };
    let datalog = policy.to_datalog();
    assert!(datalog.contains("check if budget($b), $b <= 50"));
}

#[test]
fn test_simple_policy_depth() {
    let policy = SimplePolicy {
        tools: vec![],
        budget_cents: None,
        max_depth: Some(3),
        ttl_seconds: None,
    };
    let datalog = policy.to_datalog();
    assert!(datalog.contains("check if depth($d), $d <= 3"));
}

#[test]
fn test_simple_policy_full() {
    let policy = SimplePolicy {
        tools: vec!["search".into()],
        budget_cents: Some(100),
        max_depth: Some(3),
        ttl_seconds: Some(3600),
    };
    let datalog = policy.to_datalog();
    assert!(datalog.contains("check if tool($tool)"));
    assert!(datalog.contains("check if budget($b)"));
    assert!(datalog.contains("check if depth($d), $d <= 3"));
    assert!(datalog.contains("check if time($t)"));
}

#[test]
fn test_simple_policy_empty() {
    let policy = SimplePolicy {
        tools: vec![],
        budget_cents: None,
        max_depth: None,
        ttl_seconds: None,
    };
    let datalog = policy.to_datalog();
    assert!(datalog.is_empty());
}

#[test]
fn test_policy_profile_enum() {
    let simple = PolicyProfile::Simple(SimplePolicy {
        tools: vec!["search".into()],
        budget_cents: None,
        max_depth: None,
        ttl_seconds: None,
    });
    let datalog = simple.to_datalog();
    assert!(!datalog.is_empty());
}

#[test]
fn test_standard_profile_passthrough() {
    let standard = PolicyProfile::Standard("check if user($u);".into());
    assert_eq!(standard.to_datalog(), "check if user($u);");
}
