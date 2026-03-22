use aip_core::crypto::KeyPair;
use aip_token::chained::ChainedToken;

#[test]
fn test_create_authority_block() {
    let root_kp = KeyPair::generate();
    let token = ChainedToken::create_authority(
        "aip:web:jamjet.dev/agents/orchestrator",
        &["tool:*", "delegate:*"],
        Some(500),
        3,
        3600,
        &root_kp,
    )
    .unwrap();
    assert_eq!(token.issuer(), "aip:web:jamjet.dev/agents/orchestrator");
    assert_eq!(token.max_depth(), 3);
    assert_eq!(token.current_depth(), 0);
}

#[test]
fn test_serialize_deserialize_authority() {
    let root_kp = KeyPair::generate();
    let token = ChainedToken::create_authority(
        "aip:web:example.com/agent",
        &["tool:search"],
        None,
        3,
        3600,
        &root_kp,
    )
    .unwrap();
    let bytes = token.to_bytes().unwrap();
    let restored = ChainedToken::from_bytes(&bytes, &root_kp.public_key_bytes()).unwrap();
    assert_eq!(restored.issuer(), "aip:web:example.com/agent");
}

#[test]
fn test_base64_roundtrip() {
    let root_kp = KeyPair::generate();
    let token = ChainedToken::create_authority(
        "aip:web:example.com/agent",
        &["tool:search"],
        Some(100),
        2,
        3600,
        &root_kp,
    )
    .unwrap();
    let b64 = token.to_base64().unwrap();
    let restored = ChainedToken::from_base64(&b64, &root_kp.public_key_bytes()).unwrap();
    assert_eq!(restored.issuer(), "aip:web:example.com/agent");
    assert_eq!(restored.max_depth(), 2);
}

#[test]
fn test_reject_wrong_root_key() {
    let root_kp = KeyPair::generate();
    let wrong_kp = KeyPair::generate();
    let token = ChainedToken::create_authority(
        "aip:web:example.com/agent",
        &["tool:search"],
        None,
        3,
        3600,
        &root_kp,
    )
    .unwrap();
    let bytes = token.to_bytes().unwrap();
    assert!(ChainedToken::from_bytes(&bytes, &wrong_kp.public_key_bytes()).is_err());
}

// ── Delegation tests ──

#[test]
fn test_append_delegation_block() {
    let root_kp = KeyPair::generate();
    let token = ChainedToken::create_authority(
        "aip:web:jamjet.dev/orchestrator",
        &["tool:search", "tool:browse", "tool:email"],
        Some(500),
        3,
        3600,
        &root_kp,
    )
    .unwrap();

    let delegated = token
        .delegate(
            "aip:web:jamjet.dev/orchestrator",
            "aip:web:jamjet.dev/research-analyst",
            &["tool:search", "tool:browse"],
            Some(50),
            "research subtask for query X",
        )
        .unwrap();

    assert_eq!(delegated.current_depth(), 1);
}

#[test]
fn test_delegation_chain_three_hops() {
    let root_kp = KeyPair::generate();
    let token = ChainedToken::create_authority(
        "aip:web:example.com/root",
        &["tool:*"],
        Some(500),
        3,
        3600,
        &root_kp,
    )
    .unwrap();

    let t1 = token
        .delegate(
            "aip:web:example.com/root",
            "aip:web:example.com/agent-a",
            &["tool:search", "tool:browse"],
            Some(200),
            "delegate to agent a",
        )
        .unwrap();

    let t2 = t1
        .delegate(
            "aip:web:example.com/agent-a",
            "aip:web:example.com/agent-b",
            &["tool:search"],
            Some(50),
            "delegate to agent b",
        )
        .unwrap();

    assert_eq!(t2.current_depth(), 2);
}

#[test]
fn test_reject_delegation_exceeding_max_depth() {
    let root_kp = KeyPair::generate();
    let token = ChainedToken::create_authority(
        "aip:web:example.com/root",
        &["tool:search"],
        None,
        1,
        3600,
        &root_kp,
    )
    .unwrap();

    let t1 = token
        .delegate(
            "aip:web:example.com/root",
            "aip:web:example.com/a",
            &["tool:search"],
            None,
            "first delegation",
        )
        .unwrap();

    let result = t1.delegate(
        "aip:web:example.com/a",
        "aip:web:example.com/b",
        &["tool:search"],
        None,
        "second delegation",
    );
    assert!(result.is_err());
}

#[test]
fn test_reject_empty_context() {
    let root_kp = KeyPair::generate();
    let token = ChainedToken::create_authority(
        "aip:web:example.com/root",
        &["tool:search"],
        None,
        3,
        3600,
        &root_kp,
    )
    .unwrap();

    let result = token.delegate(
        "aip:web:example.com/root",
        "aip:web:example.com/delegate",
        &["tool:search"],
        None,
        "",
    );
    assert!(result.is_err());
}

#[test]
fn test_delegated_token_serialization() {
    let root_kp = KeyPair::generate();
    let token = ChainedToken::create_authority(
        "aip:web:example.com/root",
        &["tool:search"],
        Some(100),
        3,
        3600,
        &root_kp,
    )
    .unwrap();

    let delegated = token
        .delegate(
            "aip:web:example.com/root",
            "aip:web:example.com/worker",
            &["tool:search"],
            Some(50),
            "search task",
        )
        .unwrap();

    let b64 = delegated.to_base64().unwrap();
    let restored = ChainedToken::from_base64(&b64, &root_kp.public_key_bytes()).unwrap();
    assert_eq!(restored.current_depth(), 1);
    assert_eq!(restored.issuer(), "aip:web:example.com/root");
}
