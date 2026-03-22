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
