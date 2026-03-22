use aip_core::crypto::KeyPair;
use aip_token::claims::AipClaims;
use aip_token::compact::CompactToken;

#[test]
fn test_create_and_verify_compact_token() {
    let kp = KeyPair::generate();
    let claims = AipClaims {
        iss: "aip:web:jamjet.dev/agents/orchestrator".into(),
        sub: "aip:web:jamjet.dev/agents/research".into(),
        scope: vec!["tool:search".into(), "tool:browse".into()],
        budget_usd: Some(0.50),
        max_depth: 0,
        iat: 1711100000,
        exp: 4711100000,
    };
    let token_str = CompactToken::create(&claims, &kp).unwrap();
    let verified = CompactToken::verify(&token_str, &kp.public_key_bytes()).unwrap();
    assert_eq!(verified.claims.iss, claims.iss);
    assert_eq!(verified.claims.scope, claims.scope);
}

#[test]
fn test_reject_expired_token() {
    let kp = KeyPair::generate();
    let claims = AipClaims {
        iss: "aip:web:example.com/agent".into(),
        sub: "aip:web:example.com/tool".into(),
        scope: vec![],
        budget_usd: None,
        max_depth: 0,
        iat: 1000000000,
        exp: 1000000001,
    };
    let token_str = CompactToken::create(&claims, &kp).unwrap();
    assert!(CompactToken::verify(&token_str, &kp.public_key_bytes()).is_err());
}

#[test]
fn test_reject_wrong_key() {
    let kp1 = KeyPair::generate();
    let kp2 = KeyPair::generate();
    let claims = AipClaims {
        iss: "aip:web:example.com/a".into(),
        sub: "aip:web:example.com/b".into(),
        scope: vec![],
        budget_usd: None,
        max_depth: 0,
        iat: 1711100000,
        exp: 4711100000,
    };
    let token_str = CompactToken::create(&claims, &kp1).unwrap();
    assert!(CompactToken::verify(&token_str, &kp2.public_key_bytes()).is_err());
}

#[test]
fn test_token_has_correct_typ_header() {
    let kp = KeyPair::generate();
    let claims = AipClaims {
        iss: "aip:web:example.com/a".into(),
        sub: "aip:web:example.com/b".into(),
        scope: vec![],
        budget_usd: None,
        max_depth: 0,
        iat: 1711100000,
        exp: 4711100000,
    };
    let token_str = CompactToken::create(&claims, &kp).unwrap();
    let header = CompactToken::decode_header(&token_str).unwrap();
    assert_eq!(header.typ.as_deref(), Some("aip+jwt"));
    assert_eq!(header.alg, "EdDSA");
}

#[test]
fn test_scope_check() {
    let kp = KeyPair::generate();
    let claims = AipClaims {
        iss: "aip:web:example.com/a".into(),
        sub: "aip:web:example.com/b".into(),
        scope: vec!["tool:search".into(), "tool:browse".into()],
        budget_usd: Some(1.0),
        max_depth: 0,
        iat: 1711100000,
        exp: 4711100000,
    };
    let token_str = CompactToken::create(&claims, &kp).unwrap();
    let verified = CompactToken::verify(&token_str, &kp.public_key_bytes()).unwrap();
    assert!(verified.has_scope("tool:search"));
    assert!(verified.has_scope("tool:browse"));
    assert!(!verified.has_scope("tool:email"));
}
