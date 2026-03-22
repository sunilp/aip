use aip_core::crypto::KeyPair;
use aip_mcp::error;
use aip_mcp::middleware::{detect_mode, extract_token, verify_compact, TokenMode};
use aip_token::claims::AipClaims;
use aip_token::compact::CompactToken;

#[test]
fn test_extract_token_found() {
    let headers = vec![
        ("X-AIP-Token", "some.jwt.token"),
        ("Content-Type", "application/json"),
    ];
    assert_eq!(extract_token(&headers).unwrap(), "some.jwt.token");
}

#[test]
fn test_extract_token_missing() {
    let headers = vec![("Content-Type", "application/json")];
    assert!(extract_token(&headers).is_none());
}

#[test]
fn test_extract_token_case_insensitive() {
    let headers = vec![("x-aip-token", "token123")];
    assert_eq!(extract_token(&headers).unwrap(), "token123");
}

#[test]
fn test_detect_compact_mode() {
    assert!(matches!(
        detect_mode("eyJhbGciOiJFZERTQSJ9.payload.sig"),
        TokenMode::Compact
    ));
}

#[test]
fn test_detect_chained_mode() {
    assert!(matches!(detect_mode("En0KEwoE..."), TokenMode::Chained));
}

#[test]
fn test_verify_compact_success() {
    let kp = KeyPair::generate();
    let claims = AipClaims {
        iss: "aip:web:example.com/agent".into(),
        sub: "aip:web:example.com/tool".into(),
        scope: vec!["tool:search".into()],
        budget_usd: Some(1.0),
        max_depth: 0,
        iat: 1711100000,
        exp: 4711100000,
    };
    let token_str = CompactToken::create(&claims, &kp).unwrap();
    let result = verify_compact(&token_str, &kp.public_key_bytes(), "tool:search");
    assert!(result.is_ok());
}

#[test]
fn test_verify_compact_wrong_scope() {
    let kp = KeyPair::generate();
    let claims = AipClaims {
        iss: "aip:web:example.com/agent".into(),
        sub: "aip:web:example.com/tool".into(),
        scope: vec!["tool:search".into()],
        budget_usd: None,
        max_depth: 0,
        iat: 1711100000,
        exp: 4711100000,
    };
    let token_str = CompactToken::create(&claims, &kp).unwrap();
    let result = verify_compact(&token_str, &kp.public_key_bytes(), "tool:email");
    match result {
        Err(err) => {
            assert_eq!(err.error.code, "aip_scope_insufficient");
            assert_eq!(err.http_status(), 403);
        }
        Ok(_) => panic!("expected scope_insufficient error"),
    }
}

#[test]
fn test_verify_compact_bad_signature() {
    let kp = KeyPair::generate();
    let other_kp = KeyPair::generate();
    let claims = AipClaims {
        iss: "aip:web:example.com/agent".into(),
        sub: "aip:web:example.com/tool".into(),
        scope: vec!["tool:search".into()],
        budget_usd: None,
        max_depth: 0,
        iat: 1711100000,
        exp: 4711100000,
    };
    let token_str = CompactToken::create(&claims, &kp).unwrap();
    // Verify with wrong key
    let result = verify_compact(&token_str, &other_kp.public_key_bytes(), "tool:search");
    match result {
        Err(err) => {
            assert_eq!(err.error.code, "aip_signature_invalid");
            assert_eq!(err.http_status(), 401);
        }
        Ok(_) => panic!("expected signature_invalid error"),
    }
}

#[test]
fn test_error_response_json() {
    let err = error::token_missing();
    let json = err.to_json();
    assert!(json.contains("aip_token_missing"));
    assert_eq!(err.http_status(), 401);
}

#[test]
fn test_error_response_403_codes() {
    let err = error::scope_insufficient("tool:admin");
    assert_eq!(err.http_status(), 403);
    assert!(err.to_json().contains("aip_scope_insufficient"));
}

#[test]
fn test_error_response_token_malformed() {
    let err = error::token_malformed("bad base64");
    assert_eq!(err.error.code, "aip_token_malformed");
    assert_eq!(err.http_status(), 401);
}

#[test]
fn test_error_response_identity_unresolvable() {
    let err = error::identity_unresolvable("DNS lookup failed");
    assert_eq!(err.error.code, "aip_identity_unresolvable");
    assert_eq!(err.http_status(), 401);
}
