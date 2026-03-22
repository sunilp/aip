use aip_core::identity::AipId;
use std::str::FromStr;

#[test]
fn test_parse_web_identity() {
    let id = AipId::from_str("aip:web:jamjet.dev/agents/research-analyst").unwrap();
    match id {
        AipId::Web { domain, path } => {
            assert_eq!(domain, "jamjet.dev");
            assert_eq!(path, "agents/research-analyst");
        }
        _ => panic!("expected Web variant"),
    }
}

#[test]
fn test_parse_key_identity() {
    let id = AipId::from_str("aip:key:ed25519:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP").unwrap();
    match id {
        AipId::Key { algorithm, public_key_multibase } => {
            assert_eq!(algorithm, "ed25519");
            assert!(public_key_multibase.starts_with('z'));
        }
        _ => panic!("expected Key variant"),
    }
}

#[test]
fn test_display_roundtrip() {
    let original = "aip:web:jamjet.dev/agents/research-analyst";
    let id = AipId::from_str(original).unwrap();
    assert_eq!(id.to_string(), original);
}

#[test]
fn test_reject_invalid_prefix() {
    assert!(AipId::from_str("did:web:example.com").is_err());
}

#[test]
fn test_reject_empty_path() {
    assert!(AipId::from_str("aip:web:").is_err());
}

#[test]
fn test_resolution_url() {
    let id = AipId::from_str("aip:web:jamjet.dev/agents/research-analyst").unwrap();
    assert_eq!(
        id.resolution_url().unwrap(),
        "https://jamjet.dev/.well-known/aip/agents/research-analyst.json"
    );
}

#[test]
fn test_key_identity_has_no_resolution_url() {
    let id = AipId::from_str("aip:key:ed25519:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP").unwrap();
    assert!(id.resolution_url().is_none());
}
