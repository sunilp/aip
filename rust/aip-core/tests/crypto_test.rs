use aip_core::crypto::{verify, KeyPair};

#[test]
fn test_keypair_generation() {
    let kp = KeyPair::generate();
    let multibase = kp.public_key_multibase();
    assert!(!multibase.is_empty(), "public_key_multibase must not be empty");
    assert!(multibase.starts_with('z'), "multibase must start with 'z' prefix");
}

#[test]
fn test_sign_and_verify() {
    let kp = KeyPair::generate();
    let message = b"test message";
    let signature = kp.sign(message);
    let pub_bytes = kp.public_key_bytes();

    verify(&pub_bytes, message, &signature).expect("signature should be valid");
}

#[test]
fn test_verify_rejects_tampered_message() {
    let kp = KeyPair::generate();
    let signature = kp.sign(b"hello world");
    let pub_bytes = kp.public_key_bytes();

    let result = verify(&pub_bytes, b"tampered", &signature);
    assert!(result.is_err(), "verification must fail for tampered message");
}

#[test]
fn test_verify_rejects_wrong_key() {
    let kp1 = KeyPair::generate();
    let kp2 = KeyPair::generate();
    let message = b"signed by kp1";
    let signature = kp1.sign(message);
    let wrong_pub = kp2.public_key_bytes();

    let result = verify(&wrong_pub, message, &signature);
    assert!(result.is_err(), "verification must fail with wrong public key");
}

#[test]
fn test_private_key_bytes() {
    let kp = KeyPair::generate();
    let bytes = kp.private_key_bytes();
    assert_eq!(bytes.len(), 32);
}

#[test]
fn test_public_key_multibase_roundtrip() {
    let kp = KeyPair::generate();
    let multibase = kp.public_key_multibase();
    let decoded = KeyPair::decode_multibase(&multibase).expect("decode should succeed");
    let original = kp.public_key_bytes();

    assert_eq!(decoded, original.to_vec(), "roundtrip must preserve public key bytes");
}
