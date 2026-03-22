//! Binary that generates an Ed25519 keypair, creates an AIP compact token,
//! and prints the result as JSON to stdout.

use aip_core::crypto::KeyPair;
use aip_token::claims::AipClaims;
use aip_token::compact::CompactToken;

fn main() {
    let kp = KeyPair::generate();

    let claims = AipClaims {
        iss: "aip:web:interop.test/rust-agent".into(),
        sub: "aip:web:interop.test/verifier".into(),
        scope: vec!["tool:search".into()],
        budget_usd: Some(1.0),
        max_depth: 0,
        iat: 1_711_100_000,
        exp: 4_102_444_800, // 2099-12-31T00:00:00Z
    };

    let token = CompactToken::create(&claims, &kp).expect("token creation must succeed");
    let pubkey_hex = hex::encode(kp.public_key_bytes());

    let output = serde_json::json!({
        "token": token,
        "public_key_hex": pubkey_hex,
        "iss": claims.iss,
    });

    println!("{}", serde_json::to_string(&output).unwrap());
}
