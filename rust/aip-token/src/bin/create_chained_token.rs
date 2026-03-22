//! Binary that creates a ChainedToken (Biscuit) with one delegation block
//! and prints the result as JSON to stdout.
//!
//! Used by cross-language interop tests.

use aip_core::crypto::KeyPair;
use aip_token::chained::ChainedToken;

fn main() {
    // 1. Generate a root keypair
    let root_kp = KeyPair::generate();

    // 2. Create authority token
    let authority = ChainedToken::create_authority(
        "aip:web:interop.test/rust-root",
        &["tool:search", "tool:browse"],
        Some(500),
        3,
        3600,
        &root_kp,
    )
    .expect("authority token creation must succeed");

    // 3. Append one delegation block
    let delegated = authority
        .delegate(
            "aip:web:interop.test/rust-root",
            "aip:web:interop.test/delegate",
            &["tool:search"],
            Some(100),
            "interop test delegation",
        )
        .expect("delegation must succeed");

    // 4. Serialize and output JSON
    let b64 = delegated.to_base64().expect("base64 serialization must succeed");
    let pubkey_hex = hex::encode(root_kp.public_key_bytes());

    let output = serde_json::json!({
        "token": b64,
        "root_public_key_hex": pubkey_hex,
        "issuer": "aip:web:interop.test/rust-root",
        "depth": 1,
    });

    println!("{}", serde_json::to_string(&output).unwrap());
}
