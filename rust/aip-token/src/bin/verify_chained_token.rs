//! Binary that verifies a ChainedToken (Biscuit) and authorizes a tool invocation.
//!
//! Usage: verify_chained_token <base64_token> <root_public_key_hex> <tool_name>
//!
//! Exits 0 on success (prints "OK" to stderr).
//! Exits 1 on failure (prints error message to stderr).

use aip_token::chained::ChainedToken;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: verify_chained_token <base64_token> <root_public_key_hex> <tool_name>");
        std::process::exit(1);
    }

    let token_b64 = &args[1];
    let pubkey_hex = &args[2];
    let tool_name = &args[3];

    // Decode public key from hex
    let pubkey_bytes = match hex::decode(pubkey_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("invalid hex for public key: {e}");
            std::process::exit(1);
        }
    };

    let pubkey_array: [u8; 32] = match pubkey_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("public key must be exactly 32 bytes");
            std::process::exit(1);
        }
    };

    // Deserialize and verify the chained token
    let token = match ChainedToken::from_base64(token_b64, &pubkey_array) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("token deserialization failed: {e}");
            std::process::exit(1);
        }
    };

    // Authorize the tool invocation
    match token.authorize(tool_name, &pubkey_array) {
        Ok(()) => {
            eprintln!("OK");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("authorization failed: {e}");
            std::process::exit(1);
        }
    }
}
