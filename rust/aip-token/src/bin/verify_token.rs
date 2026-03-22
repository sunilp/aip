//! Binary that verifies an AIP compact token given as CLI arguments.
//!
//! Usage: verify_token <token_string> <public_key_hex>
//!
//! Exits 0 on success (prints "OK" to stderr).
//! Exits 1 on failure (prints error message to stderr).

use aip_token::compact::CompactToken;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: verify_token <token> <public_key_hex>");
        std::process::exit(1);
    }

    let token_str = &args[1];
    let pubkey_hex = &args[2];

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

    match CompactToken::verify(token_str, &pubkey_array) {
        Ok(_) => {
            eprintln!("OK");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
