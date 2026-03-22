//! Benchmark AIP chained token creation, delegation, and verification (Rust).

use aip_core::crypto::KeyPair;
use aip_token::chained::ChainedToken;
use std::time::Instant;

const MAX_DEPTH: u32 = 5;
const ITERATIONS: usize = 100;

fn main() {
    println!("{{");
    println!("  \"language\": \"rust\",");
    println!("  \"mode\": \"chained\",");
    println!("  \"iterations_per_depth\": {},", ITERATIONS);
    println!("  \"depths\": [");

    for depth in 0..=MAX_DEPTH {
        let mut create_times = Vec::new();
        let mut verify_times = Vec::new();
        let mut token_sizes = Vec::new();

        for _ in 0..ITERATIONS {
            let kp = KeyPair::generate();
            let pubkey = kp.public_key_bytes();

            // Create authority token (depth 0)
            let start = Instant::now();
            let mut token = ChainedToken::create_authority(
                "aip:web:bench.test/agent-0",
                &["tool:search", "tool:browse"],
                Some(1000),
                MAX_DEPTH,
                3600,
                &kp,
            )
            .unwrap();
            let authority_elapsed = start.elapsed().as_nanos() as f64 / 1_000_000.0;

            // Delegate up to the target depth
            let mut append_elapsed = 0.0;
            for d in 1..=depth {
                let delegator = format!("aip:web:bench.test/agent-{}", d - 1);
                let delegate = format!("aip:web:bench.test/agent-{}", d);
                let context = format!("delegation at depth {}", d);

                let start = Instant::now();
                token = token
                    .delegate(
                        &delegator,
                        &delegate,
                        &["tool:search"],
                        Some(1000),
                        &context,
                    )
                    .unwrap();
                append_elapsed = start.elapsed().as_nanos() as f64 / 1_000_000.0;
            }

            if depth == 0 {
                create_times.push(authority_elapsed);
            } else {
                create_times.push(append_elapsed);
            }

            // Measure token size (base64 length)
            let b64 = token.to_base64().unwrap();
            token_sizes.push(b64.len());

            // Measure verification: from_base64 + authorize
            let start = Instant::now();
            let restored = ChainedToken::from_base64(&b64, &pubkey).unwrap();
            restored.authorize("tool:search", &pubkey).unwrap();
            verify_times.push(start.elapsed().as_nanos() as f64 / 1_000_000.0);
        }

        let avg_create: f64 = create_times.iter().sum::<f64>() / ITERATIONS as f64;
        let avg_verify: f64 = verify_times.iter().sum::<f64>() / ITERATIONS as f64;
        let avg_size: usize = token_sizes.iter().sum::<usize>() / ITERATIONS;

        let comma = if depth < MAX_DEPTH { "," } else { "" };

        if depth == 0 {
            println!(
                "    {{\"depth\": {}, \"token_size_bytes\": {}, \"create_ms\": {:.4}, \"verify_ms\": {:.4}}}{}",
                depth, avg_size, avg_create, avg_verify, comma
            );
        } else {
            println!(
                "    {{\"depth\": {}, \"token_size_bytes\": {}, \"append_ms\": {:.4}, \"verify_ms\": {:.4}}}{}",
                depth, avg_size, avg_create, avg_verify, comma
            );
        }
    }

    println!("  ]");
    println!("}}");
}
