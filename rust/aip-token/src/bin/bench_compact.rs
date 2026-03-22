//! Benchmark AIP compact token creation and verification (Rust).

use aip_core::crypto::KeyPair;
use aip_token::claims::AipClaims;
use aip_token::compact::CompactToken;
use std::time::Instant;

fn main() {
    let iterations = 1000;
    let kp = KeyPair::generate();
    let claims = AipClaims {
        iss: "aip:web:bench.test/agent".into(),
        sub: "aip:web:bench.test/tool".into(),
        scope: vec!["tool:search".into(), "tool:browse".into()],
        budget_usd: Some(1.0),
        max_depth: 0,
        iat: 1711100000,
        exp: 4711100000,
    };

    // Warmup
    for _ in 0..100 {
        let t = CompactToken::create(&claims, &kp).unwrap();
        let _ = CompactToken::verify(&t, &kp.public_key_bytes()).unwrap();
    }

    // Measure creation
    let mut create_times = Vec::new();
    let mut token = String::new();
    for _ in 0..iterations {
        let start = Instant::now();
        token = CompactToken::create(&claims, &kp).unwrap();
        create_times.push(start.elapsed().as_nanos() as f64 / 1_000_000.0);
    }

    // Measure verification
    let mut verify_times = Vec::new();
    let pubkey = kp.public_key_bytes();
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = CompactToken::verify(&token, &pubkey).unwrap();
        verify_times.push(start.elapsed().as_nanos() as f64 / 1_000_000.0);
    }

    create_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    verify_times.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let create_mean: f64 = create_times.iter().sum::<f64>() / iterations as f64;
    let verify_mean: f64 = verify_times.iter().sum::<f64>() / iterations as f64;
    let token_size = token.len();

    println!("{{");
    println!("  \"language\": \"rust\",");
    println!("  \"mode\": \"compact\",");
    println!("  \"iterations\": {},", iterations);
    println!("  \"create_mean_ms\": {:.4},", create_mean);
    println!("  \"create_p50_ms\": {:.4},", create_times[iterations / 2]);
    println!("  \"create_p99_ms\": {:.4},", create_times[(0.99 * iterations as f64) as usize]);
    println!("  \"verify_mean_ms\": {:.4},", verify_mean);
    println!("  \"verify_p50_ms\": {:.4},", verify_times[iterations / 2]);
    println!("  \"verify_p99_ms\": {:.4},", verify_times[(0.99 * iterations as f64) as usize]);
    println!("  \"token_size_bytes\": {}", token_size);
    println!("}}");
}
