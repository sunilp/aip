"""Benchmark AIP chained token creation, delegation, and verification (Python)."""
import sys, os, time, json, statistics
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'python'))

ITERATIONS = 100  # fewer iterations since chained ops are heavier

outdir = os.path.join(os.path.dirname(__file__), 'results')
os.makedirs(outdir, exist_ok=True)

try:
    from aip_core.crypto import KeyPair
    from aip_token.chained import ChainedToken
except ImportError:
    print("WARNING: biscuit-python not installed, skipping chained benchmark.")
    results = {"language": "python", "mode": "chained", "skipped": True,
               "reason": "biscuit-python not installed", "depths": []}
    print(json.dumps(results, indent=2))
    with open(os.path.join(outdir, 'chained_python.json'), 'w') as f:
        json.dump(results, f, indent=2)
    sys.exit(0)

MAX_DEPTH = 5

depths = []

for depth in range(MAX_DEPTH + 1):
    create_times = []
    verify_times = []
    token_sizes = []

    for _ in range(ITERATIONS):
        kp = KeyPair.generate()
        pubkey = kp.public_key_bytes()

        # Create authority token (depth 0)
        start = time.perf_counter_ns()
        token = ChainedToken.create_authority(
            issuer="aip:web:bench.test/agent-0",
            scopes=["tool:search", "tool:browse"],
            budget_cents=1000,
            max_depth=MAX_DEPTH,
            ttl_seconds=3600,
            keypair=kp,
        )
        authority_create_ns = time.perf_counter_ns() - start

        # Delegate up to the target depth
        for d in range(1, depth + 1):
            start = time.perf_counter_ns()
            token = token.delegate(
                delegator=f"aip:web:bench.test/agent-{d-1}",
                delegate=f"aip:web:bench.test/agent-{d}",
                scopes=["tool:search"],
                budget_cents=1000,
                context=f"delegation at depth {d}",
            )
            append_ns = time.perf_counter_ns() - start

        if depth == 0:
            create_times.append(authority_create_ns / 1_000_000)
        else:
            create_times.append(append_ns / 1_000_000)

        # Measure token size
        b64 = token.to_base64()
        token_sizes.append(len(b64.encode('utf-8')))

        # Measure verification: from_base64 + authorize
        start = time.perf_counter_ns()
        restored = ChainedToken.from_base64(b64, pubkey)
        restored.authorize("tool:search", pubkey)
        verify_times.append((time.perf_counter_ns() - start) / 1_000_000)

    entry = {
        "depth": depth,
        "token_size_bytes": round(statistics.mean(token_sizes)),
    }

    if depth == 0:
        entry["create_ms"] = round(statistics.mean(create_times), 4)
    else:
        entry["append_ms"] = round(statistics.mean(create_times), 4)

    entry["verify_ms"] = round(statistics.mean(verify_times), 4)

    depths.append(entry)

results = {
    "language": "python",
    "mode": "chained",
    "iterations_per_depth": ITERATIONS,
    "depths": depths,
}
print(json.dumps(results, indent=2))

with open(os.path.join(outdir, 'chained_python.json'), 'w') as f:
    json.dump(results, f, indent=2)
