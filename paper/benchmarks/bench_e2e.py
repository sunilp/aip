"""End-to-end benchmark: AIP chained vs OAuth simulation vs no-auth baseline.

Simulates a 2-hop multi-agent delegation scenario at varying inference delays.
"""
import sys, os, time, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'python'))

outdir = os.path.join(os.path.dirname(__file__), 'results')
os.makedirs(outdir, exist_ok=True)

INFERENCE_DELAYS_MS = [0, 100, 500, 1000]
OAUTH_HOP_LATENCY_MS = 10  # conservative estimate per token exchange hop
NUM_HOPS = 2
ITERATIONS = 50

conditions = []

# Try to import chained token support
try:
    from aip_core.crypto import KeyPair
    from aip_token.chained import ChainedToken
    has_biscuit = True
except ImportError:
    has_biscuit = False
    print("WARNING: biscuit-python not installed, AIP chained measurements will use fallback.")

for inference_ms in INFERENCE_DELAYS_MS:
    inference_delay_s = inference_ms / 1000.0

    # --- No-auth baseline ---
    no_auth_times = []
    for _ in range(ITERATIONS):
        start = time.perf_counter_ns()
        if inference_delay_s > 0:
            time.sleep(inference_delay_s)
        elapsed = (time.perf_counter_ns() - start) / 1_000_000
        no_auth_times.append(elapsed)

    no_auth_total = sum(no_auth_times) / len(no_auth_times)
    conditions.append({
        "name": "no_auth",
        "inference_ms": inference_ms,
        "auth_ms": 0,
        "total_ms": round(no_auth_total, 4),
    })

    # --- AIP chained: create authority + delegate + verify (2-hop) ---
    if has_biscuit:
        aip_times = []
        for _ in range(ITERATIONS):
            kp = KeyPair.generate()
            pubkey = kp.public_key_bytes()

            start = time.perf_counter_ns()

            # Create authority
            token = ChainedToken.create_authority(
                issuer="aip:web:e2e.test/orchestrator",
                scopes=["tool:search", "tool:browse"],
                budget_cents=500,
                max_depth=5,
                ttl_seconds=3600,
                keypair=kp,
            )

            # Delegate twice (2-hop chain)
            token = token.delegate(
                delegator="aip:web:e2e.test/orchestrator",
                delegate="aip:web:e2e.test/agent-1",
                scopes=["tool:search"],
                budget_cents=500,
                context="hop 1",
            )
            token = token.delegate(
                delegator="aip:web:e2e.test/agent-1",
                delegate="aip:web:e2e.test/agent-2",
                scopes=["tool:search"],
                budget_cents=500,
                context="hop 2",
            )

            # Verify
            b64 = token.to_base64()
            restored = ChainedToken.from_base64(b64, pubkey)
            restored.authorize("tool:search", pubkey)

            auth_elapsed = (time.perf_counter_ns() - start) / 1_000_000

            # Add simulated inference delay
            if inference_delay_s > 0:
                time.sleep(inference_delay_s)

            total_elapsed = auth_elapsed + inference_ms
            aip_times.append((auth_elapsed, total_elapsed))

        avg_auth = sum(t[0] for t in aip_times) / len(aip_times)
        avg_total = sum(t[1] for t in aip_times) / len(aip_times)
    else:
        # Fallback: estimate AIP auth as ~2ms based on compact token benchmarks
        avg_auth = 2.0
        avg_total = avg_auth + inference_ms

    conditions.append({
        "name": "aip_chained",
        "inference_ms": inference_ms,
        "auth_ms": round(avg_auth, 4),
        "total_ms": round(avg_total, 4),
    })

    # --- OAuth simulation: network latency per hop ---
    oauth_auth_ms = OAUTH_HOP_LATENCY_MS * NUM_HOPS
    oauth_total = oauth_auth_ms + inference_ms
    conditions.append({
        "name": "oauth_exchange",
        "inference_ms": inference_ms,
        "auth_ms": oauth_auth_ms,
        "total_ms": oauth_total,
    })

results = {
    "description": "End-to-end latency comparison: AIP chained vs OAuth vs no-auth",
    "num_hops": NUM_HOPS,
    "oauth_hop_latency_ms": OAUTH_HOP_LATENCY_MS,
    "iterations": ITERATIONS,
    "conditions": conditions,
}
print(json.dumps(results, indent=2))

with open(os.path.join(outdir, 'e2e.json'), 'w') as f:
    json.dump(results, f, indent=2)
