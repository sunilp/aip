"""Benchmark AIP compact token creation and verification (Python)."""
import sys, os, time, json, statistics
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'python'))

from aip_core.crypto import KeyPair
from aip_token.claims import AipClaims
from aip_token.compact import CompactToken

ITERATIONS = 1000

kp = KeyPair.generate()
claims = AipClaims(
    iss="aip:web:bench.test/agent",
    sub="aip:web:bench.test/tool",
    scope=["tool:search", "tool:browse"],
    budget_usd=1.0,
    max_depth=0,
    iat=int(time.time()),
    exp=int(time.time()) + 3600,
)

# Measure creation
create_times = []
for _ in range(ITERATIONS):
    start = time.perf_counter_ns()
    token = CompactToken.create(claims, kp)
    create_times.append((time.perf_counter_ns() - start) / 1_000_000)

# Measure verification
verify_times = []
pubkey = kp.public_key_bytes()
for _ in range(ITERATIONS):
    start = time.perf_counter_ns()
    CompactToken.verify(token, pubkey)
    verify_times.append((time.perf_counter_ns() - start) / 1_000_000)

token_size = len(token.encode('utf-8'))

results = {
    "language": "python",
    "mode": "compact",
    "iterations": ITERATIONS,
    "create_mean_ms": round(statistics.mean(create_times), 4),
    "create_p50_ms": round(statistics.median(create_times), 4),
    "create_p99_ms": round(sorted(create_times)[int(0.99 * ITERATIONS)], 4),
    "verify_mean_ms": round(statistics.mean(verify_times), 4),
    "verify_p50_ms": round(statistics.median(verify_times), 4),
    "verify_p99_ms": round(sorted(verify_times)[int(0.99 * ITERATIONS)], 4),
    "token_size_bytes": token_size,
}
print(json.dumps(results, indent=2))

outdir = os.path.join(os.path.dirname(__file__), 'results')
os.makedirs(outdir, exist_ok=True)
with open(os.path.join(outdir, 'compact_python.json'), 'w') as f:
    json.dump(results, f, indent=2)
