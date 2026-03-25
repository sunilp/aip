"""Experiment 1: Real MCP Tool Chain with AIP Verification.

Measures end-to-end latency of AIP-protected MCP tool calls over actual HTTP,
comparing three conditions:
  A. No auth        -- plain HTTP POST
  B. AIP compact    -- HTTP POST with X-AIP-Token (JWT), server verifies
  C. AIP chained    -- HTTP POST with Biscuit delegation token, server verifies

Uses stdlib http.server on localhost with a random available port.
All measurements include real network stack, header parsing, and token verification.
"""

import sys
import os
import json
import time
import threading
import statistics
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen
from urllib.error import HTTPError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'python'))

from aip_core.crypto import KeyPair
from aip_token.claims import AipClaims
from aip_token.compact import CompactToken

# Check for biscuit-python availability
try:
    from aip_token.chained import ChainedToken
    HAS_BISCUIT = True
except ImportError:
    HAS_BISCUIT = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ITERATIONS = 100
RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')
RESULTS_FILE = os.path.join(RESULTS_DIR, 'exp1_real_mcp.json')

# Pre-generate keys and tokens outside the measurement loop so that
# the experiment measures request-response latency, not key generation.

KEYPAIR = KeyPair.generate()
PUBLIC_KEY_BYTES = KEYPAIR.public_key_bytes()

NOW = int(time.time())
CLAIMS = AipClaims(
    iss="aip:web:exp1.test/orchestrator",
    sub="aip:web:exp1.test/tool-server",
    scope=["tool:search"],
    budget_usd=5.0,
    max_depth=0,
    iat=NOW,
    exp=NOW + 3600,
)
COMPACT_TOKEN_STR = CompactToken.create(CLAIMS, KEYPAIR)

# Pre-create chained token if biscuit is available
CHAINED_TOKEN_B64 = None
if HAS_BISCUIT:
    authority = ChainedToken.create_authority(
        issuer="aip:web:exp1.test/orchestrator",
        scopes=["tool:search", "tool:browse"],
        budget_cents=500,
        max_depth=5,
        ttl_seconds=3600,
        keypair=KEYPAIR,
    )
    delegated = authority.delegate(
        delegator="aip:web:exp1.test/orchestrator",
        delegate="aip:web:exp1.test/agent-1",
        scopes=["tool:search"],
        budget_cents=500,
        context="exp1 delegation hop",
    )
    CHAINED_TOKEN_B64 = delegated.to_base64()

# ---------------------------------------------------------------------------
# MCP Tool Server
# ---------------------------------------------------------------------------

SEARCH_RESPONSE = json.dumps({
    "results": [
        {"title": "Result 1", "url": "https://example.com/1"},
        {"title": "Result 2", "url": "https://example.com/2"},
    ]
}).encode("utf-8")

ERROR_401 = json.dumps({"error": "unauthorized"}).encode("utf-8")
ERROR_403 = json.dumps({"error": "forbidden"}).encode("utf-8")


class MCPToolHandler(BaseHTTPRequestHandler):
    """HTTP handler simulating an MCP tool endpoint with optional AIP auth."""

    def log_message(self, format, *args):
        """Suppress default request logging to avoid polluting output."""
        pass

    def do_POST(self):
        # Read request body (may be empty for this experiment)
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            self.rfile.read(content_length)

        if self.path == "/tools/search":
            # Condition A: no auth -- return immediately
            self._send_json(200, SEARCH_RESPONSE)

        elif self.path == "/tools/search-aip":
            # Condition B: AIP compact token verification
            token_str = self.headers.get("X-AIP-Token")
            if not token_str:
                self._send_json(401, ERROR_401)
                return
            try:
                verified = CompactToken.verify(token_str, PUBLIC_KEY_BYTES)
                if not verified.has_scope("tool:search"):
                    self._send_json(403, ERROR_403)
                    return
                self._send_json(200, SEARCH_RESPONSE)
            except Exception:
                self._send_json(401, ERROR_401)

        elif self.path == "/tools/search-aip-chained":
            # Condition C: AIP chained (Biscuit) token verification
            token_str = self.headers.get("X-AIP-Token")
            if not token_str:
                self._send_json(401, ERROR_401)
                return
            try:
                chained = ChainedToken.from_base64(token_str, PUBLIC_KEY_BYTES)
                chained.authorize("tool:search", PUBLIC_KEY_BYTES)
                self._send_json(200, SEARCH_RESPONSE)
            except Exception:
                self._send_json(401, ERROR_401)

        else:
            self.send_response(404)
            self.end_headers()

    def _send_json(self, status: int, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_server() -> tuple[HTTPServer, int]:
    """Start the MCP tool server on a random available port. Returns (server, port)."""
    server = HTTPServer(("127.0.0.1", 0), MCPToolHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


# ---------------------------------------------------------------------------
# Client: make real HTTP requests and measure latency
# ---------------------------------------------------------------------------

def make_request(url: str, headers: dict | None = None) -> int:
    """Make a POST request and return the HTTP status code."""
    body = json.dumps({"query": "test search"}).encode("utf-8")
    req = Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urlopen(req) as resp:
            resp.read()  # consume body
            return resp.status
    except HTTPError as e:
        return e.code


def measure_condition(url: str, headers: dict | None, iterations: int) -> list[float]:
    """Run iterations of a request and return list of latencies in ms."""
    latencies = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        status = make_request(url, headers)
        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
        assert status == 200, f"Unexpected status {status} from {url}"
        latencies.append(elapsed_ms)
    return latencies


def compute_stats(latencies: list[float]) -> dict:
    """Compute mean, p50, p99 from a list of latency values in ms."""
    latencies_sorted = sorted(latencies)
    return {
        "mean_ms": round(statistics.mean(latencies_sorted), 4),
        "p50_ms": round(statistics.median(latencies_sorted), 4),
        "p99_ms": round(latencies_sorted[int(len(latencies_sorted) * 0.99)], 4),
    }


# ---------------------------------------------------------------------------
# Main experiment
# ---------------------------------------------------------------------------

def run_experiment():
    print("=" * 68)
    print("Experiment 1: Real MCP Tool Chain with AIP Verification")
    print("=" * 68)
    print()

    server, port = start_server()
    base_url = f"http://127.0.0.1:{port}"
    print(f"Server started on port {port}")
    print(f"Iterations per condition: {ITERATIONS}")
    print(f"Biscuit (chained) available: {HAS_BISCUIT}")
    print()

    # Warmup: a few requests to prime the connection
    for _ in range(5):
        make_request(f"{base_url}/tools/search")

    # --- Condition A: No auth ---
    print("Running Condition A: No auth ...")
    no_auth_latencies = measure_condition(
        f"{base_url}/tools/search", None, ITERATIONS
    )
    no_auth_stats = compute_stats(no_auth_latencies)
    print(f"  mean={no_auth_stats['mean_ms']:.4f}ms  "
          f"p50={no_auth_stats['p50_ms']:.4f}ms  "
          f"p99={no_auth_stats['p99_ms']:.4f}ms")

    # --- Condition B: AIP compact ---
    print("Running Condition B: AIP compact ...")
    compact_latencies = measure_condition(
        f"{base_url}/tools/search-aip",
        {"X-AIP-Token": COMPACT_TOKEN_STR},
        ITERATIONS,
    )
    compact_stats = compute_stats(compact_latencies)
    print(f"  mean={compact_stats['mean_ms']:.4f}ms  "
          f"p50={compact_stats['p50_ms']:.4f}ms  "
          f"p99={compact_stats['p99_ms']:.4f}ms")

    # --- Condition C: AIP chained (2-hop) ---
    chained_stats = None
    if HAS_BISCUIT and CHAINED_TOKEN_B64:
        print("Running Condition C: AIP chained (2-hop) ...")
        chained_latencies = measure_condition(
            f"{base_url}/tools/search-aip-chained",
            {"X-AIP-Token": CHAINED_TOKEN_B64},
            ITERATIONS,
        )
        chained_stats = compute_stats(chained_latencies)
        print(f"  mean={chained_stats['mean_ms']:.4f}ms  "
              f"p50={chained_stats['p50_ms']:.4f}ms  "
              f"p99={chained_stats['p99_ms']:.4f}ms")
    else:
        print("Skipping Condition C: biscuit-python not installed.")

    # --- Compute overhead ---
    compact_overhead_ms = compact_stats["mean_ms"] - no_auth_stats["mean_ms"]
    compact_overhead_pct = (compact_overhead_ms / no_auth_stats["mean_ms"]) * 100 if no_auth_stats["mean_ms"] > 0 else 0

    overhead = {
        "compact_vs_noauth_ms": round(compact_overhead_ms, 4),
        "compact_overhead_pct": round(compact_overhead_pct, 2),
    }

    if chained_stats:
        chained_overhead_ms = chained_stats["mean_ms"] - no_auth_stats["mean_ms"]
        chained_overhead_pct = (chained_overhead_ms / no_auth_stats["mean_ms"]) * 100 if no_auth_stats["mean_ms"] > 0 else 0
        overhead["chained_vs_noauth_ms"] = round(chained_overhead_ms, 4)
        overhead["chained_overhead_pct"] = round(chained_overhead_pct, 2)

    # --- Build results ---
    conditions = {
        "no_auth": no_auth_stats,
        "aip_compact": compact_stats,
    }
    if chained_stats:
        conditions["aip_chained"] = chained_stats

    results = {
        "experiment": "real_mcp_tool_chain",
        "iterations": ITERATIONS,
        "conditions": conditions,
        "overhead": overhead,
    }

    # --- Print summary table ---
    print()
    print("-" * 68)
    print(f"{'Condition':<22} {'Mean (ms)':>10} {'P50 (ms)':>10} {'P99 (ms)':>10}")
    print("-" * 68)
    for name, stats in conditions.items():
        print(f"{name:<22} {stats['mean_ms']:>10.4f} {stats['p50_ms']:>10.4f} {stats['p99_ms']:>10.4f}")
    print("-" * 68)
    print()
    print("Overhead (AIP vs no-auth):")
    print(f"  compact:  {overhead['compact_vs_noauth_ms']:+.4f} ms  ({overhead['compact_overhead_pct']:+.2f}%)")
    if chained_stats:
        print(f"  chained:  {overhead['chained_vs_noauth_ms']:+.4f} ms  ({overhead['chained_overhead_pct']:+.2f}%)")
    print()

    # --- Write JSON results ---
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(RESULTS_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Results written to {RESULTS_FILE}")

    # --- Shutdown server ---
    server.shutdown()
    print("Server shut down.")


if __name__ == "__main__":
    run_experiment()
