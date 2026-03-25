"""Experiment 3: Multi-Agent Delegation with Real LLM Inference.

Runs a real orchestrator -> specialist -> tool chain with actual LLM
inference (Google Gemini), measuring what percentage of total end-to-end
time is AIP protocol overhead vs LLM inference.

The 2-hop delegation flow:
  Step 1: Orchestrator creates AIP authority token, calls LLM to decide
          on delegation, then delegates token to specialist.
  Step 2: Specialist receives delegated token, calls LLM to process,
          then verifies AIP authorization for tool:search.
  Step 3: Mock tool endpoint verifies chained token and returns results.

Key finding: AIP overhead should be <1% of total when real LLM inference
dominates the latency budget.
"""

import sys
import os
import json
import time
import statistics
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'python'))

from aip_core.crypto import KeyPair
from aip_token.claims import AipClaims
from aip_token.compact import CompactToken

# ---------------------------------------------------------------------------
# Load API keys from the DCI research .env file
# ---------------------------------------------------------------------------

_ENV_PATH = "/Users/sunilp/Development/sunil-ws/dci-research/.env"

if os.path.exists(_ENV_PATH):
    with open(_ENV_PATH) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ[_k] = _v

GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ITERATIONS = 10

# Try multiple model/API version combinations in order of preference
_GEMINI_CANDIDATES = [
    ("gemini-2.0-flash", "v1beta"),
    ("gemini-2.0-flash", "v1"),
    ("gemini-1.5-flash", "v1beta"),
    ("gemini-1.5-flash", "v1"),
]

MODEL = "gemini-2.0-flash"  # updated during probe
GEMINI_URL = ""              # set during probe

RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')
RESULTS_FILE = os.path.join(RESULTS_DIR, 'exp3_real_llm.json')

# Orchestrator prompt
ORCHESTRATOR_PROMPT = (
    "You are a research orchestrator. Given the query "
    "'What is the Agent Identity Protocol?', respond with exactly: "
    "DELEGATE to search specialist"
)

# Specialist prompt
SPECIALIST_PROMPT = (
    "You are a search specialist. Summarize in one sentence what you "
    "know about agent identity protocols for AI systems."
)

# Mock tool response
TOOL_RESPONSE = {
    "results": [
        {"title": "Agent Identity Protocol Spec", "url": "https://aip.dev/spec"},
        {"title": "AIP Reference Implementation", "url": "https://github.com/aip"},
    ]
}

# ---------------------------------------------------------------------------
# Gemini API helper
# ---------------------------------------------------------------------------

USE_SIMULATION = False


def _discover_flash_model() -> str:
    """Query the Gemini API to find an available flash model.

    Returns the model name (e.g. 'gemini-2.0-flash-001') or '' if none found.
    """
    list_url = (
        f"https://generativelanguage.googleapis.com/v1beta/models"
        f"?key={GOOGLE_API_KEY}"
    )
    req = Request(list_url, method="GET")
    try:
        with urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            models = body.get("models", [])
            # Prefer flash models that support generateContent
            for m in models:
                name = m.get("name", "")
                methods = m.get("supportedGenerationMethods", [])
                if "flash" in name.lower() and "generateContent" in methods:
                    # name is like "models/gemini-2.0-flash-001", strip prefix
                    return name.replace("models/", "")
    except Exception:
        pass
    return ""


def _probe_gemini_endpoint() -> tuple[str, str]:
    """Try each model/version combination and return the first that works.

    First tries discovering available models via the API, then falls back
    to the hardcoded candidate list.

    Returns (model_name, working_url) or ("", "") if none work.
    """
    # Phase 1: discover available flash model from the API
    discovered = _discover_flash_model()
    if discovered:
        candidates = [(discovered, "v1beta")] + _GEMINI_CANDIDATES
    else:
        candidates = list(_GEMINI_CANDIDATES)

    probe_payload = json.dumps({
        "contents": [{"parts": [{"text": "Say hello"}]}],
        "generationConfig": {"maxOutputTokens": 5},
    }).encode("utf-8")

    for model_name, api_version in candidates:
        url = (
            f"https://generativelanguage.googleapis.com/{api_version}"
            f"/models/{model_name}:generateContent?key={GOOGLE_API_KEY}"
        )
        req = Request(url, data=probe_payload, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urlopen(req, timeout=15) as resp:
                if resp.status == 200:
                    resp.read()  # consume body
                    return model_name, url
        except Exception:
            continue
    return "", ""


def call_gemini(prompt: str) -> str:
    """Call Google Gemini API with a simple prompt. Returns the text response.

    Falls back to simulation if the API is unreachable or returns an error.
    """
    global USE_SIMULATION

    if USE_SIMULATION:
        time.sleep(0.1)
        return "[simulated response]"

    payload = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.0,
            "maxOutputTokens": 100,
        },
    }).encode("utf-8")

    req = Request(GEMINI_URL, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")

    try:
        with urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            # Extract text from the Gemini response
            candidates = body.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "")
            return ""
    except (HTTPError, URLError, Exception) as exc:
        print(f"  [WARNING] Gemini API call failed: {exc}")
        print("  [WARNING] Falling back to simulated LLM calls (100ms sleep)")
        USE_SIMULATION = True
        time.sleep(0.1)
        return "[simulated response - API fallback]"


# ---------------------------------------------------------------------------
# AIP operations
# ---------------------------------------------------------------------------

def create_authority_token(keypair: KeyPair) -> tuple[str, float]:
    """Create an AIP authority token. Returns (token_string, elapsed_ms)."""
    now = int(time.time())
    claims = AipClaims(
        iss="aip:web:exp3.test/orchestrator",
        sub="aip:web:exp3.test/specialist",
        scope=["tool:search"],
        budget_usd=5.0,
        max_depth=3,
        iat=now,
        exp=now + 3600,
    )
    start = time.perf_counter_ns()
    token_str = CompactToken.create(claims, keypair)
    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
    return token_str, elapsed_ms


def delegate_token(keypair: KeyPair) -> tuple[str, float]:
    """Delegate an AIP token (create a new attenuated compact token).

    In compact mode, delegation means issuing a new token with reduced
    scopes/budget. Returns (delegated_token_string, elapsed_ms).
    """
    now = int(time.time())
    delegated_claims = AipClaims(
        iss="aip:web:exp3.test/orchestrator",
        sub="aip:web:exp3.test/specialist",
        scope=["tool:search"],
        budget_usd=1.0,  # Attenuated from 5.0
        max_depth=2,     # Reduced from 3
        iat=now,
        exp=now + 3600,
    )
    start = time.perf_counter_ns()
    token_str = CompactToken.create(delegated_claims, keypair)
    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
    return token_str, elapsed_ms


def verify_token(token_str: str, pubkey_bytes: bytes) -> float:
    """Verify an AIP compact token. Returns elapsed_ms."""
    start = time.perf_counter_ns()
    verified = CompactToken.verify(token_str, pubkey_bytes)
    # Also check scope authorization
    assert verified.has_scope("tool:search"), "Scope check failed"
    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
    return elapsed_ms


# ---------------------------------------------------------------------------
# Single iteration: full 2-hop delegation chain
# ---------------------------------------------------------------------------

def run_single_iteration(
    keypair: KeyPair, pubkey_bytes: bytes, iteration: int
) -> dict:
    """Run one full orchestrator -> specialist -> tool chain.

    Returns a dict with all timing measurements.
    """
    total_start = time.perf_counter_ns()

    # ---- Step 1: Orchestrator creates authority token + calls LLM ----

    # Create AIP authority token
    authority_token, aip_create_ms = create_authority_token(keypair)

    # Orchestrator LLM call: decide to delegate
    llm_orch_start = time.perf_counter_ns()
    orch_response = call_gemini(ORCHESTRATOR_PROMPT)
    llm_orchestrator_ms = (time.perf_counter_ns() - llm_orch_start) / 1_000_000

    # Delegate token to specialist (attenuated)
    delegated_token, aip_delegate_ms = delegate_token(keypair)

    # ---- Step 2: Specialist receives token, calls LLM, verifies ----

    # Specialist LLM call: process the task
    llm_spec_start = time.perf_counter_ns()
    spec_response = call_gemini(SPECIALIST_PROMPT)
    llm_specialist_ms = (time.perf_counter_ns() - llm_spec_start) / 1_000_000

    # Verify delegated token at specialist
    verify_specialist_ms = verify_token(delegated_token, pubkey_bytes)

    # ---- Step 3: Tool endpoint verifies the token chain ----

    # Verify token again at the tool endpoint (simulating tool-side check)
    verify_tool_ms = verify_token(delegated_token, pubkey_bytes)

    # Total verification time
    aip_verify_ms = verify_specialist_ms + verify_tool_ms

    total_ms = (time.perf_counter_ns() - total_start) / 1_000_000

    # Compute overhead
    aip_total_ms = aip_create_ms + aip_delegate_ms + aip_verify_ms
    aip_overhead_pct = (aip_total_ms / total_ms) * 100 if total_ms > 0 else 0

    return {
        "iteration": iteration,
        "aip_create_ms": round(aip_create_ms, 4),
        "aip_delegate_ms": round(aip_delegate_ms, 4),
        "aip_verify_ms": round(aip_verify_ms, 4),
        "llm_orchestrator_ms": round(llm_orchestrator_ms, 4),
        "llm_specialist_ms": round(llm_specialist_ms, 4),
        "total_ms": round(total_ms, 4),
        "aip_overhead_pct": round(aip_overhead_pct, 4),
    }


# ---------------------------------------------------------------------------
# Main experiment
# ---------------------------------------------------------------------------

def run_experiment():
    global MODEL, GEMINI_URL, USE_SIMULATION

    print("=" * 72)
    print("Experiment 3: Multi-Agent Delegation with Real LLM Inference")
    print("=" * 72)
    print()

    if not GOOGLE_API_KEY:
        print("[WARNING] GOOGLE_API_KEY not found. Using simulated LLM calls.")
        USE_SIMULATION = True
    else:
        # Probe for a working Gemini endpoint
        print("Probing Gemini API endpoints ...")
        found_model, found_url = _probe_gemini_endpoint()
        if found_model:
            MODEL = found_model
            GEMINI_URL = found_url
            print(f"  Found working endpoint: {MODEL}")
        else:
            print("  [WARNING] No working Gemini endpoint found.")
            print("  [WARNING] Falling back to simulated LLM calls (100ms sleep)")
            USE_SIMULATION = True

    model_label = MODEL

    # Pre-generate keys (not part of the measurement)
    keypair = KeyPair.generate()
    pubkey_bytes = keypair.public_key_bytes()

    print(f"Model:      {MODEL}")
    print(f"Iterations: {ITERATIONS}")
    print(f"API Key:    {'present' if GOOGLE_API_KEY else 'MISSING'}")
    print()

    # Warmup: one LLM call to prime the connection
    if not USE_SIMULATION:
        print("Warming up Gemini API ...")
        warmup_resp = call_gemini("Say 'ready' in one word.")
    else:
        warmup_resp = ""
    if USE_SIMULATION:
        model_label = "simulated_100ms"
        print("[WARNING] Using simulated LLM calls (100ms sleep per call)")
    else:
        print(f"Warmup response: {warmup_resp.strip()[:50]}")
    print()

    # Run iterations
    results = []
    for i in range(1, ITERATIONS + 1):
        print(f"Iteration {i}/{ITERATIONS} ...", end=" ", flush=True)
        r = run_single_iteration(keypair, pubkey_bytes, i)
        results.append(r)
        print(
            f"total={r['total_ms']:.1f}ms  "
            f"aip={r['aip_create_ms'] + r['aip_delegate_ms'] + r['aip_verify_ms']:.3f}ms  "
            f"llm_orch={r['llm_orchestrator_ms']:.1f}ms  "
            f"llm_spec={r['llm_specialist_ms']:.1f}ms  "
            f"overhead={r['aip_overhead_pct']:.4f}%"
        )

    # Compute summary statistics
    aip_totals = [
        r["aip_create_ms"] + r["aip_delegate_ms"] + r["aip_verify_ms"]
        for r in results
    ]
    llm_totals = [
        r["llm_orchestrator_ms"] + r["llm_specialist_ms"]
        for r in results
    ]
    total_totals = [r["total_ms"] for r in results]
    overhead_pcts = [r["aip_overhead_pct"] for r in results]

    summary = {
        "mean_total_ms": round(statistics.mean(total_totals), 4),
        "mean_aip_ms": round(statistics.mean(aip_totals), 4),
        "mean_llm_ms": round(statistics.mean(llm_totals), 4),
        "mean_aip_overhead_pct": round(statistics.mean(overhead_pcts), 4),
        "p50_aip_overhead_pct": round(statistics.median(overhead_pcts), 4),
        "p99_aip_overhead_pct": round(
            sorted(overhead_pcts)[int(len(overhead_pcts) * 0.99)], 4
        ),
    }

    output = {
        "experiment": "real_llm_multi_agent",
        "model": model_label,
        "iterations": ITERATIONS,
        "results": results,
        "summary": summary,
    }

    # Write JSON results
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(RESULTS_FILE, 'w') as f:
        json.dump(output, f, indent=2)

    # Print summary table
    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print()
    print(f"Model:              {model_label}")
    print(f"Iterations:         {ITERATIONS}")
    print()

    header = (
        f"{'Metric':<28} {'Mean':>12} {'P50':>12} {'P99':>12}"
    )
    print(header)
    print("-" * len(header))

    mean_aip = summary["mean_aip_ms"]
    mean_llm = summary["mean_llm_ms"]
    mean_total = summary["mean_total_ms"]

    p50_aip = round(statistics.median(aip_totals), 4)
    p50_llm = round(statistics.median(llm_totals), 4)
    p50_total = round(statistics.median(total_totals), 4)

    p99_idx = int(len(results) * 0.99)
    sorted_aip = sorted(aip_totals)
    sorted_llm = sorted(llm_totals)
    sorted_total = sorted(total_totals)

    p99_aip = round(sorted_aip[p99_idx], 4)
    p99_llm = round(sorted_llm[p99_idx], 4)
    p99_total = round(sorted_total[p99_idx], 4)

    print(f"{'AIP overhead (ms)':<28} {mean_aip:>12.4f} {p50_aip:>12.4f} {p99_aip:>12.4f}")
    print(f"{'LLM inference (ms)':<28} {mean_llm:>12.4f} {p50_llm:>12.4f} {p99_llm:>12.4f}")
    print(f"{'Total end-to-end (ms)':<28} {mean_total:>12.4f} {p50_total:>12.4f} {p99_total:>12.4f}")
    print("-" * len(header))
    print(
        f"{'AIP overhead (%)':<28} "
        f"{summary['mean_aip_overhead_pct']:>11.4f}% "
        f"{summary['p50_aip_overhead_pct']:>11.4f}% "
        f"{summary['p99_aip_overhead_pct']:>11.4f}%"
    )
    print()

    # Per-iteration detail table
    print("-" * 72)
    print(f"{'Iter':>4}  {'AIP (ms)':>10}  {'LLM Orch':>10}  {'LLM Spec':>10}  "
          f"{'Total':>10}  {'Overhead':>10}")
    print("-" * 72)
    for r in results:
        aip_ms = r["aip_create_ms"] + r["aip_delegate_ms"] + r["aip_verify_ms"]
        print(
            f"{r['iteration']:>4}  "
            f"{aip_ms:>10.4f}  "
            f"{r['llm_orchestrator_ms']:>10.1f}  "
            f"{r['llm_specialist_ms']:>10.1f}  "
            f"{r['total_ms']:>10.1f}  "
            f"{r['aip_overhead_pct']:>9.4f}%"
        )
    print("-" * 72)
    print()

    print(f"Results written to {RESULTS_FILE}")
    print()


if __name__ == "__main__":
    run_experiment()
