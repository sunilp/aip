#!/usr/bin/env python3
"""Orchestrator that demonstrates a 3-hop AIP delegation chain.

This single script plays all three roles for simplicity:

  1. **Root / Human-System** -- generates the root keypair and creates an
     authority token with broad permissions.
  2. **Orchestrator** -- delegates an attenuated token to a specialist
     (narrowed scope and budget).
  3. **Specialist** -- calls the tool server with the chained token.

The tool server (tool_server.py) must be running on port 8341 before
this script is executed.

Usage:
  python examples/multi-agent-delegation/orchestrator.py
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# Make the AIP SDK importable when running from the repo root.
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "python"))

# ---------------------------------------------------------------------------
# Check for biscuit-python before proceeding.
# ---------------------------------------------------------------------------
try:
    import biscuit_auth  # noqa: F401
except ImportError:
    print("ERROR: biscuit-python is required for the chained-token example.")
    print("Install it with:")
    print("  pip install biscuit-python")
    sys.exit(1)

from aip_core.crypto import KeyPair
from aip_token import ChainedToken

if ChainedToken is None:
    print("ERROR: ChainedToken could not be imported.")
    print("Make sure biscuit-python is installed:")
    print("  pip install biscuit-python")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_TOOL_PORT = os.environ.get("AIP_TOOL_PORT", "8341")
TOOL_SERVER_URL = f"http://127.0.0.1:{_TOOL_PORT}"
TOOL_ENDPOINT = f"{TOOL_SERVER_URL}/tools/search"


# ---------------------------------------------------------------------------
# Helper: make a request to the tool server
# ---------------------------------------------------------------------------
def _call_tool_server(
    token_b64: str,
    root_pubkey_hex: str,
    scope: str,
    label: str,
) -> int:
    """Send a POST to the tool server and return the HTTP status code."""
    print(f"  POST {TOOL_ENDPOINT}")
    print(f"  X-AIP-Scope: {scope}")
    print(f"  X-AIP-Token: {token_b64[:40]}...{token_b64[-10:]}")
    print()

    req = urllib.request.Request(
        TOOL_ENDPOINT,
        method="POST",
        headers={
            "X-AIP-Token": token_b64,
            "X-AIP-Scope": scope,
            "X-AIP-Root-Public-Key": root_pubkey_hex,
            "Content-Type": "application/json",
        },
        data=json.dumps({"query": "AIP delegation chain"}).encode("utf-8"),
    )

    try:
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read().decode("utf-8")
    except urllib.error.URLError as exc:
        print(f"  Connection error: {exc.reason}")
        print(f"  Make sure tool_server.py is running on {TOOL_SERVER_URL}")
        return -1

    print(f"  Response status: {status}")
    try:
        parsed = json.loads(body)
        print(f"  Response body:   {json.dumps(parsed, indent=4)}")
    except json.JSONDecodeError:
        print(f"  Response body:   {body}")
    print()
    return status


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 60)
    print("AIP Multi-Agent Delegation Example -- Orchestrator")
    print("=" * 60)
    print()

    # ------------------------------------------------------------------
    # Step 1: Generate root keypair
    # ------------------------------------------------------------------
    print("[step 1] Generating root Ed25519 keypair ...")
    root_kp = KeyPair.generate()
    root_pub_hex = root_kp.public_key_bytes().hex()
    print(f"  Root public key (hex): {root_pub_hex}")
    print()

    # ------------------------------------------------------------------
    # Step 2: Create authority chained token (root -> orchestrator)
    # ------------------------------------------------------------------
    print("[step 2] Creating authority chained token ...")
    authority_scopes = ["search", "browse", "email"]
    authority_budget = 500  # cents ($5.00)
    max_depth = 3
    ttl = 3600  # 1 hour

    print(f"  Issuer:     orchestrator-001")
    print(f"  Scopes:     {', '.join(authority_scopes)}")
    print(f"  Budget:     {authority_budget} cents (${authority_budget / 100:.2f})")
    print(f"  Max depth:  {max_depth}")
    print(f"  TTL:        {ttl} seconds")

    authority_token = ChainedToken.create_authority(
        issuer="orchestrator-001",
        scopes=authority_scopes,
        budget_cents=authority_budget,
        max_depth=max_depth,
        ttl_seconds=ttl,
        keypair=root_kp,
    )
    print(f"  Authority token created (depth={authority_token.current_depth()}).")
    print()

    # ------------------------------------------------------------------
    # Step 3: Delegate to specialist (attenuate scopes and budget)
    # ------------------------------------------------------------------
    print("[step 3] Delegating to specialist ...")
    delegated_scopes = ["search"]
    delegated_budget = 100  # cents ($1.00)
    context = "research task"

    print(f"  Delegator:  orchestrator-001")
    print(f"  Delegate:   specialist-search-01")
    print(f"  Scopes:     {', '.join(delegated_scopes)}  (attenuated from: {', '.join(authority_scopes)})")
    print(f"  Budget:     {delegated_budget} cents (${delegated_budget / 100:.2f})")
    print(f"  Context:    {context}")

    specialist_token = authority_token.delegate(
        delegator="orchestrator-001",
        delegate="specialist-search-01",
        scopes=delegated_scopes,
        budget_cents=delegated_budget,
        context=context,
    )
    print(f"  Delegated token created (depth={specialist_token.current_depth()}).")
    print()

    # Serialize for transport.
    token_b64 = specialist_token.to_base64()
    print(f"  Serialized token length: {len(token_b64)} chars (base64)")
    print()

    # ------------------------------------------------------------------
    # Step 4: Specialist calls tool server -- scope "search" (allowed)
    # ------------------------------------------------------------------
    print("[step 4] Specialist calls tool server: scope=search (should succeed) ...")
    status_search = _call_tool_server(token_b64, root_pub_hex, "search", "search call")

    # ------------------------------------------------------------------
    # Step 5: Specialist calls tool server -- scope "email" (denied)
    # ------------------------------------------------------------------
    print("[step 5] Specialist calls tool server: scope=email (should be denied) ...")
    status_email = _call_tool_server(token_b64, root_pub_hex, "email", "email call")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("=" * 60)
    print("Done.")

    if status_search == -1 or status_email == -1:
        print("  One or more requests failed to connect.")
        print(f"  Make sure tool_server.py is running on {TOOL_SERVER_URL}")
        sys.exit(1)

    search_pass = "PASS" if status_search == 200 else "FAIL"
    email_pass = "PASS" if status_email == 403 else "FAIL"

    print(f"  Step 4 (search): Expected 200, got {status_search} -- {search_pass}")
    print(f"  Step 5 (email):  Expected 403, got {status_email} -- {email_pass}")
    print("=" * 60)

    if search_pass != "PASS" or email_pass != "PASS":
        sys.exit(1)


if __name__ == "__main__":
    main()
