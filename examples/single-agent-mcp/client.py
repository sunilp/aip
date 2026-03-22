#!/usr/bin/env python3
"""Agent client that authenticates to an MCP tool server using AIP compact tokens.

Usage:
  python examples/single-agent-mcp/client.py

Optionally set AGENT_PRIVATE_KEY_HEX to reuse the keypair printed by the
server (when it auto-generates a demo agent keypair).
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# Make the AIP SDK importable when running from the repo root.
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "python"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from aip_core import KeyPair
from aip_token import CompactToken, AipClaims

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SERVER_URL = "http://127.0.0.1:8340"
TOOL_ENDPOINT = f"{SERVER_URL}/tools/search"


def _load_or_generate_keypair() -> KeyPair:
    """Load the agent keypair from env or generate a new one."""
    hex_key = os.environ.get("AGENT_PRIVATE_KEY_HEX")
    if hex_key:
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_key))
        return KeyPair(priv)
    return KeyPair.generate()


def _make_request(url: str, token: str, label: str) -> None:
    """Send a POST request with the AIP token and print the result."""
    print(f"--- {label} ---")
    print(f"  POST {url}")
    print(f"  X-AIP-Token: {token[:40]}...{token[-10:]}")
    print()

    req = urllib.request.Request(
        url,
        method="POST",
        headers={
            "X-AIP-Token": token,
            "Content-Type": "application/json",
        },
        data=b"{}",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read().decode("utf-8")

    print(f"  Response status: {status}")
    try:
        parsed = json.loads(body)
        print(f"  Response body:   {json.dumps(parsed, indent=4)}")
    except json.JSONDecodeError:
        print(f"  Response body:   {body}")
    print()


def main():
    print("=" * 60)
    print("AIP Single-Agent MCP Example -- Client")
    print("=" * 60)
    print()

    # Step 1: Load or generate the agent keypair
    kp = _load_or_generate_keypair()
    pub_hex = kp.public_key_bytes().hex()
    priv_hex = kp._private_key.private_bytes_raw().hex()
    multibase = kp.public_key_multibase()

    print("[client] Agent keypair ready.")
    print(f"  Public key  (hex):       {pub_hex}")
    print(f"  Public key  (multibase): {multibase}")
    print(f"  Private key (hex):       {priv_hex}")
    print()

    if not os.environ.get("AGENT_PRIVATE_KEY_HEX"):
        print("[client] To reuse this keypair, set:")
        print(f"  export AGENT_PRIVATE_KEY_HEX={priv_hex}")
        print()
        print("[client] To let the server recognise this agent, set:")
        print(f"  export AGENT_PUBLIC_KEY_HEX={pub_hex}")
        print()

    # Step 2: Build the issuer AIP identifier
    iss = f"aip:key:ed25519:{multibase}"
    sub = f"aip:web:localhost:8340/tools/search"
    now = int(time.time())

    # ------------------------------------------------------------------
    # Request 1: valid scope (should succeed with 200)
    # ------------------------------------------------------------------
    print("[client] Creating token with scope ['tool:search'] ...")
    claims_ok = AipClaims(
        iss=iss,
        sub=sub,
        scope=["tool:search"],
        budget_usd=1.0,
        max_depth=0,
        iat=now,
        exp=now + 3600,  # 1 hour from now
    )
    token_ok = CompactToken.create(claims_ok, kp)
    print(f"[client] Token created (length={len(token_ok)} chars).")
    print()

    _make_request(TOOL_ENDPOINT, token_ok, "Request 1: valid scope (tool:search)")

    # ------------------------------------------------------------------
    # Request 2: wrong scope (should fail with 403)
    # ------------------------------------------------------------------
    print("[client] Creating token with scope ['tool:email'] (unauthorized) ...")
    claims_bad = AipClaims(
        iss=iss,
        sub=sub,
        scope=["tool:email"],
        budget_usd=1.0,
        max_depth=0,
        iat=now,
        exp=now + 3600,
    )
    token_bad = CompactToken.create(claims_bad, kp)
    print(f"[client] Token created (length={len(token_bad)} chars).")
    print()

    _make_request(TOOL_ENDPOINT, token_bad, "Request 2: wrong scope (tool:email)")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("=" * 60)
    print("Done. Request 1 should have returned 200, Request 2 should have returned 403.")
    print("=" * 60)


if __name__ == "__main__":
    main()
