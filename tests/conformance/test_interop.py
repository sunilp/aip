"""Cross-language interoperability tests: Rust <-> Python.

These tests verify that tokens created in one language can be verified
by the other language's implementation, ensuring wire-format compatibility.
"""

import subprocess
import json
import os
import sys

# Path to the aip root
AIP_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUST_DIR = os.path.join(AIP_ROOT, "rust")

# Add python dir to path so we can import aip_core/aip_token
sys.path.insert(0, os.path.join(AIP_ROOT, "python"))

from aip_core.crypto import KeyPair
from aip_token.claims import AipClaims
from aip_token.compact import CompactToken


def test_rust_token_verified_by_python():
    """Create token in Rust, verify in Python."""
    result = subprocess.run(
        ["cargo", "run", "--bin", "create_token"],
        cwd=RUST_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Rust token creation failed: {result.stderr}"
    output = json.loads(result.stdout)

    token_str = output["token"]
    pubkey_hex = output["public_key_hex"]
    pubkey_bytes = bytes.fromhex(pubkey_hex)

    verified = CompactToken.verify(token_str, pubkey_bytes)
    assert verified.claims.iss == output["iss"]
    assert verified.has_scope("tool:search")


def test_python_token_verified_by_rust():
    """Create token in Python, verify in Rust."""
    kp = KeyPair.generate()
    claims = AipClaims(
        iss="aip:web:interop.test/python-agent",
        sub="aip:web:interop.test/verifier",
        scope=["tool:test"],
        budget_usd=1.0,
        max_depth=0,
        iat=1711100000,
        exp=4711100000,
    )
    token_str = CompactToken.create(claims, kp)
    pubkey_hex = kp.public_key_bytes().hex()

    result = subprocess.run(
        ["cargo", "run", "--bin", "verify_token", "--", token_str, pubkey_hex],
        cwd=RUST_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Rust verification failed: {result.stderr}"
