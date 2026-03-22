"""Cross-language interoperability tests for ChainedToken (Biscuit): Rust <-> Python.

These tests verify that chained delegation tokens created in one language
can be deserialized and authorized by the other language's implementation,
ensuring wire-format compatibility for Biscuit-backed tokens.
"""

import subprocess
import json
import os
import sys

AIP_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUST_DIR = os.path.join(AIP_ROOT, "rust")
sys.path.insert(0, os.path.join(AIP_ROOT, "python"))

# Only run if biscuit_auth is available
pytest = __import__("pytest")
biscuit_available = True
try:
    import biscuit_auth  # noqa: F401
except ImportError:
    biscuit_available = False


@pytest.mark.skipif(not biscuit_available, reason="biscuit-python not installed")
def test_rust_chained_token_verified_by_python():
    """Create a chained token in Rust, verify and authorize in Python."""
    from aip_token.chained import ChainedToken

    result = subprocess.run(
        ["cargo", "run", "--bin", "create_chained_token"],
        cwd=RUST_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Rust failed: {result.stderr}"
    output = json.loads(result.stdout)

    pubkey_bytes = bytes.fromhex(output["root_public_key_hex"])
    token = ChainedToken.from_base64(output["token"], pubkey_bytes)
    assert token.issuer() == output["issuer"]
    token.authorize("tool:search", pubkey_bytes)


@pytest.mark.skipif(not biscuit_available, reason="biscuit-python not installed")
def test_python_chained_token_verified_by_rust():
    """Create a chained token in Python, verify and authorize in Rust."""
    from aip_core.crypto import KeyPair
    from aip_token.chained import ChainedToken

    kp = KeyPair.generate()
    token = ChainedToken.create_authority(
        issuer="aip:web:interop.test/python-root",
        scopes=["tool:search"],
        budget_cents=100,
        max_depth=3,
        ttl_seconds=3600,
        keypair=kp,
    )
    b64 = token.to_base64()
    pubkey_hex = kp.public_key_bytes().hex()

    result = subprocess.run(
        [
            "cargo",
            "run",
            "--bin",
            "verify_chained_token",
            "--",
            b64,
            pubkey_hex,
            "tool:search",
        ],
        cwd=RUST_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Rust verification failed: {result.stderr}"
