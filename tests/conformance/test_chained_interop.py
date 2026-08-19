"""Cross-language interoperability tests for ChainedToken (Biscuit): Rust <-> Python.

A chained token minted by one implementation MUST verify under the other. Both
implementations follow the canonical block encoding in draft-prakash-aip-01
Section 3.4.1, so a delegation block emitted by either is readable by both.

Coverage rule for this file: every test MUST exercise at least one delegation
block. An authority-only token shares no encoding surface with a delegation
block and so proves nothing about interop.
"""

import json
import os
import subprocess
import sys

import pytest

AIP_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUST_DIR = os.path.join(AIP_ROOT, "rust")
sys.path.insert(0, os.path.join(AIP_ROOT, "python"))

try:
    import biscuit_auth  # noqa: F401

    biscuit_available = True
except ImportError:
    biscuit_available = False

pytestmark = pytest.mark.skipif(
    not biscuit_available, reason="biscuit-python not installed"
)


def _rust(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["cargo", "run", "--quiet", *args],
        cwd=RUST_DIR,
        capture_output=True,
        text=True,
        timeout=300,
    )


def _python_delegated_token(scopes, delegated_scopes, budget=500, sub_budget=100):
    from aip_core.crypto import KeyPair
    from aip_token.chained import ChainedToken

    kp = KeyPair.generate()
    authority = ChainedToken.create_authority(
        issuer="aip:web:interop.test/python-root",
        scopes=scopes,
        budget_cents=budget,
        max_depth=3,
        ttl_seconds=3600,
        keypair=kp,
    )
    delegated = authority.delegate(
        delegator="aip:web:interop.test/python-root",
        delegate="aip:web:interop.test/delegate",
        scopes=delegated_scopes,
        budget_cents=sub_budget,
        context="interop test delegation",
    )
    return delegated.to_base64(), kp.public_key_bytes()


def test_rust_delegated_token_verified_by_python():
    """A Rust-minted chain carrying a delegation block authorizes in Python."""
    from aip_token.chained import ChainedToken

    result = _rust("--bin", "create_chained_token")
    assert result.returncode == 0, f"Rust failed: {result.stderr}"
    output = json.loads(result.stdout)

    pubkey = bytes.fromhex(output["root_public_key_hex"])
    token = ChainedToken.from_base64(output["token"], pubkey)

    assert token.issuer() == output["issuer"]
    assert token.current_depth() == 1, "fixture must carry a delegation block"
    token.authorize("tool:search", pubkey)


def test_python_delegated_token_verified_by_rust():
    """A Python-minted chain carrying a delegation block authorizes in Rust."""
    b64, pubkey = _python_delegated_token(
        scopes=["tool:search", "tool:browse"], delegated_scopes=["tool:search"]
    )

    result = _rust(
        "--bin", "verify_chained_token", "--", b64, pubkey.hex(), "tool:search"
    )
    assert result.returncode == 0, f"Rust verification failed: {result.stderr}"


def test_scope_narrowed_away_is_rejected_by_rust():
    """A tool dropped by a delegation is not authorized, even though the root granted it."""
    b64, pubkey = _python_delegated_token(
        scopes=["tool:search", "tool:browse"], delegated_scopes=["tool:search"]
    )

    result = _rust(
        "--bin", "verify_chained_token", "--", b64, pubkey.hex(), "tool:browse"
    )
    assert result.returncode != 0, "delegation dropped tool:browse; it must not authorize"


def test_scope_narrowed_away_is_rejected_by_python():
    """Same narrowing, verified in Python, so both sides agree on the boundary."""
    from aip_token.chained import ChainedToken

    b64, pubkey = _python_delegated_token(
        scopes=["tool:search", "tool:browse"], delegated_scopes=["tool:search"]
    )
    token = ChainedToken.from_base64(b64, pubkey)

    with pytest.raises(Exception):
        token.authorize("tool:browse", pubkey)
