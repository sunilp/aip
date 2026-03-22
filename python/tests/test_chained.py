"""Tests for ChainedToken (Biscuit-based delegation)."""

import pytest

biscuit_auth = pytest.importorskip("biscuit_auth", reason="biscuit-python not installed")

from aip_core.crypto import KeyPair
from aip_token.chained import ChainedToken


def test_create_authority():
    root_kp = KeyPair.generate()
    token = ChainedToken.create_authority(
        issuer="aip:web:example.com/agent",
        scopes=["tool:search"],
        budget_cents=100,
        max_depth=3,
        ttl_seconds=3600,
        keypair=root_kp,
    )
    assert token.issuer() == "aip:web:example.com/agent"
    assert token.max_depth() == 3
    assert token.current_depth() == 0


def test_serialize_roundtrip():
    root_kp = KeyPair.generate()
    token = ChainedToken.create_authority(
        issuer="aip:web:example.com/agent",
        scopes=["tool:search"],
        budget_cents=None,
        max_depth=3,
        ttl_seconds=3600,
        keypair=root_kp,
    )
    b64 = token.to_base64()
    restored = ChainedToken.from_base64(b64, root_kp.public_key_bytes())
    assert restored.issuer() == "aip:web:example.com/agent"


def test_delegation():
    root_kp = KeyPair.generate()
    token = ChainedToken.create_authority(
        issuer="aip:web:example.com/root",
        scopes=["tool:search", "tool:email"],
        budget_cents=500,
        max_depth=3,
        ttl_seconds=3600,
        keypair=root_kp,
    )
    delegated = token.delegate(
        delegator="aip:web:example.com/root",
        delegate="aip:web:example.com/worker",
        scopes=["tool:search"],
        budget_cents=100,
        context="search task",
    )
    assert delegated.current_depth() == 1


def test_reject_depth_exceeded():
    root_kp = KeyPair.generate()
    token = ChainedToken.create_authority(
        issuer="aip:web:example.com/root",
        scopes=["tool:search"],
        budget_cents=None,
        max_depth=1,
        ttl_seconds=3600,
        keypair=root_kp,
    )
    t1 = token.delegate(
        delegator="aip:web:example.com/root",
        delegate="aip:web:example.com/a",
        scopes=["tool:search"],
        budget_cents=None,
        context="first",
    )
    with pytest.raises(Exception):
        t1.delegate(
            delegator="aip:web:example.com/a",
            delegate="aip:web:example.com/b",
            scopes=["tool:search"],
            budget_cents=None,
            context="second",
        )


def test_reject_empty_context():
    root_kp = KeyPair.generate()
    token = ChainedToken.create_authority(
        issuer="aip:web:example.com/root",
        scopes=["tool:search"],
        budget_cents=None,
        max_depth=3,
        ttl_seconds=3600,
        keypair=root_kp,
    )
    with pytest.raises(Exception):
        token.delegate(
            delegator="aip:web:example.com/root",
            delegate="aip:web:example.com/worker",
            scopes=["tool:search"],
            budget_cents=None,
            context="",
        )


def test_authorize_valid():
    root_kp = KeyPair.generate()
    token = ChainedToken.create_authority(
        issuer="aip:web:example.com/agent",
        scopes=["tool:search"],
        budget_cents=100,
        max_depth=3,
        ttl_seconds=3600,
        keypair=root_kp,
    )
    token.authorize("tool:search", root_kp.public_key_bytes())


def test_authorize_rejects_unauthorized():
    root_kp = KeyPair.generate()
    token = ChainedToken.create_authority(
        issuer="aip:web:example.com/agent",
        scopes=["tool:search"],
        budget_cents=100,
        max_depth=3,
        ttl_seconds=3600,
        keypair=root_kp,
    )
    with pytest.raises(Exception):
        token.authorize("tool:email", root_kp.public_key_bytes())
