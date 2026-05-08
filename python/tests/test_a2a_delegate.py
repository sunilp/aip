"""Tests for aip_a2a.delegate — append a delegation block before forwarding a task."""
import pytest

biscuit_auth = pytest.importorskip("biscuit_auth", reason="biscuit-python not installed")

from aip_core.crypto import KeyPair
from aip_token.chained import ChainedToken

from aip_a2a.delegate import append_delegation_block


def test_append_delegation_attenuates_scope():
    root_kp = KeyPair.generate()
    token = ChainedToken.create_authority(
        issuer="aip:web:acme.com/orchestrator",
        scopes=["research:read", "research:write"],
        budget_cents=500,
        max_depth=3,
        ttl_seconds=3600,
        keypair=root_kp,
    )
    extended = append_delegation_block(
        token,
        delegator="aip:web:acme.com/orchestrator",
        delegate="aip:web:acme.com/researcher",
        scopes=["research:read"],
        context="search-task-1",
        budget_cents=100,
    )
    assert extended.current_depth() == 1


def test_append_delegation_requires_non_empty_context():
    root_kp = KeyPair.generate()
    token = ChainedToken.create_authority(
        issuer="aip:web:acme.com/orch",
        scopes=["research:read"],
        budget_cents=100,
        max_depth=3,
        ttl_seconds=3600,
        keypair=root_kp,
    )
    with pytest.raises(ValueError) as exc:
        append_delegation_block(
            token,
            delegator="aip:web:acme.com/orch",
            delegate="aip:web:acme.com/researcher",
            scopes=["research:read"],
            context="",  # empty
        )
    assert "context" in str(exc.value)


def test_append_delegation_serializable():
    root_kp = KeyPair.generate()
    token = ChainedToken.create_authority(
        issuer="aip:web:acme.com/orch",
        scopes=["research:read"],
        budget_cents=100,
        max_depth=3,
        ttl_seconds=3600,
        keypair=root_kp,
    )
    extended = append_delegation_block(
        token,
        delegator="aip:web:acme.com/orch",
        delegate="aip:web:acme.com/researcher",
        scopes=["research:read"],
        context="t1",
    )
    b64 = extended.to_base64()
    assert isinstance(b64, str) and len(b64) > 0
