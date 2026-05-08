"""Tests for aip_a2a.verify — extract and verify tokens from A2A task bodies."""
import pytest

biscuit_auth = pytest.importorskip("biscuit_auth", reason="biscuit-python not installed")

from aip_core.crypto import KeyPair
from aip_token.chained import ChainedToken

from aip_a2a.error import AudienceError, ChainError, ScopeError
from aip_a2a.verify import VerifiedIdentity, extract_token_from_task, verify_a2a_task


# --- token extraction -------------------------------------------------------

def test_extract_token_present():
    body = {"params": {"metadata": {"aip_token": "ABC123"}}}
    assert extract_token_from_task(body) == "ABC123"


def test_extract_token_missing_returns_none():
    body = {"params": {"metadata": {}}}
    assert extract_token_from_task(body) is None


def test_extract_token_missing_metadata_returns_none():
    assert extract_token_from_task({"params": {}}) is None
    assert extract_token_from_task({}) is None


# --- verify_a2a_task --------------------------------------------------------

def _make_2hop_chain(orchestrator_id, researcher_id, scopes):
    root_kp = KeyPair.generate()
    token = ChainedToken.create_authority(
        issuer=orchestrator_id,
        scopes=scopes,
        budget_cents=200,
        max_depth=3,
        ttl_seconds=3600,
        keypair=root_kp,
    )
    delegated = token.delegate(
        delegator=orchestrator_id,
        delegate=researcher_id,
        scopes=scopes,
        budget_cents=100,
        context="task-1",
    )
    return delegated, root_kp


def test_verify_success():
    orchestrator = "aip:web:acme.com/orchestrator"
    researcher = "aip:web:acme.com/researcher"
    token, root_kp = _make_2hop_chain(orchestrator, researcher, ["research:read"])
    body = {"params": {"metadata": {"aip_token": token.to_base64()}}}
    result = verify_a2a_task(
        body,
        expected_audience=researcher,
        root_public_key_bytes=root_kp.public_key_bytes(),
        required_scope="research:read",
    )
    assert isinstance(result, VerifiedIdentity)
    assert result.subject == researcher
    assert result.chain_depth == 1


def test_verify_audience_mismatch():
    token, root_kp = _make_2hop_chain(
        "aip:web:acme.com/orchestrator",
        "aip:web:acme.com/researcher",
        ["research:read"],
    )
    body = {"params": {"metadata": {"aip_token": token.to_base64()}}}
    with pytest.raises(AudienceError):
        verify_a2a_task(
            body,
            expected_audience="aip:web:acme.com/writer",  # wrong recipient
            root_public_key_bytes=root_kp.public_key_bytes(),
            required_scope="research:read",
        )


def test_verify_scope_insufficient():
    token, root_kp = _make_2hop_chain(
        "aip:web:acme.com/orchestrator",
        "aip:web:acme.com/researcher",
        ["research:read"],
    )
    body = {"params": {"metadata": {"aip_token": token.to_base64()}}}
    with pytest.raises(ScopeError):
        verify_a2a_task(
            body,
            expected_audience="aip:web:acme.com/researcher",
            root_public_key_bytes=root_kp.public_key_bytes(),
            required_scope="research:write",  # not granted
        )


def test_verify_missing_token_raises_chain_error():
    kp = KeyPair.generate()
    with pytest.raises(ChainError):
        verify_a2a_task(
            {"params": {"metadata": {}}},
            expected_audience="aip:web:acme.com/researcher",
            root_public_key_bytes=kp.public_key_bytes(),
            required_scope="research:read",
        )


def test_verify_rejects_attenuated_away_scope():
    """A scope dropped by a delegation block must not be authorized at the leaf,
    even if the authority block originally granted it.

    Regression test: a previous text-parsing implementation only checked block 0
    and would have incorrectly authorized this case.
    """
    orchestrator = "aip:web:acme.com/orchestrator"
    researcher = "aip:web:acme.com/researcher"

    root_kp = KeyPair.generate()
    auth = ChainedToken.create_authority(
        issuer=orchestrator,
        scopes=["research:read", "research:write"],
        budget_cents=200,
        max_depth=3,
        ttl_seconds=3600,
        keypair=root_kp,
    )
    delegated = auth.delegate(
        delegator=orchestrator,
        delegate=researcher,
        scopes=["research:read"],  # research:write is attenuated away
        budget_cents=100,
        context="task-1",
    )
    body = {"params": {"metadata": {"aip_token": delegated.to_base64()}}}

    # research:read works (granted at every level)
    result = verify_a2a_task(
        body,
        expected_audience=researcher,
        root_public_key_bytes=root_kp.public_key_bytes(),
        required_scope="research:read",
    )
    assert result.subject == researcher

    # research:write must be rejected — the delegation attenuated it away
    with pytest.raises(ScopeError):
        verify_a2a_task(
            body,
            expected_audience=researcher,
            root_public_key_bytes=root_kp.public_key_bytes(),
            required_scope="research:write",
        )
