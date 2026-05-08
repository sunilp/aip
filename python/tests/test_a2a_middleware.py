"""Tests for aip_a2a.middleware — wrap an A2A task handler with AIP verification."""
import pytest

biscuit_auth = pytest.importorskip("biscuit_auth", reason="biscuit-python not installed")

from aip_core.crypto import KeyPair
from aip_token.chained import ChainedToken

from aip_a2a.middleware import A2AVerifyMiddleware
from aip_a2a.error import A2AError


def _make_token(orchestrator, researcher, scopes):
    root_kp = KeyPair.generate()
    token = ChainedToken.create_authority(
        issuer=orchestrator,
        scopes=scopes,
        budget_cents=200,
        max_depth=3,
        ttl_seconds=3600,
        keypair=root_kp,
    )
    return token.delegate(
        delegator=orchestrator,
        delegate=researcher,
        scopes=scopes,
        budget_cents=100,
        context="task-1",
    ), root_kp


def test_middleware_calls_handler_on_valid_token():
    researcher = "aip:web:acme.com/researcher"
    token, root_kp = _make_token("aip:web:acme.com/orch", researcher, ["research:read"])

    handler_called_with = {}

    def handler(body, *, context):
        handler_called_with["body"] = body
        handler_called_with["subject"] = context.subject
        return {"jsonrpc": "2.0", "result": "ok"}

    mw = A2AVerifyMiddleware(
        handler,
        own_aip_id=researcher,
        root_public_key_bytes=root_kp.public_key_bytes(),
        required_scope="research:read",
    )
    body = {"params": {"metadata": {"aip_token": token.to_base64()}}}
    result = mw(body)
    assert result == {"jsonrpc": "2.0", "result": "ok"}
    assert handler_called_with["subject"] == researcher


def test_middleware_returns_error_response_on_invalid():
    kp = KeyPair.generate()

    def handler(body, *, context):
        pytest.fail("handler should not be called on invalid token")

    mw = A2AVerifyMiddleware(
        handler,
        own_aip_id="aip:web:acme.com/researcher",
        root_public_key_bytes=kp.public_key_bytes(),
        required_scope="research:read",
    )
    body = {"params": {"metadata": {}}}  # no token
    result = mw(body)
    assert result["error"]["code"] == "aip_chain_invalid"
    assert result["status"] == 401


def test_middleware_audience_mismatch_returns_403():
    token, root_kp = _make_token(
        "aip:web:acme.com/orch", "aip:web:acme.com/researcher", ["research:read"]
    )

    def handler(body, *, context):
        pytest.fail("handler should not be called")

    mw = A2AVerifyMiddleware(
        handler,
        own_aip_id="aip:web:acme.com/writer",  # wrong audience
        root_public_key_bytes=root_kp.public_key_bytes(),
        required_scope="research:read",
    )
    body = {"params": {"metadata": {"aip_token": token.to_base64()}}}
    result = mw(body)
    assert result["error"]["code"] == "aip_audience_mismatch"
    assert result["status"] == 403
