"""Tests for aip_a2a.error — A2A-specific error types and response formatting."""
from aip_a2a.error import (
    A2AError,
    AudienceError,
    ChainError,
    DepthError,
    ExpiryError,
    ScopeError,
    a2a_error_response,
)


def test_audience_error_subclasses_a2a_error():
    e = AudienceError("expected aip:web:b.com, got aip:web:c.com")
    assert isinstance(e, A2AError)
    assert e.code == "aip_audience_mismatch"


def test_scope_error_includes_scope():
    e = ScopeError("research:read")
    assert e.code == "aip_scope_insufficient"
    assert "research:read" in str(e)


def test_chain_error_default_code():
    e = ChainError("invalid signature on block 1")
    assert e.code == "aip_chain_invalid"


def test_expiry_error():
    e = ExpiryError()
    assert e.code == "aip_token_expired"


def test_depth_error_includes_max():
    e = DepthError(max_depth=3)
    assert e.code == "aip_depth_exceeded"
    assert "3" in str(e)


def test_a2a_error_response_format():
    resp = a2a_error_response("aip_audience_mismatch", "wrong recipient", 403)
    assert resp == {
        "error": {"code": "aip_audience_mismatch", "message": "wrong recipient"},
        "status": 403,
    }
