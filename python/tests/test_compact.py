"""Tests for the aip_token compact token (JWT + EdDSA)."""

import pytest

from aip_core.crypto import KeyPair
from aip_token.claims import AipClaims
from aip_token.compact import CompactToken
from aip_token.error import TokenError


def test_create_and_verify():
    kp = KeyPair.generate()
    claims = AipClaims(
        iss="aip:web:jamjet.dev/agents/orchestrator",
        sub="aip:web:jamjet.dev/agents/research",
        scope=["tool:search", "tool:browse"],
        budget_usd=0.50,
        max_depth=0,
        iat=1711100000,
        exp=4711100000,
    )
    token_str = CompactToken.create(claims, kp)
    verified = CompactToken.verify(token_str, kp.public_key_bytes())
    assert verified.claims.iss == claims.iss
    assert verified.claims.scope == claims.scope


def test_reject_expired():
    kp = KeyPair.generate()
    claims = AipClaims(
        iss="aip:web:example.com/a",
        sub="aip:web:example.com/b",
        scope=[],
        budget_usd=None,
        max_depth=0,
        iat=1000000000,
        exp=1000000001,
    )
    token_str = CompactToken.create(claims, kp)
    with pytest.raises(TokenError) as exc_info:
        CompactToken.verify(token_str, kp.public_key_bytes())
    assert exc_info.value.error_code() == "token_expired"


def test_reject_wrong_key():
    kp1 = KeyPair.generate()
    kp2 = KeyPair.generate()
    claims = AipClaims(
        iss="aip:web:example.com/a",
        sub="aip:web:example.com/b",
        scope=[],
        budget_usd=None,
        max_depth=0,
        iat=1711100000,
        exp=4711100000,
    )
    token_str = CompactToken.create(claims, kp1)
    with pytest.raises(TokenError) as exc_info:
        CompactToken.verify(token_str, kp2.public_key_bytes())
    assert exc_info.value.error_code() == "signature_invalid"


def test_has_scope():
    kp = KeyPair.generate()
    claims = AipClaims(
        iss="aip:web:example.com/a",
        sub="aip:web:example.com/b",
        scope=["tool:search", "tool:browse"],
        budget_usd=1.0,
        max_depth=0,
        iat=1711100000,
        exp=4711100000,
    )
    token_str = CompactToken.create(claims, kp)
    verified = CompactToken.verify(token_str, kp.public_key_bytes())
    assert verified.has_scope("tool:search")
    assert not verified.has_scope("tool:email")


def test_header_typ():
    kp = KeyPair.generate()
    claims = AipClaims(
        iss="aip:web:example.com/a",
        sub="aip:web:example.com/b",
        scope=[],
        budget_usd=None,
        max_depth=0,
        iat=1711100000,
        exp=4711100000,
    )
    token_str = CompactToken.create(claims, kp)
    header = CompactToken.decode_header(token_str)
    assert header["typ"] == "aip+jwt"
    assert header["alg"] == "EdDSA"
