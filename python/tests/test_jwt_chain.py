"""JWT chain encoding (draft-prakash-aip-02 Section 5.1). Each negative test
is a MUST or MUST NOT from the draft, asserted directly."""

import base64
import hashlib
import json
import time

import jwt
import pytest

from aip_core.crypto import KeyPair
from aip_token import jwt_chain
from aip_token.error import TokenError
from aip_token.jwt_chain import JwtChain, holder_jwk

ROOT_ID = "aip:web:a.example/orchestrator"
B_ID = "aip:web:b.example/researcher"
C_ID = "aip:web:c.example/writer"


@pytest.fixture
def keys():
    return {"root": KeyPair.generate(), "b": KeyPair.generate(), "c": KeyPair.generate()}


def make_chain(keys, **root_kw):
    kw = dict(
        issuer=ROOT_ID, delegate=B_ID, tools=["tool:search", "tool:write"],
        max_depth=2, ttl_seconds=600, issuer_keypair=keys["root"],
        holder_public_key=keys["b"].public_key_bytes(), budget_cents=500,
        domains=["a.com", "b.com"], principal="user:alice",
    )
    kw.update(root_kw)
    root = JwtChain.create_root(**kw)
    return root.append(
        holder_keypair=keys["b"], delegate=C_ID,
        next_holder_public_key=keys["c"].public_key_bytes(),
        context="draft the summary", tools=["tool:search"], budget_cents=100,
    )


def forge_link(prev_segment, signer, claims):
    """Sign a link without the mint-time checks, as an attacker would."""
    body = {"iat": int(time.time()), "jti": "x",
            "prev": base64.urlsafe_b64encode(
                hashlib.sha256(prev_segment.encode("ascii")).digest()).rstrip(b"=").decode()}
    body.update(claims)
    return jwt.encode(body, signer._private_key, algorithm="EdDSA",
                      headers={"typ": "aip-link+jwt"})


def code(e):
    return e.value.code


def test_roundtrip_and_authorize(keys):
    token = make_chain(keys).serialize()
    assert token.count("~") == 1
    chain = JwtChain.verify(token, keys["root"].public_key_bytes())
    assert chain.issuer() == ROOT_ID
    assert chain.depth() == 1
    assert chain.leaf_delegate() == C_ID
    assert chain.effective.budget_cents == 100
    assert chain.effective.principal == "user:alice"
    chain.authorize("tool:search", "a.com")
    with pytest.raises(TokenError) as e:
        chain.authorize("tool:write")
    assert code(e) == "scope_insufficient"


def test_header_and_claim_names(keys):
    token = make_chain(keys).serialize()
    first, second = token.split("~")
    assert jwt.get_unverified_header(first) == {"alg": "EdDSA", "typ": "aip-link+jwt"}
    c0 = jwt.decode(first, options={"verify_signature": False})
    c1 = jwt.decode(second, options={"verify_signature": False})
    assert {"iss", "sub", "iat", "exp", "jti", "aip_tools", "aip_max_depth", "cnf"} <= set(c0)
    assert c0["cnf"] == {"jwk": holder_jwk(keys["b"].public_key_bytes())}
    assert {"iss", "sub", "prev", "aip_ctx", "cnf"} <= set(c1)
    assert "aip_max_depth" not in c1
    assert c1["iss"] == c0["sub"]


def test_unauthorized_tool_is_rejected(keys):
    chain = JwtChain.verify(make_chain(keys).serialize(), keys["root"].public_key_bytes())
    with pytest.raises(TokenError) as e:
        chain.authorize("tool:delete")
    assert code(e) == "scope_insufficient"


def test_wrong_root_key(keys):
    with pytest.raises(TokenError) as e:
        JwtChain.verify(make_chain(keys).serialize(), KeyPair.generate().public_key_bytes())
    assert code(e) == "signature_invalid"


def test_tampered_signature(keys):
    first, second = make_chain(keys).serialize().split("~")
    tampered = second[:-2] + ("A" if second[-2] != "A" else "B") + second[-1]
    with pytest.raises(TokenError) as e:
        JwtChain.verify(f"{first}~{tampered}", keys["root"].public_key_bytes())
    assert code(e) == "signature_invalid"


def test_alg_none_rejected(keys):
    first, _ = make_chain(keys).serialize().split("~")
    unsigned = jwt.encode({"iss": B_ID}, None, algorithm="none")
    with pytest.raises(TokenError) as e:
        JwtChain.verify(f"{first}~{unsigned}", keys["root"].public_key_bytes())
    assert code(e) == "signature_invalid"


def test_wrong_typ_rejected(keys):
    claims = {"iss": ROOT_ID, "sub": B_ID, "exp": int(time.time()) + 60,
              "aip_tools": ["tool:search"], "aip_max_depth": 1,
              "cnf": {"jwk": holder_jwk(keys["b"].public_key_bytes())}}
    seg = jwt.encode(claims, keys["root"]._private_key, algorithm="EdDSA", headers={"typ": "JWT"})
    with pytest.raises(TokenError) as e:
        JwtChain.verify(seg, keys["root"].public_key_bytes())
    assert code(e) == "signature_invalid"


def test_link_signed_by_non_holder_rejected(keys):
    first, _ = make_chain(keys).serialize().split("~")
    forged = forge_link(first, keys["c"], {"iss": B_ID, "sub": C_ID, "aip_ctx": "x",
                                          "cnf": {"jwk": holder_jwk(keys["c"].public_key_bytes())}})
    with pytest.raises(TokenError) as e:
        JwtChain.verify(f"{first}~{forged}", keys["root"].public_key_bytes())
    assert code(e) == "signature_invalid"


def test_prev_mismatch_rejected(keys):
    _, second = make_chain(keys).serialize().split("~")
    # second is validly signed by b, but its prev names a different root link
    root_other = JwtChain.create_root(
        issuer=ROOT_ID, delegate=B_ID, tools=["tool:search"], max_depth=2, ttl_seconds=600,
        issuer_keypair=keys["root"], holder_public_key=keys["b"].public_key_bytes())
    with pytest.raises(TokenError) as e:
        JwtChain.verify(f"{root_other.serialize()}~{second}", keys["root"].public_key_bytes())
    assert code(e) == "signature_invalid"


def test_iss_must_equal_previous_sub(keys):
    first, _ = make_chain(keys).serialize().split("~")
    forged = forge_link(first, keys["b"], {"iss": "aip:web:imposter.example", "sub": C_ID,
                                          "aip_ctx": "x",
                                          "cnf": {"jwk": holder_jwk(keys["c"].public_key_bytes())}})
    with pytest.raises(TokenError) as e:
        JwtChain.verify(f"{first}~{forged}", keys["root"].public_key_bytes())
    assert code(e) == "signature_invalid"


@pytest.mark.parametrize("claims,expected", [
    ({"aip_tools": ["tool:delete"]}, "scope_insufficient"),
    ({"aip_tools": ["tool:*"]}, "scope_insufficient"),
    ({"aip_domains": ["evil.com"]}, "scope_insufficient"),
    ({"aip_budget_cents": 900}, "budget_exceeded"),
    ({"exp": int(time.time()) + 99999}, "token_expired"),
    ({"aip_principal": "user:mallory"}, "token_malformed"),
    ({"aip_ctx": ""}, "token_malformed"),
    ({"aip_max_depth": 9}, "token_malformed"),
])
def test_forged_widening_link_rejected(keys, claims, expected):
    root = JwtChain.create_root(
        issuer=ROOT_ID, delegate=B_ID, tools=["tool:search", "tool:write"], max_depth=2,
        ttl_seconds=600, issuer_keypair=keys["root"],
        holder_public_key=keys["b"].public_key_bytes(), budget_cents=500,
        domains=["a.com"], principal="user:alice")
    first = root.serialize()
    body = {"iss": B_ID, "sub": C_ID, "aip_ctx": "work",
            "cnf": {"jwk": holder_jwk(keys["c"].public_key_bytes())}}
    body.update(claims)
    forged = forge_link(first, keys["b"], body)
    with pytest.raises(TokenError) as e:
        JwtChain.verify(f"{first}~{forged}", keys["root"].public_key_bytes())
    assert code(e) == expected


def test_depth_exceeded(keys):
    chain = make_chain(keys, max_depth=1)
    with pytest.raises(TokenError) as e:
        chain.append(holder_keypair=keys["c"], delegate="aip:web:d.example",
                     next_holder_public_key=KeyPair.generate().public_key_bytes(),
                     context="more")
    assert code(e) == "depth_exceeded"


def test_append_by_non_holder_rejected(keys):
    root = JwtChain.create_root(
        issuer=ROOT_ID, delegate=B_ID, tools=["tool:search"], max_depth=2, ttl_seconds=600,
        issuer_keypair=keys["root"], holder_public_key=keys["b"].public_key_bytes())
    with pytest.raises(TokenError) as e:
        root.append(holder_keypair=keys["c"], delegate=C_ID,
                    next_holder_public_key=keys["c"].public_key_bytes(), context="x")
    assert code(e) == "signature_invalid"


def test_mint_time_widening_rejected(keys):
    root = JwtChain.create_root(
        issuer=ROOT_ID, delegate=B_ID, tools=["tool:search"], max_depth=2, ttl_seconds=600,
        issuer_keypair=keys["root"], holder_public_key=keys["b"].public_key_bytes())
    with pytest.raises(TokenError) as e:
        root.append(holder_keypair=keys["b"], delegate=C_ID,
                    next_holder_public_key=keys["c"].public_key_bytes(),
                    context="x", tools=["tool:delete"])
    assert code(e) == "scope_insufficient"


def test_expired_chain(keys):
    past = int(time.time()) - 10_000
    root = JwtChain.create_root(
        issuer=ROOT_ID, delegate=B_ID, tools=["tool:search"], max_depth=1, ttl_seconds=60,
        issuer_keypair=keys["root"], holder_public_key=keys["b"].public_key_bytes(), now=past)
    with pytest.raises(TokenError) as e:
        JwtChain.verify(root.serialize(), keys["root"].public_key_bytes())
    assert code(e) == "token_expired"


def test_authorize_requires_verify(keys):
    with pytest.raises(TokenError) as e:
        make_chain(keys).authorize("tool:search")
    assert code(e) == "token_malformed"


def test_anchor_claim_carried(keys):
    anchor = {"alg": "S256", "txn_token": "abc"}
    root = JwtChain.create_root(
        issuer=ROOT_ID, delegate=B_ID, tools=["tool:search"], max_depth=0, ttl_seconds=60,
        issuer_keypair=keys["root"], holder_public_key=keys["b"].public_key_bytes(), anchor=anchor)
    c0 = jwt.decode(root.serialize(), options={"verify_signature": False})
    assert c0["aip_anchor"] == anchor


@pytest.mark.parametrize("token", ["", "~", "abc~", "not-a-jwt"])
def test_garbage_is_malformed_or_missing(keys, token):
    with pytest.raises(TokenError) as e:
        JwtChain.verify(token, keys["root"].public_key_bytes())
    assert code(e) in ("token_missing", "token_malformed")
