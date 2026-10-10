import pytest

pytest.importorskip("biscuit_auth")

from aip_core.crypto import KeyPair
from aip_token.chained import ChainedToken
from aip_token.error import TokenError

ROOT = "aip:web:a.example/orchestrator"


def authority(kp, **kw):
    args = dict(issuer=ROOT, scopes=["tool:search", "tool:write"], budget_cents=500,
                max_depth=3, ttl_seconds=600, keypair=kp, principal="user:alice",
                domains=["a.com", "b.com"])
    args.update(kw)
    return ChainedToken.create_authority(**args)


def test_links_reflect_blocks():
    kp = KeyPair.generate()
    tok = authority(kp).delegate("aip:web:a.example/orchestrator", "aip:web:b.example",
                                 ["tool:search"], 100, "research", domains=["a.com"])
    tok.verify_chain(kp.public_key_bytes())
    links = tok.links()
    assert links[0].issuer == ROOT and links[0].max_depth == 3
    assert links[0].domains == frozenset({"a.com", "b.com"})
    assert links[0].expiry is not None
    assert links[1].delegate == "aip:web:b.example" and links[1].context == "research"
    assert tok.effective.domains == frozenset({"a.com"})
    assert tok.effective.budget_cents == 100


def test_domain_widening_rejected_at_mint():
    kp = KeyPair.generate()
    with pytest.raises(TokenError) as e:
        authority(kp).delegate(ROOT, "aip:web:b.example", ["tool:search"], None, "x",
                               domains=["evil.com"])
    assert e.value.code == "scope_insufficient"


def test_authorize_checks_domain():
    kp = KeyPair.generate()
    tok = authority(kp).delegate(ROOT, "aip:web:b.example", ["tool:search"], None, "x",
                                 domains=["a.com"])
    tok.authorize("tool:search", kp.public_key_bytes(), domain="a.com")
    tok.authorize("tool:search", kp.public_key_bytes())
    with pytest.raises(TokenError) as e:
        tok.authorize("tool:search", kp.public_key_bytes(), domain="b.com")
    assert e.value.code == "scope_insufficient"


def test_domain_is_a_fact_not_a_check():
    kp = KeyPair.generate()
    src = authority(kp).block_source(0)
    assert 'domain("a.com");' in src
    assert "check if domain" not in src
