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


from biscuit_auth import BlockBuilder  # noqa: E402


def forged(kp, block_src):
    tok = authority(kp)
    new = tok._biscuit.append(BlockBuilder(block_src))
    return ChainedToken.from_base64(new.to_base64(), kp.public_key_bytes())


BASE = 'delegator("a");\ndelegate("b");\ncontext("x");\n'


def verify_code(kp, src):
    with pytest.raises(TokenError) as e:
        forged(kp, src).verify_chain(kp.public_key_bytes())
    return e.value.code


def test_forged_domain_widening():
    kp = KeyPair.generate()
    assert verify_code(kp, BASE + 'domain("evil.com");\n') == "scope_insufficient"


def test_forged_extended_expiry():
    kp = KeyPair.generate()
    assert verify_code(
        kp, BASE + "check if time($t), $t <= 2999-01-01T00:00:00Z;\n") == "token_expired"


def test_forged_max_depth_in_delegation_block():
    kp = KeyPair.generate()
    assert verify_code(kp, BASE + "max_depth(9);\n") == "token_malformed"


def test_forged_duplicate_budget_fact():
    kp = KeyPair.generate()
    assert verify_code(kp, BASE + "budget_ceiling(1);\nbudget_ceiling(2);\n") == "token_malformed"


def test_mint_rejects_empty_lists():
    kp = KeyPair.generate()
    for kw in ({"scopes": []}, {"domains": []}):
        with pytest.raises(TokenError) as e:
            authority(kp, **kw)
        assert e.value.code == "token_malformed"
    with pytest.raises(TokenError) as e:
        authority(kp).delegate(ROOT, "aip:web:b.example", ["tool:search"], None, "x", domains=[])
    assert e.value.code == "token_malformed"


def test_forged_block_without_delegator_or_delegate():
    kp = KeyPair.generate()
    assert verify_code(kp, 'context("work");\n') == "token_malformed"


def test_forged_block_without_delegate():
    kp = KeyPair.generate()
    assert verify_code(kp, 'delegator("a");\ncontext("x");\n') == "token_malformed"


def test_forged_block_without_delegator():
    kp = KeyPair.generate()
    assert verify_code(kp, 'delegate("b");\ncontext("x");\n') == "token_malformed"


def test_authority_without_identity_rejected():
    from aip_token import chained
    with pytest.raises(TokenError) as e:
        chained._require_parties('scope("x");\n', 0)
    assert e.value.code == "token_malformed"
