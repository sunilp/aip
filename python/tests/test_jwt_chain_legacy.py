import time

import pytest

from aip_core.crypto import KeyPair
from aip_token.claims import AipClaims
from aip_token.compact import CompactToken
from aip_token.error import TokenError
from aip_token.jwt_chain import JwtChain, detect_format


def legacy(kp, **kw):
    now = int(time.time())
    claims = dict(iss="aip:web:a.example", sub="aip:web:b.example", scope=["tool:search"],
                  budget_usd=1.5, max_depth=0, iat=now, exp=now + 300)
    claims.update(kw)
    return CompactToken.create(AipClaims(**claims), kp)


def test_legacy_compact_verifies_as_one_link_chain():
    kp = KeyPair.generate()
    chain = JwtChain.verify(legacy(kp), kp.public_key_bytes())
    assert chain.depth() == 0
    assert chain.effective.tools == frozenset({"tool:search"})
    assert chain.effective.budget_cents == 150
    chain.authorize("tool:search")
    with pytest.raises(TokenError):
        chain.authorize("tool:write")


def test_legacy_expired():
    kp = KeyPair.generate()
    now = int(time.time())
    with pytest.raises(TokenError) as e:
        JwtChain.verify(legacy(kp, iat=now - 1000, exp=now - 10), kp.public_key_bytes())
    assert e.value.code == "token_expired"


def test_detect_format():
    kp = KeyPair.generate()
    assert detect_format(legacy(kp)) == "compact"
    chain = JwtChain.create_root(
        issuer="aip:web:a.example", delegate="aip:web:b.example", tools=["tool:search"],
        max_depth=0, ttl_seconds=60, issuer_keypair=kp,
        holder_public_key=KeyPair.generate().public_key_bytes())
    assert detect_format(chain.serialize()) == "jwt-chain"
    assert detect_format(chain.serialize() + "~" + chain.serialize()) == "jwt-chain"
    assert detect_format("En0KEwoEdG9vbBgDIgkKBwgKEgMYgAg") == "biscuit"


def test_detect_format_rejects_non_string():
    with pytest.raises(TokenError) as e:
        detect_format(None)
    assert e.value.code == "token_malformed"


@pytest.mark.parametrize("bad", [float("nan"), float("inf")])
def test_legacy_non_finite_budget_is_malformed(bad):
    kp = KeyPair.generate()
    try:
        tok = legacy(kp, budget_usd=bad)
    except Exception:
        pytest.skip("token with non-finite budget cannot be built")
    with pytest.raises(TokenError) as e:
        JwtChain.verify(tok, kp.public_key_bytes())
    assert e.value.code == "token_malformed"
