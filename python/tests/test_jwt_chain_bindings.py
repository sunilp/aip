import pytest

from aip_core.crypto import KeyPair
from aip_mcp.audit import audit_jwt_chain
from aip_mcp.middleware import detect_mode, verify_request
from aip_token.error import TokenError
from aip_token.jwt_chain import JwtChain


def chain(kp_root, holder, **kw):
    args = dict(issuer="aip:web:a.example", delegate="aip:web:b.example",
                tools=["tool:search"], max_depth=1, ttl_seconds=300,
                issuer_keypair=kp_root, holder_public_key=holder.public_key_bytes(),
                budget_cents=200)
    args.update(kw)
    return JwtChain.create_root(**args)


def test_detect_mode_jwt_chain():
    root, holder = KeyPair.generate(), KeyPair.generate()
    assert detect_mode(chain(root, holder).serialize()) == "jwt-chain"


def test_middleware_verifies_jwt_chain():
    root, holder = KeyPair.generate(), KeyPair.generate()
    headers = {"X-AIP-Token": chain(root, holder).serialize()}
    verified = verify_request(headers, root.public_key_bytes(), "tool:search")
    assert verified.issuer() == "aip:web:a.example"
    with pytest.raises(TokenError):
        verify_request(headers, root.public_key_bytes(), "tool:delete")


def test_audit_jwt_chain_limits():
    root, holder = KeyPair.generate(), KeyPair.generate()
    tok = JwtChain.verify(chain(root, holder, max_depth=4, budget_cents=90000).serialize(),
                          root.public_key_bytes())
    result = audit_jwt_chain(tok, max_depth=2, max_budget_cents=1000)
    assert not result.passed
    assert len(result.errors) == 2
