"""draft-prakash-aip-02 Section 4, asserted for both encodings.

Each case builds a legitimate root, then an attacker-controlled delegation
that violates one MUST, and checks the verifier rejects it with the draft's
error code. Biscuit attackers append blocks directly (they do not run the
mint-time checks); JWT attackers sign forged links with the holder key.
"""

import base64
import hashlib
import time

import jwt
import pytest

from aip_core.crypto import KeyPair
from aip_token.error import TokenError
from aip_token.jwt_chain import JwtChain, holder_jwk

biscuit_auth = pytest.importorskip("biscuit_auth")
from biscuit_auth import BlockBuilder  # noqa: E402

from aip_token.canonical import int_fact, str_fact, tool_check  # noqa: E402
from aip_token.chained import ChainedToken  # noqa: E402

ROOT_ID, B_ID, C_ID = "aip:web:a.example", "aip:web:b.example", "aip:web:c.example"

VIOLATIONS = {
    "tool_widening": ({"tools": ["tool:delete"]}, "scope_insufficient", "widens tools"),
    "domain_widening": ({"domains": ["evil.com"]}, "scope_insufficient", "widens domains"),
    "budget_raise": ({"budget": 900}, "budget_exceeded", "budget"),
    "principal_swap": ({"principal": "user:mallory"}, "token_malformed", "substitutes the principal"),
    "missing_context": ({"context": ""}, "token_malformed", "has no context"),
}


def biscuit_attack(spec):
    kp = KeyPair.generate()
    tok = ChainedToken.create_authority(
        issuer=ROOT_ID, scopes=["tool:search"], budget_cents=500, max_depth=3,
        ttl_seconds=600, keypair=kp, principal="user:alice", domains=["a.com"])
    block = str_fact("delegator", ROOT_ID) + str_fact("delegate", B_ID)
    if spec.get("context", "work"):
        block += str_fact("context", spec.get("context", "work"))
    if "tools" in spec:
        block += tool_check(spec["tools"])
    for d in spec.get("domains", []):
        block += str_fact("domain", d)
    if "budget" in spec:
        block += int_fact("budget_ceiling", spec["budget"])
    if "principal" in spec:
        block += str_fact("principal", spec["principal"])
    forged = tok._biscuit.append(BlockBuilder(block))
    restored = ChainedToken.from_base64(forged.to_base64(), kp.public_key_bytes())
    return lambda: restored.verify_chain(kp.public_key_bytes())


def jwt_attack(spec):
    root_kp, b_kp, c_kp = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    root = JwtChain.create_root(
        issuer=ROOT_ID, delegate=B_ID, tools=["tool:search"], max_depth=3, ttl_seconds=600,
        issuer_keypair=root_kp, holder_public_key=b_kp.public_key_bytes(),
        budget_cents=500, domains=["a.com"], principal="user:alice")
    first = root.serialize()
    body = {"iss": B_ID, "sub": C_ID, "iat": int(time.time()), "jti": "x",
            "prev": base64.urlsafe_b64encode(hashlib.sha256(first.encode()).digest()).rstrip(b"=").decode(),
            "aip_ctx": spec.get("context", "work"),
            "cnf": {"jwk": holder_jwk(c_kp.public_key_bytes())}}
    if "tools" in spec:
        body["aip_tools"] = spec["tools"]
    if "domains" in spec:
        body["aip_domains"] = spec["domains"]
    if "budget" in spec:
        body["aip_budget_cents"] = spec["budget"]
    if "principal" in spec:
        body["aip_principal"] = spec["principal"]
    forged = jwt.encode(body, b_kp._private_key, algorithm="EdDSA", headers={"typ": "aip-link+jwt"})
    return lambda: JwtChain.verify(f"{first}~{forged}", root_kp.public_key_bytes())


@pytest.mark.parametrize("encoding", [biscuit_attack, jwt_attack], ids=["biscuit", "jwt"])
@pytest.mark.parametrize("name", sorted(VIOLATIONS))
def test_violation_rejected_in_both_encodings(encoding, name):
    spec, expected, reason = VIOLATIONS[name]
    with pytest.raises(TokenError) as e:
        encoding(spec)()
    assert e.value.code == expected
    assert reason in str(e.value)
