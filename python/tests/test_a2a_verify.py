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


# --- JWT chain encoding -----------------------------------------------------

def _jwt_one_hop(orchestrator_id, researcher_id, tools):
    from aip_token.jwt_chain import JwtChain

    root_kp, holder_kp, leaf_kp = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    root = JwtChain.create_root(
        issuer=orchestrator_id, delegate="aip:web:acme.com/broker", tools=tools,
        max_depth=2, ttl_seconds=3600, issuer_keypair=root_kp,
        holder_public_key=holder_kp.public_key_bytes(), budget_cents=200,
    )
    chain = root.append(
        holder_keypair=holder_kp, delegate=researcher_id,
        next_holder_public_key=leaf_kp.public_key_bytes(), context="task-1",
    )
    return chain.serialize(), root_kp


def test_verify_jwt_chain_success():
    orchestrator = "aip:web:acme.com/orchestrator"
    researcher = "aip:web:acme.com/researcher"
    token, root_kp = _jwt_one_hop(orchestrator, researcher, ["research:read"])
    body = {"params": {"metadata": {"aip_token": token}}}
    result = verify_a2a_task(
        body,
        expected_audience=researcher,
        root_public_key_bytes=root_kp.public_key_bytes(),
        required_scope="research:read",
    )
    assert result.subject == researcher
    assert result.chain_depth == 1
    assert result.issuer == orchestrator


# --- JWT chain negatives and the truncation limitation ----------------------

def _body(token):
    return {"params": {"metadata": {"aip_token": token}}}


def test_jwt_audience_mismatch():
    token, root_kp = _jwt_one_hop("aip:web:acme.com/orchestrator",
                                  "aip:web:acme.com/researcher", ["research:read"])
    with pytest.raises(AudienceError):
        verify_a2a_task(_body(token), expected_audience="aip:web:acme.com/writer",
                        root_public_key_bytes=root_kp.public_key_bytes(),
                        required_scope="research:read")


def test_jwt_wrong_root_key():
    token, _ = _jwt_one_hop("aip:web:acme.com/orchestrator",
                            "aip:web:acme.com/researcher", ["research:read"])
    with pytest.raises(ChainError):
        verify_a2a_task(_body(token), expected_audience="aip:web:acme.com/researcher",
                        root_public_key_bytes=KeyPair.generate().public_key_bytes(),
                        required_scope="research:read")


def test_jwt_expired():
    import time
    from aip_a2a.error import ExpiryError
    from aip_token.jwt_chain import JwtChain

    root_kp, holder_kp, leaf_kp = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    past = int(time.time()) - 7200
    root = JwtChain.create_root(
        issuer="aip:web:acme.com/orchestrator", delegate="aip:web:acme.com/broker",
        tools=["research:read"], max_depth=2, ttl_seconds=60, issuer_keypair=root_kp,
        holder_public_key=holder_kp.public_key_bytes(), now=past)
    chain = root.append(holder_keypair=holder_kp, delegate="aip:web:acme.com/researcher",
                        next_holder_public_key=leaf_kp.public_key_bytes(),
                        context="task-1", now=past)
    with pytest.raises(ExpiryError):
        verify_a2a_task(_body(chain.serialize()),
                        expected_audience="aip:web:acme.com/researcher",
                        root_public_key_bytes=root_kp.public_key_bytes(),
                        required_scope="research:read")


def test_jwt_scope_denied():
    token, root_kp = _jwt_one_hop("aip:web:acme.com/orchestrator",
                                  "aip:web:acme.com/researcher", ["research:read"])
    with pytest.raises(ScopeError):
        verify_a2a_task(_body(token), expected_audience="aip:web:acme.com/researcher",
                        root_public_key_bytes=root_kp.public_key_bytes(),
                        required_scope="research:write")


def test_jwt_truncated_prefix_accepted_at_intermediate_audience():
    """Known limitation (CHANGELOG): without proof of possession a prefix of a
    valid chain verifies at the intermediate audience. With root->A->B->C, C can
    present the prefix ending at B to B's service. This pins current behaviour;
    it is not a desired property."""
    from aip_token.jwt_chain import JwtChain

    root_kp, a_kp, b_kp, c_kp = (KeyPair.generate() for _ in range(4))
    root = JwtChain.create_root(
        issuer="aip:web:acme.com/root", delegate="aip:web:acme.com/a",
        tools=["research:read"], max_depth=3, ttl_seconds=3600, issuer_keypair=root_kp,
        holder_public_key=a_kp.public_key_bytes())
    to_b = root.append(holder_keypair=a_kp, delegate="aip:web:acme.com/b",
                       next_holder_public_key=b_kp.public_key_bytes(), context="t1")
    to_c = to_b.append(holder_keypair=b_kp, delegate="aip:web:acme.com/c",
                       next_holder_public_key=c_kp.public_key_bytes(), context="t2")
    prefix = "~".join(to_c.serialize().split("~")[:2])
    assert prefix == to_b.serialize()
    result = verify_a2a_task(_body(prefix), expected_audience="aip:web:acme.com/b",
                             root_public_key_bytes=root_kp.public_key_bytes(),
                             required_scope="research:read")
    assert result.subject == "aip:web:acme.com/b"


def test_garbage_token_is_chain_error():
    kp = KeyPair.generate()
    with pytest.raises(ChainError):
        verify_a2a_task(_body("garbage"), expected_audience="x",
                        root_public_key_bytes=kp.public_key_bytes(),
                        required_scope="research:read")


def test_compact_token_rejected_by_a2a():
    import time
    from aip_token.claims import AipClaims
    from aip_token.compact import CompactToken

    kp = KeyPair.generate()
    now = int(time.time())
    tok = CompactToken.create(AipClaims(iss="aip:web:a.example", sub="aip:web:b.example",
                                        scope=["research:read"], max_depth=0,
                                        iat=now, exp=now + 300), kp)
    with pytest.raises(ChainError, match="compact"):
        verify_a2a_task(_body(tok), expected_audience="aip:web:b.example",
                        root_public_key_bytes=kp.public_key_bytes(),
                        required_scope="research:read")
