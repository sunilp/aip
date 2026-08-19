"""Canonical block encoding and the V4 attenuation walk (draft-prakash-aip-01).

Section 3.4.1 fixes the exact Datalog each implementation emits, and Section 4
step V4 requires a structural walk confirming every hop narrows its parent.
These tests pin both, because divergence here is invisible until a token
crosses an implementation boundary.
"""

import pytest

biscuit_auth = pytest.importorskip("biscuit_auth", reason="biscuit-python not installed")

from biscuit_auth import BlockBuilder

from aip_core.crypto import KeyPair
from aip_token.chained import ChainedToken
from aip_token.error import TokenError


def _forge(token, datalog):
    """Append a raw block, bypassing this library entirely.

    This is the adversary's position: they hold a valid token and a key, and
    they append whatever Datalog they like. The library's mint-time checks are
    not in their path, so only the verifier can catch them.
    """
    forged = token._biscuit.append(BlockBuilder(datalog))
    return ChainedToken(
        forged,
        token.issuer(),
        token.max_depth(),
        token._root_pubkey_bytes,
        depth=token.current_depth() + 1,
    )


def _authority(scopes=("tool:search", "tool:browse"), budget=500):
    kp = KeyPair.generate()
    return (
        ChainedToken.create_authority(
            issuer="aip:web:example.com/root",
            scopes=list(scopes),
            budget_cents=budget,
            max_depth=3,
            ttl_seconds=3600,
            keypair=kp,
        ),
        kp,
    )


# --- Canonical encoding ---------------------------------------------------


def test_authority_block_emits_tool_check():
    token, _ = _authority()
    src = token.block_source(0)
    assert 'check if tool($t), ["tool:search", "tool:browse"].contains($t)' in src


def test_authority_block_emits_budget_ceiling_fact():
    token, _ = _authority(budget=500)
    src = token.block_source(0)
    assert "budget_ceiling(500)" in src


def test_no_block_emits_a_budget_check():
    """A Datalog check over budget cannot express parent comparison. V4 does it."""
    token, _ = _authority()
    delegated = token.delegate(
        delegator="aip:web:example.com/root",
        delegate="aip:web:example.com/sub",
        scopes=["tool:search"],
        budget_cents=100,
        context="test",
    )
    for i in range(delegated.block_count()):
        assert "check if budget" not in delegated.block_source(i)


def test_delegation_block_emits_canonical_facts_and_check():
    token, _ = _authority()
    delegated = token.delegate(
        delegator="aip:web:example.com/root",
        delegate="aip:web:example.com/sub",
        scopes=["tool:search"],
        budget_cents=100,
        context="quarterly report",
    )
    src = delegated.block_source(1)
    assert 'delegator("aip:web:example.com/root")' in src
    assert 'delegate("aip:web:example.com/sub")' in src
    assert 'context("quarterly report")' in src
    assert "budget_ceiling(100)" in src
    assert 'check if tool($t), ["tool:search"].contains($t)' in src


# --- V4 structural attenuation walk ---------------------------------------


def test_delegating_a_scope_the_parent_lacks_is_refused_at_mint():
    token, _ = _authority(scopes=["tool:search"])
    with pytest.raises(TokenError):
        token.delegate(
            delegator="aip:web:example.com/root",
            delegate="aip:web:example.com/sub",
            scopes=["tool:email"],
            budget_cents=100,
            context="test",
        )


def test_raising_the_budget_ceiling_is_refused_at_mint():
    token, _ = _authority(budget=100)
    with pytest.raises(TokenError):
        token.delegate(
            delegator="aip:web:example.com/root",
            delegate="aip:web:example.com/sub",
            scopes=["tool:search"],
            budget_cents=500,
            context="test",
        )


def test_negative_budget_ceiling_is_refused():
    token, _ = _authority(budget=100)
    with pytest.raises(TokenError):
        token.delegate(
            delegator="aip:web:example.com/root",
            delegate="aip:web:example.com/sub",
            scopes=["tool:search"],
            budget_cents=-1,
            context="test",
        )


def test_verifier_rejects_a_chain_whose_budget_ceiling_widened():
    """V4 runs at verification, not only at mint, so a forged chain is caught."""
    token, kp = _authority(budget=100)
    forged = _forge(
        token,
        'delegator("aip:web:example.com/root");\n'
        'delegate("aip:web:example.com/sub");\n'
        'context("forged");\n'
        "budget_ceiling(500);\n"
        'check if tool($t), ["tool:search"].contains($t);\n',
    )
    with pytest.raises(TokenError) as exc:
        forged.authorize("tool:search", kp.public_key_bytes())
    assert exc.value.code == "budget_exceeded"


def test_verifier_rejects_a_chain_whose_scope_widened():
    token, kp = _authority(scopes=["tool:search"])
    forged = _forge(
        token,
        'delegator("aip:web:example.com/root");\n'
        'delegate("aip:web:example.com/sub");\n'
        'context("forged");\n'
        "budget_ceiling(50);\n"
        'check if tool($t), ["tool:search", "tool:email"].contains($t);\n',
    )
    with pytest.raises(TokenError) as exc:
        forged.authorize("tool:search", kp.public_key_bytes())
    assert exc.value.code == "scope_insufficient"


def test_empty_context_is_refused():
    token, _ = _authority()
    with pytest.raises(TokenError):
        token.delegate(
            delegator="aip:web:example.com/root",
            delegate="aip:web:example.com/sub",
            scopes=["tool:search"],
            budget_cents=100,
            context="",
        )


# --- Principal invariance (V4) --------------------------------------------


def test_principal_is_carried_and_invariant():
    kp = KeyPair.generate()
    token = ChainedToken.create_authority(
        issuer="aip:web:example.com/root",
        scopes=["tool:search"],
        budget_cents=500,
        max_depth=3,
        ttl_seconds=3600,
        keypair=kp,
        principal="user:alice@example.com",
    )
    assert 'principal("user:alice@example.com")' in token.block_source(0)

    forged = _forge(
        token,
        'delegator("aip:web:example.com/root");\n'
        'delegate("aip:web:example.com/sub");\n'
        'context("forged");\n'
        'principal("user:mallory@example.com");\n'
        'check if tool($t), ["tool:search"].contains($t);\n',
    )
    with pytest.raises(TokenError) as exc:
        forged.authorize("tool:search", kp.public_key_bytes())
    assert exc.value.code == "token_malformed"


# --- Wildcard scopes ------------------------------------------------------


def test_wildcard_authority_authorizes_a_specific_tool():
    """`tool:*` must actually authorize `tool:search`, not compare literally."""
    token, kp = _authority(scopes=["tool:*"])
    token.authorize("tool:search", kp.public_key_bytes())


def test_wildcard_authority_refuses_a_tool_outside_the_prefix():
    token, kp = _authority(scopes=["tool:*"])
    with pytest.raises(TokenError):
        token.authorize("admin:delete", kp.public_key_bytes())


def test_wildcard_narrows_to_specific_across_hops():
    token, kp = _authority(scopes=["tool:*"])
    delegated = token.delegate(
        delegator="aip:web:example.com/root",
        delegate="aip:web:example.com/sub",
        scopes=["tool:search"],
        budget_cents=100,
        context="narrow the wildcard",
    )
    delegated.authorize("tool:search", kp.public_key_bytes())
    with pytest.raises(TokenError):
        delegated.authorize("tool:browse", kp.public_key_bytes())


def test_specific_parent_cannot_widen_to_a_wildcard_child():
    token, _ = _authority(scopes=["tool:search"])
    with pytest.raises(TokenError):
        token.delegate(
            delegator="aip:web:example.com/root",
            delegate="aip:web:example.com/sub",
            scopes=["tool:*"],
            budget_cents=100,
            context="attempted widening",
        )


def test_mixed_exact_and_wildcard_scopes_both_authorize():
    token, kp = _authority(scopes=["report:daily", "tool:*"])
    token.authorize("report:daily", kp.public_key_bytes())
    token.authorize("tool:search", kp.public_key_bytes())
    with pytest.raises(TokenError):
        token.authorize("report:weekly", kp.public_key_bytes())
