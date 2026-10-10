"""V3, V4, V5 and the request check over the encoding-neutral link model
(draft-prakash-aip-02 Sections 3 and 4)."""

import pytest

from aip_token.chain_model import Link, authorize_request, covers, verify_links
from aip_token.error import TokenError

NOW = 1_800_000_000


def root(**kw):
    base = dict(
        issuer="aip:web:a.example", delegate="aip:web:b.example",
        tools=frozenset({"tool:search", "tool:write"}), expiry=NOW + 600, max_depth=3,
    )
    base.update(kw)
    return Link(**base)


def hop(**kw):
    base = dict(issuer="aip:web:b.example", delegate="aip:web:c.example", context="summarize report")
    base.update(kw)
    return Link(**base)


def code(exc_info):
    return exc_info.value.code


def test_covers():
    assert covers("tool:search", "tool:search")
    assert covers("*", "tool:anything")
    assert covers("tool:*", "tool:search")
    assert not covers("tool:search", "tool:*")
    assert not covers("tool:search", "tool:write")


def test_single_link_effective_is_root():
    eff = verify_links([root()], NOW)
    assert eff.tools == frozenset({"tool:search", "tool:write"})
    assert eff.max_depth == 3


def test_inheritance_fills_absent_dimensions():
    eff = verify_links([root(budget_cents=500, domains=frozenset({"a.com"})), hop()], NOW)
    assert eff.tools == frozenset({"tool:search", "tool:write"})
    assert eff.budget_cents == 500
    assert eff.domains == frozenset({"a.com"})
    assert eff.delegate == "aip:web:c.example"


def test_narrowing_is_accepted():
    eff = verify_links(
        [root(budget_cents=500, domains=frozenset({"a.com", "b.com"})),
         hop(tools=frozenset({"tool:search"}), budget_cents=100,
             domains=frozenset({"a.com"}), expiry=NOW + 60)],
        NOW,
    )
    assert eff.tools == frozenset({"tool:search"})
    assert eff.budget_cents == 100
    assert eff.expiry == NOW + 60


@pytest.mark.parametrize("bad_hop,expected", [
    (dict(tools=frozenset({"tool:delete"})), "scope_insufficient"),
    (dict(domains=frozenset({"evil.com"})), "scope_insufficient"),
    (dict(budget_cents=900), "budget_exceeded"),
    (dict(budget_cents=-1), "budget_exceeded"),
    (dict(expiry=NOW + 6000), "token_expired"),
    (dict(principal="user:mallory"), "token_malformed"),
    (dict(context=""), "token_malformed"),
    (dict(context=None), "token_malformed"),
    (dict(max_depth=9), "token_malformed"),
])
def test_widening_or_malformed_hop_is_rejected(bad_hop, expected):
    with pytest.raises(TokenError) as e:
        verify_links(
            [root(budget_cents=500, domains=frozenset({"a.com"}), principal="user:alice"),
             hop(**bad_hop)],
            NOW,
        )
    assert code(e) == expected


def test_wildcard_parent_permits_specific_child():
    verify_links([root(tools=frozenset({"tool:*"})), hop(tools=frozenset({"tool:search"}))], NOW)


def test_specific_parent_cannot_widen_to_wildcard():
    with pytest.raises(TokenError) as e:
        verify_links([root(tools=frozenset({"tool:search"})), hop(tools=frozenset({"tool:*"}))], NOW)
    assert code(e) == "scope_insufficient"


def test_depth_exceeded():
    links = [root(max_depth=1), hop(), hop(issuer="aip:web:c.example", delegate="aip:web:d.example")]
    with pytest.raises(TokenError) as e:
        verify_links(links, NOW)
    assert code(e) == "depth_exceeded"


def test_expired_root():
    with pytest.raises(TokenError) as e:
        verify_links([root(expiry=NOW - 1)], NOW)
    assert code(e) == "token_expired"


@pytest.mark.parametrize("missing", ["tools", "expiry", "max_depth"])
def test_root_missing_required_field(missing):
    with pytest.raises(TokenError) as e:
        verify_links([root(**{missing: None})], NOW)
    assert code(e) == "token_malformed"


def test_empty_chain():
    with pytest.raises(TokenError) as e:
        verify_links([], NOW)
    assert code(e) == "token_malformed"


def test_authorize_request():
    eff = verify_links([root(domains=frozenset({"a.com"}))], NOW)
    authorize_request(eff, "tool:search")
    authorize_request(eff, "tool:search", "a.com")
    with pytest.raises(TokenError) as e:
        authorize_request(eff, "tool:delete")
    assert code(e) == "scope_insufficient"
    with pytest.raises(TokenError) as e:
        authorize_request(eff, "tool:search", "b.com")
    assert code(e) == "scope_insufficient"


def test_wire_code_prefixes_once():
    assert TokenError("x", "scope_insufficient").wire_code == "aip_scope_insufficient"
    assert TokenError("x", "aip_scope_insufficient").wire_code == "aip_scope_insufficient"


@pytest.mark.parametrize("field", ["tools", "domains"])
def test_empty_allowlist_on_root_is_malformed(field):
    with pytest.raises(TokenError) as e:
        verify_links([root(**{field: frozenset()})], NOW)
    assert e.value.code == "token_malformed"


@pytest.mark.parametrize("field", ["tools", "domains"])
def test_empty_allowlist_on_hop_is_malformed(field):
    hop = Link(issuer="aip:web:b.example", delegate="aip:web:c.example",
               context="x", **{field: frozenset()})
    with pytest.raises(TokenError) as e:
        verify_links([root(domains=frozenset({"a.com"})), hop], NOW)
    assert e.value.code == "token_malformed"
