"""Tests for aip_a2a.agent_card — parsing the aip_identity extension."""
import pytest
from aip_a2a.agent_card import AipIdentity, parse_aip_identity, AgentCardError


def test_parse_web_identity_full():
    card = {
        "name": "Researcher",
        "skills": [],
        "aip_identity": {
            "id": "aip:web:acme.com/agents/researcher",
            "document_url": "https://acme.com/.well-known/aip/agents/researcher.json",
        },
    }
    ident = parse_aip_identity(card)
    assert isinstance(ident, AipIdentity)
    assert ident.id == "aip:web:acme.com/agents/researcher"
    assert ident.document_url == "https://acme.com/.well-known/aip/agents/researcher.json"


def test_parse_key_identity_no_url_required():
    card = {
        "aip_identity": {"id": "aip:key:base58hash..."},
    }
    ident = parse_aip_identity(card)
    assert ident.id == "aip:key:base58hash..."
    assert ident.document_url is None


def test_parse_missing_extension_returns_none():
    assert parse_aip_identity({"name": "X"}) is None


def test_parse_missing_id_raises():
    with pytest.raises(AgentCardError) as exc:
        parse_aip_identity({"aip_identity": {"document_url": "https://x.com/d.json"}})
    assert "id" in str(exc.value)


def test_parse_invalid_id_format_raises():
    with pytest.raises(AgentCardError) as exc:
        parse_aip_identity({"aip_identity": {"id": "not-an-aip-id"}})
    assert "aip:" in str(exc.value)


def test_parse_web_id_requires_https_document_url():
    with pytest.raises(AgentCardError) as exc:
        parse_aip_identity({
            "aip_identity": {
                "id": "aip:web:acme.com/agent",
                "document_url": "http://acme.com/d.json",  # http, not https
            }
        })
    assert "https" in str(exc.value).lower()


def test_parse_web_id_missing_document_url_raises():
    with pytest.raises(AgentCardError) as exc:
        parse_aip_identity({"aip_identity": {"id": "aip:web:acme.com/agent"}})
    assert "document_url" in str(exc.value)
