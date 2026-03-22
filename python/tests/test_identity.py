"""Tests for aip_core.identity module."""

import pytest

from aip_core.identity import AipId
from aip_core.error import InvalidIdentifier


class TestParseWeb:
    def test_parse_web(self):
        aid = AipId.parse("aip:web:example.com/agents/assistant")
        assert aid.scheme == "web"
        assert aid.domain == "example.com"
        assert aid.path == "agents/assistant"

    def test_parse_web_no_path(self):
        aid = AipId.parse("aip:web:example.com")
        assert aid.scheme == "web"
        assert aid.domain == "example.com"
        assert aid.path is None


class TestParseKey:
    def test_parse_key(self):
        aid = AipId.parse("aip:key:ed25519:z6Mkf5rGMoatrSj1f4CyvuHBeXJ")
        assert aid.scheme == "key"
        assert aid.algorithm == "ed25519"
        assert aid.public_key_multibase == "z6Mkf5rGMoatrSj1f4CyvuHBeXJ"


class TestDisplayRoundtrip:
    def test_display_roundtrip_web(self):
        s = "aip:web:example.com/agents/assistant"
        assert str(AipId.parse(s)) == s

    def test_display_roundtrip_web_no_path(self):
        s = "aip:web:example.com"
        assert str(AipId.parse(s)) == s

    def test_display_roundtrip_key(self):
        s = "aip:key:ed25519:z6Mkf5rGMoatrSj1f4CyvuHBeXJ"
        assert str(AipId.parse(s)) == s


class TestRejectInvalid:
    def test_reject_did_web(self):
        with pytest.raises(InvalidIdentifier):
            AipId.parse("did:web:example.com")

    def test_reject_empty(self):
        with pytest.raises(InvalidIdentifier):
            AipId.parse("")

    def test_reject_bad_scheme(self):
        with pytest.raises(InvalidIdentifier):
            AipId.parse("aip:ftp:example.com")

    def test_reject_key_missing_multibase(self):
        with pytest.raises(InvalidIdentifier):
            AipId.parse("aip:key:ed25519")


class TestResolutionUrl:
    def test_resolution_url(self):
        aid = AipId.parse("aip:web:example.com/agents/assistant")
        assert aid.resolution_url() == "https://example.com/.well-known/aip/agents/assistant.json"

    def test_resolution_url_no_path(self):
        aid = AipId.parse("aip:web:example.com")
        assert aid.resolution_url() == "https://example.com/.well-known/aip.json"

    def test_key_no_resolution_url(self):
        aid = AipId.parse("aip:key:ed25519:z6Mkf5rGMoatrSj1f4CyvuHBeXJ")
        assert aid.resolution_url() is None
