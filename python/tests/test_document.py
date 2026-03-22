"""Tests for aip_core.document module."""

import json
from datetime import datetime, timezone, timedelta

import pytest

from aip_core.crypto import KeyPair, verify
from aip_core.document import IdentityDocument
from aip_core.error import SignatureInvalid, VersionUnsupported


def _build_signed_document(
    kp: KeyPair,
    *,
    aip_version: str = "1.0",
    expires: str | None = None,
    key_valid_from: str | None = None,
    key_valid_until: str | None = None,
    extra_fields: dict | None = None,
) -> str:
    """Build a valid signed identity document JSON string."""
    multibase = kp.public_key_multibase()

    key_entry = {
        "id": "key-1",
        "type": "Ed25519",
        "public_key_multibase": multibase,
    }
    if key_valid_from is not None:
        key_entry["valid_from"] = key_valid_from
    if key_valid_until is not None:
        key_entry["valid_until"] = key_valid_until

    doc = {
        "aip": aip_version,
        "id": "aip:web:example.com/agents/assistant",
        "public_keys": [key_entry],
    }
    if expires is not None:
        doc["expires"] = expires
    if extra_fields:
        doc.update(extra_fields)

    # Compute canonical JSON (sorted keys, no whitespace, no document_signature)
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"))
    sig = kp.sign(canonical.encode("utf-8"))

    import base64
    doc["document_signature"] = base64.b64encode(sig).decode("ascii")

    return json.dumps(doc)


class TestParseValidDocument:
    def test_parse_valid_document(self):
        kp = KeyPair.generate()
        raw = _build_signed_document(kp)
        doc = IdentityDocument.from_json(raw)
        assert doc.aip == "1.0"
        assert doc.id == "aip:web:example.com/agents/assistant"
        assert len(doc.public_keys) == 1
        assert doc.public_keys[0].id == "key-1"
        assert doc.public_keys[0].type == "Ed25519"


class TestVerifySignature:
    def test_verify_signature(self):
        kp = KeyPair.generate()
        raw = _build_signed_document(kp)
        doc = IdentityDocument.from_json(raw)
        # Should not raise
        doc.verify_signature()

    def test_reject_tampered_signature(self):
        kp = KeyPair.generate()
        raw = _build_signed_document(kp)
        # Tamper with a field
        data = json.loads(raw)
        data["id"] = "aip:web:evil.com/agents/malicious"
        tampered = json.dumps(data)
        doc = IdentityDocument.from_json(tampered)
        with pytest.raises(SignatureInvalid):
            doc.verify_signature()


class TestExpired:
    def test_reject_expired(self):
        kp = KeyPair.generate()
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        raw = _build_signed_document(kp, expires=past)
        doc = IdentityDocument.from_json(raw)
        assert doc.is_expired(datetime.now(timezone.utc)) is True

    def test_not_expired(self):
        kp = KeyPair.generate()
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        raw = _build_signed_document(kp, expires=future)
        doc = IdentityDocument.from_json(raw)
        assert doc.is_expired(datetime.now(timezone.utc)) is False

    def test_no_expires_not_expired(self):
        kp = KeyPair.generate()
        raw = _build_signed_document(kp)
        doc = IdentityDocument.from_json(raw)
        assert doc.is_expired(datetime.now(timezone.utc)) is False


class TestFindValidKey:
    def test_find_valid_key(self):
        kp = KeyPair.generate()
        now = datetime.now(timezone.utc)
        valid_from = (now - timedelta(days=10)).isoformat()
        valid_until = (now + timedelta(days=10)).isoformat()
        raw = _build_signed_document(
            kp, key_valid_from=valid_from, key_valid_until=valid_until
        )
        doc = IdentityDocument.from_json(raw)
        key = doc.find_valid_key(now)
        assert key is not None
        assert key.id == "key-1"

    def test_find_valid_key_expired(self):
        kp = KeyPair.generate()
        now = datetime.now(timezone.utc)
        valid_from = (now - timedelta(days=20)).isoformat()
        valid_until = (now - timedelta(days=10)).isoformat()
        raw = _build_signed_document(
            kp, key_valid_from=valid_from, key_valid_until=valid_until
        )
        doc = IdentityDocument.from_json(raw)
        key = doc.find_valid_key(now)
        assert key is None

    def test_find_valid_key_no_bounds(self):
        kp = KeyPair.generate()
        raw = _build_signed_document(kp)
        doc = IdentityDocument.from_json(raw)
        key = doc.find_valid_key(datetime.now(timezone.utc))
        assert key is not None


class TestVersionCheck:
    def test_reject_unsupported_version(self):
        kp = KeyPair.generate()
        raw = _build_signed_document(kp, aip_version="2.0")
        doc = IdentityDocument.from_json(raw)
        with pytest.raises(VersionUnsupported):
            doc.check_version()

    def test_accept_version_1(self):
        kp = KeyPair.generate()
        raw = _build_signed_document(kp, aip_version="1.0")
        doc = IdentityDocument.from_json(raw)
        # Should not raise
        doc.check_version()

    def test_accept_version_1_1(self):
        kp = KeyPair.generate()
        raw = _build_signed_document(kp, aip_version="1.1")
        doc = IdentityDocument.from_json(raw)
        # Should not raise
        doc.check_version()
