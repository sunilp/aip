"""AIP Identity Document model, parsing, signing, and verification."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from aip_core.crypto import KeyPair, verify
from aip_core.error import (
    DocumentExpired,
    InvalidDocument,
    SignatureInvalid,
    VersionUnsupported,
)


class PublicKeyEntry(BaseModel):
    """A single public key entry in an identity document."""

    id: str
    type: str
    public_key_multibase: str
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None


class IdentityDocument(BaseModel):
    """AIP Identity Document."""

    aip: str
    id: str
    public_keys: List[PublicKeyEntry] = Field(default_factory=list)
    name: Optional[str] = None
    delegation: Optional[Dict[str, Any]] = None
    protocols: Optional[List[Dict[str, Any]]] = None
    revocation: Optional[Dict[str, Any]] = None
    extensions: Optional[Dict[str, Any]] = None
    document_signature: Optional[str] = None
    expires: Optional[str] = None

    @classmethod
    def from_json(cls, s: str) -> IdentityDocument:
        """Parse and validate a JSON identity document string."""
        try:
            data = json.loads(s)
        except json.JSONDecodeError as exc:
            raise InvalidDocument(f"invalid JSON: {exc}") from exc
        return cls.model_validate(data)

    def canonical_json(self) -> str:
        """Return the canonical JSON representation.

        Canonical form: sorted keys, no whitespace, document_signature field excluded.
        """
        data = self.model_dump(exclude_none=True)
        data.pop("document_signature", None)
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    def verify_signature(self) -> None:
        """Verify the document signature against the first public key.

        Raises SignatureInvalid if the signature is missing or does not match.
        """
        if not self.document_signature:
            raise SignatureInvalid("document_signature is missing")
        if not self.public_keys:
            raise SignatureInvalid("no public keys in document")

        # Decode the base64 signature
        try:
            sig_bytes = base64.b64decode(self.document_signature)
        except Exception as exc:
            raise SignatureInvalid(f"invalid base64 signature: {exc}") from exc

        # Get the first public key
        key_entry = self.public_keys[0]
        pub_bytes = KeyPair.decode_multibase(key_entry.public_key_multibase)

        canonical = self.canonical_json()
        if not verify(pub_bytes, canonical.encode("utf-8"), sig_bytes):
            raise SignatureInvalid("document signature verification failed")

    def find_valid_key(self, at: datetime) -> Optional[PublicKeyEntry]:
        """Find the first public key valid at the given datetime.

        A key is valid if:
          - valid_from is None or at >= valid_from
          - valid_until is None or at <= valid_until
        """
        for key in self.public_keys:
            if key.valid_from is not None:
                vf = datetime.fromisoformat(key.valid_from)
                if at < vf:
                    continue
            if key.valid_until is not None:
                vu = datetime.fromisoformat(key.valid_until)
                if at > vu:
                    continue
            return key
        return None

    def check_version(self) -> None:
        """Check that the document version is supported (major version <= 1).

        Raises VersionUnsupported if the major version exceeds 1.
        """
        try:
            major = int(self.aip.split(".")[0])
        except (ValueError, IndexError) as exc:
            raise VersionUnsupported(f"cannot parse version: {self.aip!r}") from exc
        if major > 1:
            raise VersionUnsupported(f"unsupported AIP version: {self.aip}")

    def is_expired(self, at: datetime) -> bool:
        """Return True if the document has expired at the given datetime."""
        if self.expires is None:
            return False
        exp = datetime.fromisoformat(self.expires)
        return at >= exp
