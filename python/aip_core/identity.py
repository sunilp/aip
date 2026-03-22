"""AIP identity parsing and resolution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from aip_core.error import InvalidIdentifier


@dataclass(frozen=True)
class AipId:
    """Parsed AIP identifier.

    For web identifiers:  scheme="web", domain=..., path=... (path may be None)
    For key identifiers:  scheme="key", algorithm=..., public_key_multibase=...
    """

    scheme: str
    domain: Optional[str] = None
    path: Optional[str] = None
    algorithm: Optional[str] = None
    public_key_multibase: Optional[str] = None

    @classmethod
    def parse(cls, s: str) -> AipId:
        """Parse an AIP identifier string.

        Accepted formats:
          - aip:web:domain/path
          - aip:web:domain
          - aip:key:algorithm:multibase

        Raises InvalidIdentifier on malformed input.
        """
        if not s or not s.startswith("aip:"):
            raise InvalidIdentifier(f"not an AIP identifier: {s!r}")

        parts = s.split(":", maxsplit=2)
        if len(parts) < 3:
            raise InvalidIdentifier(f"too few segments: {s!r}")

        _, scheme, remainder = parts

        if scheme == "web":
            # remainder might be "domain/path" or just "domain"
            if "/" in remainder:
                domain, path = remainder.split("/", maxsplit=1)
                return cls(scheme="web", domain=domain, path=path)
            else:
                if not remainder:
                    raise InvalidIdentifier(f"empty domain: {s!r}")
                return cls(scheme="web", domain=remainder)

        elif scheme == "key":
            # remainder is "algorithm:multibase"
            key_parts = remainder.split(":", maxsplit=1)
            if len(key_parts) != 2 or not key_parts[1]:
                raise InvalidIdentifier(
                    f"key identifier must be aip:key:algorithm:multibase, got: {s!r}"
                )
            algorithm, multibase = key_parts
            return cls(
                scheme="key", algorithm=algorithm, public_key_multibase=multibase
            )

        else:
            raise InvalidIdentifier(f"unknown scheme: {scheme!r}")

    def resolution_url(self) -> Optional[str]:
        """Return the HTTPS resolution URL for web identifiers, or None for key identifiers."""
        if self.scheme != "web":
            return None
        if self.path:
            return f"https://{self.domain}/.well-known/aip/{self.path}.json"
        return f"https://{self.domain}/.well-known/aip.json"

    def __str__(self) -> str:
        if self.scheme == "web":
            if self.path:
                return f"aip:web:{self.domain}/{self.path}"
            return f"aip:web:{self.domain}"
        elif self.scheme == "key":
            return f"aip:key:{self.algorithm}:{self.public_key_multibase}"
        return f"aip:{self.scheme}"
