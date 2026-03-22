"""Compact token format: JWT with EdDSA (Ed25519) signatures."""

from __future__ import annotations

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aip_core.crypto import KeyPair
from aip_token.claims import AipClaims
from aip_token.error import TokenError


class CompactToken:
    """AIP compact token backed by a JWT with EdDSA signatures."""

    def __init__(self, claims: AipClaims) -> None:
        self._claims = claims

    @property
    def claims(self) -> AipClaims:
        """Return the verified claims."""
        return self._claims

    def has_scope(self, scope: str) -> bool:
        """Return True if *scope* is present in the token's scope list."""
        return scope in self._claims.scope

    # -- static / class methods -------------------------------------------

    @staticmethod
    def create(claims: AipClaims, keypair: KeyPair) -> str:
        """Create a signed compact token (JWT) from *claims* using *keypair*.

        The resulting JWT carries header ``{"alg": "EdDSA", "typ": "aip+jwt"}``.
        """
        payload = claims.model_dump(mode="json")
        token: str = jwt.encode(
            payload,
            keypair._private_key,
            algorithm="EdDSA",
            headers={"typ": "aip+jwt"},
        )
        return token

    @staticmethod
    def verify(token_str: str, public_key_bytes: bytes) -> CompactToken:
        """Verify *token_str* against the given raw public key bytes.

        Returns a ``CompactToken`` with the decoded claims on success.
        Raises ``TokenError`` on any failure (expired, bad signature, malformed).
        """
        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            payload = jwt.decode(
                token_str,
                public_key,
                algorithms=["EdDSA"],
            )
            claims = AipClaims(**payload)
            return CompactToken(claims)
        except jwt.ExpiredSignatureError:
            raise TokenError.token_expired()
        except jwt.InvalidSignatureError:
            raise TokenError.signature_invalid()
        except jwt.DecodeError as exc:
            raise TokenError.token_malformed(str(exc))
        except Exception as exc:
            raise TokenError.token_malformed(str(exc))

    @staticmethod
    def decode_header(token_str: str) -> dict:
        """Decode the JWT header without verifying the signature."""
        return jwt.get_unverified_header(token_str)
