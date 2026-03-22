"""Cryptographic primitives for AIP: Ed25519 key pairs, signing, and verification."""

from __future__ import annotations

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.exceptions import InvalidSignature


class KeyPair:
    """Ed25519 key pair for AIP identity operations."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls) -> KeyPair:
        """Generate a new Ed25519 key pair."""
        return cls(Ed25519PrivateKey.generate())

    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte public key."""
        return self._private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    def public_key_multibase(self) -> str:
        """Return the public key as a z-prefix base58btc multibase string."""
        return "z" + base58.b58encode(self.public_key_bytes()).decode("ascii")

    @staticmethod
    def decode_multibase(s: str) -> bytes:
        """Decode a z-prefix base58btc multibase string to raw bytes."""
        if not s.startswith("z"):
            raise ValueError("multibase string must start with 'z' (base58btc)")
        return base58.b58decode(s[1:])

    def sign(self, message: bytes) -> bytes:
        """Sign a message with Ed25519 and return the 64-byte signature."""
        return self._private_key.sign(message)


def sign(kp: KeyPair, message: bytes) -> bytes:
    """Sign a message using the given key pair."""
    return kp.sign(message)


def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature. Returns True if valid, False otherwise."""
    pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        pub.verify(signature, message)
        return True
    except InvalidSignature:
        return False
