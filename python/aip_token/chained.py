"""ChainedToken: Biscuit-backed delegation tokens for AIP.

Bridges AIP's Ed25519 key pairs with biscuit-python to provide
cryptographically attenuated delegation chains.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from biscuit_auth import (
    AuthorizerBuilder,
    Biscuit,
    BiscuitBuilder,
    BlockBuilder,
    Fact,
    PrivateKey as BiscuitPrivateKey,
    PublicKey as BiscuitPublicKey,
    Rule,
)

from aip_core.crypto import KeyPair
from aip_token.error import TokenError

# biscuit-python >= 0.4 requires an Algorithm argument for from_bytes();
# older versions do not.  Detect at import time.
try:
    from biscuit_auth import Algorithm as _Algorithm
    _ED25519 = _Algorithm.Ed25519
except ImportError:
    _ED25519 = None  # type: ignore[assignment]


def _biscuit_private_key(keypair: KeyPair) -> BiscuitPrivateKey:
    """Convert an AIP KeyPair's private key to a biscuit PrivateKey."""
    raw = keypair.private_key_bytes()
    if _ED25519 is not None:
        return BiscuitPrivateKey.from_bytes(raw, _ED25519)
    return BiscuitPrivateKey.from_bytes(raw)  # type: ignore[call-arg]


def _biscuit_public_key(raw_bytes: bytes) -> BiscuitPublicKey:
    """Convert raw 32-byte public key bytes to a biscuit PublicKey."""
    if _ED25519 is not None:
        return BiscuitPublicKey.from_bytes(raw_bytes, _ED25519)
    return BiscuitPublicKey.from_bytes(raw_bytes)  # type: ignore[call-arg]


class ChainedToken:
    """A Biscuit-based chained delegation token.

    Supports creating authority tokens, delegating with attenuation,
    serialization/deserialization, and authorization checks.
    """

    def __init__(
        self,
        biscuit: Biscuit,
        issuer_str: str,
        max_depth_val: int,
        root_pubkey_bytes: bytes | None = None,
        depth: int = 0,
    ) -> None:
        self._biscuit = biscuit
        self._issuer = issuer_str
        self._max_depth = max_depth_val
        self._root_pubkey_bytes = root_pubkey_bytes
        self._depth = depth

    @staticmethod
    def create_authority(
        issuer: str,
        scopes: list[str],
        budget_cents: int | None,
        max_depth: int,
        ttl_seconds: int,
        keypair: KeyPair,
    ) -> ChainedToken:
        """Create a new authority (root) token."""
        biscuit_private = _biscuit_private_key(keypair)

        expiry = datetime.now(tz=timezone.utc) + timedelta(seconds=ttl_seconds)

        facts = f'identity("{issuer}");\n'
        for scope in scopes:
            facts += f'right("{scope}");\n'
        if budget_cents is not None:
            facts += f"budget({budget_cents});\n"
        facts += f"max_depth({max_depth});\n"
        facts += f'check if time($t), $t <= {expiry.strftime("%Y-%m-%dT%H:%M:%SZ")};\n'

        builder = BiscuitBuilder(facts)
        biscuit = builder.build(biscuit_private)

        return ChainedToken(
            biscuit,
            issuer,
            max_depth,
            keypair.public_key_bytes(),
            depth=0,
        )

    def delegate(
        self,
        delegator: str,
        delegate: str,
        scopes: list[str],
        budget_cents: int | None,
        context: str,
    ) -> ChainedToken:
        """Create a delegated (attenuated) token by appending a block.

        Raises TokenError if context is empty or delegation depth is exceeded.
        """
        if not context or not context.strip():
            raise TokenError("Context must be non-empty", "aip_token_malformed")

        if self._depth >= self._max_depth:
            raise TokenError("Delegation depth exceeded", "aip_depth_exceeded")

        checks = f'delegator("{delegator}");\n'
        checks += f'delegate("{delegate}");\n'
        checks += f'context("{context}");\n'
        for scope in scopes:
            checks += f'check if right("{scope}");\n'
        if budget_cents is not None:
            checks += f"check if budget($b), $b <= {budget_cents};\n"

        block = BlockBuilder(checks)
        new_biscuit = self._biscuit.append(block)

        return ChainedToken(
            new_biscuit,
            self._issuer,
            self._max_depth,
            self._root_pubkey_bytes,
            depth=self._depth + 1,
        )

    def authorize(self, tool: str, root_public_key_bytes: bytes) -> None:
        """Verify the token chain and authorize a specific tool invocation.

        Re-verifies from serialized form to ensure the full chain is valid.
        Raises on authorization failure.
        """
        biscuit_pubkey = _biscuit_public_key(root_public_key_bytes)
        serialized = self._biscuit.to_base64()
        verified = Biscuit.from_base64(serialized, biscuit_pubkey)

        now = datetime.now(tz=timezone.utc)
        auth_code = (
            f'tool("{tool}");\n'
            f'time({now.strftime("%Y-%m-%dT%H:%M:%SZ")});\n'
            f"depth({self._depth});\n"
            f'allow if right("{tool}");\n'
        )
        authorizer = AuthorizerBuilder(auth_code).build(verified)
        authorizer.authorize()

    def to_base64(self) -> str:
        """Serialize the token to a URL-safe base64 string."""
        return self._biscuit.to_base64()

    @staticmethod
    def from_base64(s: str, root_public_key_bytes: bytes) -> ChainedToken:
        """Deserialize a token from base64 and verify against the root public key."""
        biscuit_pubkey = _biscuit_public_key(root_public_key_bytes)
        biscuit = Biscuit.from_base64(s, biscuit_pubkey)

        # Extract issuer and max_depth by parsing the authority block source.
        # We avoid using Authorizer here because it triggers all checks
        # (tool, time) which have no matching facts during deserialization.
        issuer = "unknown"
        max_depth = 3
        try:
            source = biscuit.block_source(0)
            if source:
                for line in source.split("\n"):
                    line = line.strip().rstrip(";")
                    if line.startswith("identity("):
                        # Extract string between quotes: identity("aip:web:...")
                        start = line.index('"') + 1
                        end = line.rindex('"')
                        issuer = line[start:end]
                    elif line.startswith("max_depth("):
                        val = line[len("max_depth("):-1]
                        max_depth = int(val)
        except Exception:
            pass

        # Depth is block_count - 1 (authority block is block 0)
        depth = biscuit.block_count() - 1

        return ChainedToken(biscuit, issuer, max_depth, root_public_key_bytes, depth=depth)

    def issuer(self) -> str:
        """Return the token issuer identity."""
        return self._issuer

    def max_depth(self) -> int:
        """Return the maximum delegation depth."""
        return self._max_depth

    def current_depth(self) -> int:
        """Return the current delegation depth (0 for authority tokens)."""
        return self._depth
