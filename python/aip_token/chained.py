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


def _biscuit_private_key(keypair: KeyPair) -> BiscuitPrivateKey:
    """Convert an AIP KeyPair's private key to a biscuit PrivateKey."""
    return BiscuitPrivateKey.from_bytes(keypair.private_key_bytes())


def _biscuit_public_key(raw_bytes: bytes) -> BiscuitPublicKey:
    """Convert raw 32-byte public key bytes to a biscuit PublicKey."""
    return BiscuitPublicKey.from_bytes(raw_bytes)


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

        # Extract issuer and max_depth from authority block via an authorizer
        auth_code = "allow if true;"
        authorizer = AuthorizerBuilder(auth_code).build(biscuit)
        authorizer.authorize()

        # Query identity fact
        identities = authorizer.query(Rule("data($id) <- identity($id)"))
        issuer = "unknown"
        if identities:
            terms = identities[0].terms
            if terms:
                issuer = str(terms[0])

        # Query max_depth fact
        depths = authorizer.query(Rule("data($d) <- max_depth($d)"))
        max_depth = 3
        if depths:
            terms = depths[0].terms
            if terms:
                max_depth = int(terms[0])

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
