"""Verify AIP tokens carried in A2A task metadata.

Spec: spec/aip-bindings-a2a.md §3 (token transport) and §4 (verification flow).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from aip_a2a.error import AudienceError, ChainError, ExpiryError, ScopeError
from aip_token.error import TokenError

if TYPE_CHECKING:
    from aip_token.chained import ChainedToken


@dataclass(frozen=True)
class VerifiedIdentity:
    """The verified identity of the caller after successful chain verification."""

    subject: str
    chain_depth: int
    issuer: str


def extract_token_from_task(body: dict) -> str | None:
    """Read the aip_token from an A2A task body's metadata field.

    Spec §3: token MUST live at body.params.metadata.aip_token.
    """
    params = body.get("params") or {}
    metadata = params.get("metadata") or {}
    token = metadata.get("aip_token")
    return token if isinstance(token, str) else None


def verify_a2a_task(
    body: dict,
    *,
    expected_audience: str,
    root_public_key_bytes: bytes,
    required_scope: str,
) -> VerifiedIdentity:
    """Verify the AIP token carried in an A2A task body. Returns VerifiedIdentity on success.

    Implements the 6-step flow from spec §4 (verification side):
      1. Extract token (from metadata.aip_token).
      2. Parse + verify signatures of the full chain (ChainedToken.from_base64).
      3. Check final delegation targets `expected_audience`.
      4. Check required scope is authorized end-to-end (ChainedToken.authorize).
      5. Map biscuit/token errors to A2A error types.

    Raises:
        ChainError: token missing or chain signatures invalid.
        AudienceError: final delegation does not target expected_audience.
        ScopeError: required scope not authorized at any chain depth.
        ExpiryError: token expired.
    """
    from aip_token.chained import ChainedToken  # lazy: biscuit-python is optional dep

    token_str = extract_token_from_task(body)
    if not token_str:
        raise ChainError("missing aip_token in task metadata")

    try:
        token = ChainedToken.from_base64(token_str, root_public_key_bytes)
    except TokenError as exc:
        if exc.code == "aip_token_expired":
            raise ExpiryError() from exc
        raise ChainError(str(exc)) from exc

    if token.current_depth() < 1:
        raise ChainError("expected at least one delegation block in chain")

    # Audience check before scope: if the token was not issued to us, reject before
    # doing any policy evaluation. final_delegate() reads the deepest block's
    # `delegate("X")` fact, which was signed end-to-end by from_base64.
    final_delegate = _final_delegate(token)
    if final_delegate != expected_audience:
        raise AudienceError(
            f"final delegation targets {final_delegate!r}, expected {expected_audience!r}"
        )

    # Scope check: ChainedToken.authorize() re-verifies the full chain and
    # evaluates every block's `check if right(...)` rules — this enforces
    # scope attenuation across delegation hops.
    try:
        token.authorize(required_scope, root_public_key_bytes)
    except TokenError as exc:
        if exc.code == "aip_token_expired":
            raise ExpiryError() from exc
        raise ChainError(str(exc)) from exc
    except Exception as exc:
        # biscuit_auth.AuthorizationError or similar — the requested scope is not
        # authorized at some point in the chain.
        raise ScopeError(required_scope) from exc

    return VerifiedIdentity(
        subject=expected_audience,
        chain_depth=token.current_depth(),
        issuer=token.issuer(),
    )


def _final_delegate(token: ChainedToken) -> str:
    """Extract the final delegation target from a chained token.

    The biscuit chain's signatures are verified by from_base64 before we get here,
    so reading block source for the `delegate("X")` fact is safe — any tampering
    would have caused from_base64 to raise.
    """
    biscuit = getattr(token, "_biscuit", None)
    if biscuit is None:
        raise ChainError("cannot determine final delegate from token")

    block_count = biscuit.block_count()
    if block_count < 2:
        raise ChainError("token has no delegation block")

    last_block_src = biscuit.block_source(block_count - 1) or ""
    for line in last_block_src.split("\n"):
        line = line.strip().rstrip(";")
        if line.startswith('delegate("'):
            start = line.index('"') + 1
            end = line.rindex('"')
            return line[start:end]

    raise ChainError("token's last block has no delegate fact")
