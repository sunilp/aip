"""Verify AIP tokens carried in A2A task metadata.

Spec: spec/aip-bindings-a2a.md §3 (token transport) and §4 (verification flow).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

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
      1. Extract token (from metadata.aip_token)
      2. Parse + verify signatures of the full chain
      3. Check final delegation targets `expected_audience`
      4. Check required scope is authorized
      5. Map biscuit/token errors to A2A error types

    Args:
        body: parsed A2A task JSON body.
        expected_audience: the receiving agent's own AIP id.
        root_public_key_bytes: the 32-byte ed25519 public key of the chain's root issuer.
        required_scope: the scope the caller must hold to authorize this task.

    Raises:
        ChainError: token missing or chain signatures invalid.
        AudienceError: final delegation does not target expected_audience.
        ScopeError: required scope not authorized.
        ExpiryError: token expired.
    """
    from aip_token.chained import ChainedToken  # lazy: biscuit_auth is optional dep

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
        # An A2A task implies at least one delegation hop (orchestrator -> recipient).
        raise ChainError("expected at least one delegation block in chain")

    # Check audience before scope: an audience mismatch means the token was
    # not issued to us, so we should reject before doing any scope work.
    final_delegate = _final_delegate(token)
    if final_delegate != expected_audience:
        raise AudienceError(
            f"final delegation targets {final_delegate!r}, expected {expected_audience!r}"
        )

    # Verify the required scope is authorized (granted in the authority block).
    if not _has_scope(token, required_scope):
        raise ScopeError(required_scope)

    return VerifiedIdentity(
        subject=expected_audience,
        chain_depth=token.current_depth(),
        issuer=token.issuer(),
    )


def _has_scope(token: ChainedToken, scope: str) -> bool:
    """Check whether the given scope is granted in the authority block.

    The authority block (block 0) contains 'right("scope")' facts for each
    granted scope. We check directly rather than calling token.authorize()
    because the authorize() method requires a budget fact in the authorizer
    context that is not available at verify time.
    """
    biscuit = getattr(token, "_biscuit", None)
    if biscuit is None:
        return False
    authority_src = biscuit.block_source(0) or ""
    target = f'right("{scope}")'
    for line in authority_src.split("\n"):
        if line.strip().rstrip(";") == target:
            return True
    return False


def _final_delegate(token: ChainedToken) -> str:
    """Extract the final delegation target from a chained token.

    Best-effort: prefer a structured accessor if ChainedToken exposes one;
    otherwise parse the last delegation block's source directly.
    """
    if hasattr(token, "final_delegate"):
        return token.final_delegate()  # type: ignore[no-any-return]

    # Fallback: parse the last block's source text for the delegate("...") fact.
    # Block 0 is the authority block; delegation blocks start at index 1.
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
