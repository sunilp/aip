"""Append a delegation block to a chained token before forwarding via A2A.

Thin wrapper around aip_token.chained.ChainedToken.delegate() that enforces the
A2A-specific rule that `context` MUST be non-empty (spec §4 step 3).
"""

from __future__ import annotations

from aip_token.chained import ChainedToken


def append_delegation_block(
    token: ChainedToken,
    *,
    delegator: str,
    delegate: str,
    scopes: list[str],
    context: str,
    budget_cents: int | None = None,
) -> ChainedToken:
    """Append a delegation block to a chained token.

    Args:
        token: existing chained token (authority or already-delegated).
        delegator: AIP id of the agent doing the delegation.
        delegate: AIP id of the agent being delegated to.
        scopes: scope subset to grant; MUST be a subset of the parent's scopes.
        context: non-empty per-task context string. Required by spec §4.
        budget_cents: optional budget ceiling for this delegation block.

    Returns:
        A new ChainedToken with one additional delegation block.

    Raises:
        ValueError: if context is empty.
    """
    if not context or not context.strip():
        raise ValueError("delegation context MUST be non-empty (spec §4 step 3)")
    return token.delegate(
        delegator=delegator,
        delegate=delegate,
        scopes=scopes,
        budget_cents=budget_cents,
        context=context,
    )
