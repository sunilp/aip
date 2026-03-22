"""Delegation block metadata for AIP chained tokens."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DelegationBlock:
    """Metadata describing a single delegation step in a chained token."""

    delegator: str
    delegate: str
    scopes: list[str]
    budget_cents: int | None
    context: str
