"""AIP token claims model."""

from __future__ import annotations

from pydantic import BaseModel


class AipClaims(BaseModel):
    """Claims carried inside an AIP compact token (JWT)."""

    iss: str
    """Issuer AIP identifier."""

    sub: str
    """Subject AIP identifier."""

    scope: list[str]
    """List of scope strings (e.g. 'tool:search')."""

    budget_usd: float | None = None
    """Optional budget ceiling in USD."""

    max_depth: int = 0
    """Maximum delegation depth. 0 means no further delegation allowed."""

    iat: int
    """Issued-at unix timestamp."""

    exp: int
    """Expiry unix timestamp."""
