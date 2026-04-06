"""Security self-audit for AIP tokens.

Inspects tokens for security issues beyond simple validity:
TTL hygiene, scope safety, budget limits, delegation chain integrity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aip_token.compact import CompactToken
    from aip_token.chained import ChainedToken

# Thresholds (configurable via proxy config, these are defaults)
MAX_TTL_SECONDS = 3600        # 1 hour
HIGH_BUDGET_USD = 10.0        # warn above this
HIGH_BUDGET_CENTS = 10000     # warn above this (chained)
MAX_SAFE_DEPTH = 5            # warn above this


@dataclass
class AuditResult:
    """Result of a security self-audit on a token."""
    passed: bool
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "warnings": self.warnings,
            "errors": self.errors,
        }


def audit_compact(token: "CompactToken") -> AuditResult:
    """Audit a verified compact (JWT) token for security issues."""
    warnings: list[str] = []
    errors: list[str] = []

    claims = token.claims

    # Empty scope is a security error -- token authorizes nothing
    if not claims.scope:
        errors.append("Empty scope: token authorizes no actions")

    # Wildcard scope is dangerous
    if "*" in claims.scope:
        warnings.append("Wildcard scope '*' grants unrestricted access")

    # TTL check
    ttl = claims.exp - claims.iat
    if ttl > MAX_TTL_SECONDS:
        warnings.append(
            f"TTL is {ttl}s ({ttl // 3600}h {(ttl % 3600) // 60}m), "
            f"exceeds recommended maximum of {MAX_TTL_SECONDS}s"
        )

    # Budget check
    if claims.budget_usd is not None and claims.budget_usd > HIGH_BUDGET_USD:
        warnings.append(
            f"Budget ${claims.budget_usd:.2f} exceeds "
            f"recommended maximum of ${HIGH_BUDGET_USD:.2f}"
        )

    passed = len(errors) == 0
    return AuditResult(passed=passed, warnings=warnings, errors=errors)


def audit_chained(token: "ChainedToken") -> AuditResult:
    """Audit a chained (Biscuit) token for security issues."""
    warnings: list[str] = []
    errors: list[str] = []

    # Depth check
    max_depth = token.max_depth()
    if max_depth > MAX_SAFE_DEPTH:
        warnings.append(
            f"Max delegation depth {max_depth} exceeds "
            f"recommended maximum of {MAX_SAFE_DEPTH}"
        )

    # Budget check (chained tokens use cents)
    # Parse budget from the authority block source (block 0) using the same
    # approach as ChainedToken.from_base64() -- block_source() is the only
    # stable introspection API exposed by biscuit-python.
    try:
        source = token._biscuit.block_source(0)
        if source and "budget(" in source:
            for line in source.split("\n"):
                line = line.strip().rstrip(";")
                if line.startswith("budget("):
                    # Extract integer between budget( and )
                    inner = line[len("budget("):-1]
                    try:
                        cents = int(inner)
                        if cents > HIGH_BUDGET_CENTS:
                            warnings.append(
                                f"Authority budget {cents} cents "
                                f"(${cents / 100:.2f}) exceeds recommended "
                                f"maximum of ${HIGH_BUDGET_CENTS / 100:.2f}"
                            )
                    except ValueError:
                        pass
                    break
    except (AttributeError, TypeError, Exception):
        pass  # Can't inspect budget, skip

    passed = len(errors) == 0
    return AuditResult(passed=passed, warnings=warnings, errors=errors)
