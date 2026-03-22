"""aip_token: JWT-based token issuance and verification for the Agent Identity Protocol."""

from aip_token.claims import AipClaims
from aip_token.compact import CompactToken
from aip_token.delegation import DelegationBlock
from aip_token.error import TokenError
from aip_token.policy import SimplePolicy

try:
    from aip_token.chained import ChainedToken
except ImportError:
    ChainedToken = None  # type: ignore[assignment,misc]

__all__ = [
    "AipClaims",
    "ChainedToken",
    "CompactToken",
    "DelegationBlock",
    "SimplePolicy",
    "TokenError",
]
