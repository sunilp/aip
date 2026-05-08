"""aip_a2a: AIP binding for the Agent-to-Agent (A2A) protocol."""

from aip_a2a.agent_card import AipIdentity, AgentCardError, parse_aip_identity
from aip_a2a.error import (
    A2AError,
    AudienceError,
    ChainError,
    DepthError,
    ExpiryError,
    ScopeError,
    a2a_error_response,
)

__version__ = "0.3.0"

__all__ = [
    "AipIdentity",
    "AgentCardError",
    "parse_aip_identity",
    "A2AError",
    "AudienceError",
    "ChainError",
    "DepthError",
    "ExpiryError",
    "ScopeError",
    "a2a_error_response",
]
