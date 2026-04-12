"""aip-agents: AIP identity and delegation for AI agent frameworks."""

from aip_agents.core.config import AIPConfig
from aip_agents.core.identity_manager import AIPIdentity, IdentityManager
from aip_agents.core.token_manager import TokenManager
from aip_agents.core.key_store import KeyStore

__version__ = "0.2.0"

__all__ = [
    "AIPConfig",
    "AIPIdentity",
    "IdentityManager",
    "KeyStore",
    "TokenManager",
    "__version__",
]
