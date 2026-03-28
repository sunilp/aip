import time

from aip_agents.core.config import AIPConfig
from aip_agents.core.identity_manager import IdentityManager
from aip_token.claims import AipClaims
from aip_token.compact import CompactToken
from aip_token.chained import ChainedToken
from aip_token.error import TokenError


class TokenManager:
    """Issues compact tokens and chained delegation tokens for agents."""

    DEFAULT_TTL = 3600

    def __init__(self, identity_manager: IdentityManager, config: AIPConfig):
        self._id_mgr = identity_manager
        self._config = config

    def issue(self, agent_name: str, scope: list[str], ttl: int = DEFAULT_TTL) -> str:
        identity = self._id_mgr.get(agent_name)
        if identity is None:
            raise TokenError(f"Agent '{agent_name}' not registered", "identity_unresolvable")
        root = self._id_mgr.root_identity()
        now = int(time.time())
        claims = AipClaims(
            iss=root.aip_id,
            sub=identity.aip_id,
            scope=scope,
            max_depth=0,
            iat=now,
            exp=now + ttl,
        )
        return CompactToken.create(claims, root.keypair)

    def verify(self, token_str: str, required_scope: str) -> CompactToken:
        root = self._id_mgr.root_identity()
        verified = CompactToken.verify(token_str, root.public_key_bytes)
        if not verified.has_scope(required_scope):
            raise TokenError(
                f"Token does not authorize '{required_scope}'",
                "scope_insufficient",
            )
        return verified

    def issue_chained(
        self,
        agent_name: str,
        scope: list[str],
        max_depth: int = 5,
        budget_cents: int | None = None,
        ttl: int = DEFAULT_TTL,
    ) -> str:
        identity = self._id_mgr.get(agent_name)
        if identity is None:
            raise TokenError(f"Agent '{agent_name}' not registered", "identity_unresolvable")
        token = ChainedToken.create_authority(
            issuer=identity.aip_id,
            scopes=scope,
            budget_cents=budget_cents,
            max_depth=max_depth,
            ttl_seconds=ttl,
            keypair=identity.keypair,
        )
        return token.to_base64()

    def delegate(
        self,
        parent_token: str,
        parent_name: str,
        child_name: str,
        attenuated_scope: list[str],
        context: str,
        budget_cents: int | None = None,
    ) -> str:
        parent_identity = self._id_mgr.get(parent_name)
        child_identity = self._id_mgr.get(child_name)
        if parent_identity is None:
            raise TokenError(f"Agent '{parent_name}' not registered", "identity_unresolvable")
        if child_identity is None:
            raise TokenError(f"Agent '{child_name}' not registered", "identity_unresolvable")
        chained = ChainedToken.from_base64(
            parent_token, parent_identity.public_key_bytes
        )
        delegated = chained.delegate(
            delegator=parent_identity.aip_id,
            delegate=child_identity.aip_id,
            scopes=attenuated_scope,
            budget_cents=budget_cents,
            context=context,
        )
        return delegated.to_base64()

    def authorize_chained(self, token_str: str, tool: str) -> None:
        for identity in self._id_mgr.all():
            try:
                chained = ChainedToken.from_base64(token_str, identity.public_key_bytes)
                chained.authorize(tool, identity.public_key_bytes)
                return
            except Exception:
                continue
        raise TokenError(f"No valid authority found for tool '{tool}'", "scope_insufficient")

    def chain_depth(self, token_str: str) -> int:
        for identity in self._id_mgr.all():
            try:
                chained = ChainedToken.from_base64(token_str, identity.public_key_bytes)
                return chained.current_depth()
            except Exception:
                continue
        raise TokenError("Cannot determine chain depth", "token_malformed")
