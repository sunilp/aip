from __future__ import annotations

from aip_agents.core.config import AIPConfig
from aip_agents.core.identity_manager import IdentityManager
from aip_agents.core.logger import AIPLogger
from aip_agents.core.token_manager import TokenManager


class AIPAdkPlugin:
    """AIP identity and delegation plugin for Google ADK."""

    def __init__(self, config: AIPConfig | None = None):
        self._config = config or AIPConfig()
        self._identity_manager = IdentityManager(self._config)
        self._token_manager = TokenManager(self._identity_manager, self._config)
        self._logger = AIPLogger(enabled=self._config.log_tokens)
        self._agent_tokens: dict[str, str] = {}
        self._agent_scopes: dict[str, list[str]] = {}
        # Tracks the name of the authority (chain root) whose keypair signed the biscuit
        self._authority_name: dict[str, str] = {}

    @property
    def identity_manager(self) -> IdentityManager:
        return self._identity_manager

    @property
    def token_manager(self) -> TokenManager:
        return self._token_manager

    def register(self, runner) -> None:
        root_agent = runner.agent
        self._register_agent_tree(root_agent, parent_name=None, authority_name=None)

    def _register_agent_tree(
        self,
        agent,
        parent_name: str | None,
        authority_name: str | None,
    ) -> None:
        name = agent.name
        identity = self._identity_manager.register(name)
        self._logger.identity_created(name, identity.aip_id)
        scope = self._extract_tool_names(agent)
        self._agent_scopes[name] = scope

        if parent_name is None:
            # Root agent: issue a chained authority token under its own key
            token = self._token_manager.issue_chained(name, scope=scope)
            self._agent_tokens[name] = token
            self._authority_name[name] = name
            self._logger.token_issued(name, scope, "chained")
            effective_authority = name
        else:
            # Sub-agent: delegate from parent's token using the chain authority's key
            parent_token = self._agent_tokens.get(parent_name)
            if parent_token is not None:
                # Always use the chain authority name so from_base64 uses the right pubkey
                chain_authority = authority_name or parent_name
                delegation_token = self._token_manager.delegate(
                    parent_token=parent_token,
                    parent_name=chain_authority,
                    child_name=name,
                    attenuated_scope=scope,
                    context=f"Sub-agent delegation: {parent_name} -> {name}",
                )
                self._agent_tokens[name] = delegation_token
                self._authority_name[name] = chain_authority
                depth = self._token_manager.chain_depth(delegation_token)
                self._logger.delegation(parent_name, name, scope, depth)
                effective_authority = chain_authority
            else:
                token = self._token_manager.issue_chained(name, scope=scope)
                self._agent_tokens[name] = token
                self._authority_name[name] = name
                effective_authority = name

        for sub_agent in getattr(agent, "sub_agents", []):
            self._register_agent_tree(
                sub_agent,
                parent_name=name,
                authority_name=effective_authority,
            )

    def get_agent_token(self, name: str) -> str | None:
        return self._agent_tokens.get(name)

    def get_agent_scope(self, name: str) -> list[str]:
        return self._agent_scopes.get(name, [])

    def get_chain_depth(self, name: str) -> int:
        token = self._agent_tokens.get(name)
        if token is None:
            raise ValueError(f"No token for agent '{name}'")
        return self._token_manager.chain_depth(token)

    def get_tool_call_headers(self, name: str) -> dict[str, str]:
        token = self._agent_tokens.get(name)
        if token is None:
            return {}
        return {"X-AIP-Token": token}

    def _extract_tool_names(self, agent) -> list[str]:
        names = []
        for tool in getattr(agent, "tools", []):
            if hasattr(tool, "name"):
                names.append(tool.name)
            elif isinstance(tool, str):
                names.append(tool)
        return names if names else ["*"]
