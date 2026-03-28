from __future__ import annotations

from aip_agents.core.config import AIPConfig
from aip_agents.core.identity_manager import IdentityManager
from aip_agents.core.logger import AIPLogger
from aip_agents.core.token_manager import TokenManager


class AIPCrewPlugin:
    """AIP identity and delegation plugin for CrewAI."""

    def __init__(self, config: AIPConfig | None = None):
        self._config = config or AIPConfig()
        self._identity_manager = IdentityManager(self._config)
        self._token_manager = TokenManager(self._identity_manager, self._config)
        self._logger = AIPLogger(enabled=self._config.log_tokens)
        self._agent_tokens: dict[str, str] = {}
        self._agent_scopes: dict[str, list[str]] = {}

    @property
    def identity_manager(self) -> IdentityManager:
        return self._identity_manager

    @property
    def token_manager(self) -> TokenManager:
        return self._token_manager

    def register(self, crew) -> None:
        for agent in crew.agents:
            role = agent.role
            identity = self._identity_manager.register(role)
            self._logger.identity_created(role, identity.aip_id)
            scope = self._extract_tool_names(agent)
            self._agent_scopes[role] = scope
            if self._config.auto_delegation:
                token = self._token_manager.issue_chained(role, scope=scope)
            else:
                token = self._token_manager.issue(role, scope=scope)
            self._agent_tokens[role] = token
            self._logger.token_issued(role, scope, "chained" if self._config.auto_delegation else "compact")

    def get_agent_token(self, role: str) -> str | None:
        return self._agent_tokens.get(role)

    def get_agent_scope(self, role: str) -> list[str]:
        return self._agent_scopes.get(role, [])

    def create_delegation(self, parent_role: str, child_role: str, task_description: str, scope: list[str] | None = None) -> str:
        parent_token = self._agent_tokens.get(parent_role)
        if parent_token is None:
            raise ValueError(f"No token found for agent '{parent_role}'")
        effective_scope = scope or self._agent_scopes.get(child_role, [])
        delegation_token = self._token_manager.delegate(
            parent_token=parent_token,
            parent_name=parent_role,
            child_name=child_role,
            attenuated_scope=effective_scope,
            context=task_description,
        )
        depth = self._token_manager.chain_depth(delegation_token)
        self._logger.delegation(parent_role, child_role, effective_scope, depth)
        self._agent_tokens[child_role] = delegation_token
        return delegation_token

    def get_tool_call_headers(self, role: str) -> dict[str, str]:
        token = self._agent_tokens.get(role)
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
