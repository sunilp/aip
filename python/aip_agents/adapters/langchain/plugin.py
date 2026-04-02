from __future__ import annotations

from aip_agents.core.config import AIPConfig
from aip_agents.core.identity_manager import IdentityManager
from aip_agents.core.logger import AIPLogger
from aip_agents.core.token_manager import TokenManager


class AIPLangChainPlugin:
    """AIP identity and delegation plugin for LangChain.

    Supports two registration patterns:

    1. Single agent:
        plugin.register(executor, name="researcher")

    2. Multiple agents (supervisor pattern):
        plugin.register_agents({
            "researcher": researcher_executor,
            "writer": writer_executor,
        })
    """

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

    def register(self, executor, name: str) -> None:
        """Register a single LangChain AgentExecutor or agent.

        Args:
            executor: An AgentExecutor, agent created by create_agent(),
                      or any object with a ``tools`` attribute.
            name: A human-readable name for this agent (used as the identity key).
        """
        identity = self._identity_manager.register(name)
        self._logger.identity_created(name, identity.aip_id)
        scope = self._extract_tool_names(executor)
        self._agent_scopes[name] = scope
        if self._config.auto_delegation:
            token = self._token_manager.issue_chained(name, scope=scope)
        else:
            token = self._token_manager.issue(name, scope=scope)
        self._agent_tokens[name] = token
        self._logger.token_issued(name, scope, "chained" if self._config.auto_delegation else "compact")

    def register_agents(self, agents: dict) -> None:
        """Register multiple named agents.

        Args:
            agents: Mapping of agent name to AgentExecutor or agent object.
                    Example: {"researcher": researcher_exec, "writer": writer_exec}
        """
        for name, executor in agents.items():
            self.register(executor, name=name)

    def get_agent_token(self, name: str) -> str | None:
        return self._agent_tokens.get(name)

    def get_agent_scope(self, name: str) -> list[str]:
        return self._agent_scopes.get(name, [])

    def create_delegation(
        self,
        parent_name: str,
        child_name: str,
        task_description: str,
        scope: list[str] | None = None,
    ) -> str:
        """Create a delegation token from parent agent to child agent.

        The child receives a narrowed token that can only exercise the
        specified scope (or the child's registered scope if not provided).
        """
        parent_token = self._agent_tokens.get(parent_name)
        if parent_token is None:
            raise ValueError(f"No token found for agent '{parent_name}'")
        effective_scope = scope or self._agent_scopes.get(child_name, [])
        delegation_token = self._token_manager.delegate(
            parent_token=parent_token,
            parent_name=parent_name,
            child_name=child_name,
            attenuated_scope=effective_scope,
            context=task_description,
        )
        depth = self._token_manager.chain_depth(delegation_token)
        self._logger.delegation(parent_name, child_name, effective_scope, depth)
        self._agent_tokens[child_name] = delegation_token
        return delegation_token

    def get_tool_call_headers(self, name: str) -> dict[str, str]:
        """Return HTTP headers with the AIP token for outgoing tool calls."""
        token = self._agent_tokens.get(name)
        if token is None:
            return {}
        return {"X-AIP-Token": token}

    def _extract_tool_names(self, executor) -> list[str]:
        """Extract tool names from an AgentExecutor or agent."""
        tools = getattr(executor, "tools", [])
        names = []
        for tool in tools:
            if hasattr(tool, "name"):
                names.append(tool.name)
            elif isinstance(tool, str):
                names.append(tool)
        return names if names else ["*"]
