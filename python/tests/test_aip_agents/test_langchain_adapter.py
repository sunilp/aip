from dataclasses import dataclass, field
from aip_agents.core.config import AIPConfig
from aip_agents.adapters.langchain.plugin import AIPLangChainPlugin


@dataclass
class MockTool:
    name: str
    description: str = ""


@dataclass
class MockAgentExecutor:
    """Mimics LangChain AgentExecutor with a tools attribute."""
    tools: list = field(default_factory=list)


def test_register_single_agent():
    plugin = AIPLangChainPlugin(AIPConfig(app_name="test-lc"))
    executor = MockAgentExecutor(tools=[MockTool("web_search")])
    plugin.register(executor, name="researcher")
    assert plugin.identity_manager.get("researcher") is not None


def test_register_creates_root_identity():
    plugin = AIPLangChainPlugin(AIPConfig(app_name="my-lc-app"))
    executor = MockAgentExecutor(tools=[])
    plugin.register(executor, name="agent-1")
    root = plugin.identity_manager.root_identity()
    assert root.name == "my-lc-app"


def test_register_agents_multiple():
    plugin = AIPLangChainPlugin(AIPConfig(app_name="test-lc"))
    researcher = MockAgentExecutor(tools=[MockTool("web_search")])
    writer = MockAgentExecutor(tools=[MockTool("file_write")])
    plugin.register_agents({"researcher": researcher, "writer": writer})
    assert plugin.identity_manager.get("researcher") is not None
    assert plugin.identity_manager.get("writer") is not None


def test_get_agent_token():
    plugin = AIPLangChainPlugin(AIPConfig(app_name="test-lc"))
    executor = MockAgentExecutor(tools=[MockTool("web_search")])
    plugin.register(executor, name="researcher")
    token = plugin.get_agent_token("researcher")
    assert token is not None
    assert isinstance(token, str)


def test_get_tool_call_headers():
    plugin = AIPLangChainPlugin(AIPConfig(app_name="test-lc"))
    executor = MockAgentExecutor(tools=[MockTool("web_search")])
    plugin.register(executor, name="researcher")
    headers = plugin.get_tool_call_headers("researcher")
    assert "X-AIP-Token" in headers


def test_get_tool_call_headers_missing_agent():
    plugin = AIPLangChainPlugin(AIPConfig(app_name="test-lc"))
    headers = plugin.get_tool_call_headers("nonexistent")
    assert headers == {}


def test_delegation_token():
    plugin = AIPLangChainPlugin(AIPConfig(app_name="test-lc", auto_delegation=True))
    supervisor = MockAgentExecutor(tools=[MockTool("web_search"), MockTool("email")])
    researcher = MockAgentExecutor(tools=[MockTool("web_search")])
    plugin.register_agents({"supervisor": supervisor, "researcher": researcher})
    delegation_token = plugin.create_delegation(
        parent_name="supervisor",
        child_name="researcher",
        task_description="Research AI identity protocols",
        scope=["web_search"],
    )
    assert delegation_token is not None
    assert isinstance(delegation_token, str)


def test_scope_from_tools():
    plugin = AIPLangChainPlugin(AIPConfig(app_name="test-lc"))
    executor = MockAgentExecutor(tools=[MockTool("web_search"), MockTool("calculator")])
    plugin.register(executor, name="researcher")
    scope = plugin.get_agent_scope("researcher")
    assert "web_search" in scope
    assert "calculator" in scope


def test_default_scope_no_tools():
    plugin = AIPLangChainPlugin(AIPConfig(app_name="test-lc"))
    executor = MockAgentExecutor(tools=[])
    plugin.register(executor, name="agent")
    scope = plugin.get_agent_scope("agent")
    assert scope == ["*"]
