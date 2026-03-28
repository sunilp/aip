from dataclasses import dataclass, field
from aip_agents.core.config import AIPConfig
from aip_agents.adapters.adk.plugin import AIPAdkPlugin


@dataclass
class MockTool:
    name: str


@dataclass
class MockAgent:
    name: str
    tools: list = field(default_factory=list)
    sub_agents: list = field(default_factory=list)


@dataclass
class MockRunner:
    agent: MockAgent


def test_register_assigns_identities():
    plugin = AIPAdkPlugin(AIPConfig(app_name="test-app"))
    agent = MockAgent(name="research_agent", tools=[MockTool("web_search")])
    runner = MockRunner(agent=agent)
    plugin.register(runner)
    assert plugin.identity_manager.get("research_agent") is not None


def test_register_walks_sub_agents():
    plugin = AIPAdkPlugin(AIPConfig(app_name="test-app"))
    sub1 = MockAgent(name="summarizer", tools=[MockTool("summarize")])
    sub2 = MockAgent(name="translator", tools=[MockTool("translate")])
    root = MockAgent(name="coordinator", tools=[MockTool("route")], sub_agents=[sub1, sub2])
    runner = MockRunner(agent=root)
    plugin.register(runner)
    assert plugin.identity_manager.get("coordinator") is not None
    assert plugin.identity_manager.get("summarizer") is not None
    assert plugin.identity_manager.get("translator") is not None


def test_register_creates_delegation_for_sub_agents():
    plugin = AIPAdkPlugin(AIPConfig(app_name="test-app", auto_delegation=True))
    sub = MockAgent(name="worker", tools=[MockTool("search")])
    root = MockAgent(name="coordinator", tools=[MockTool("search"), MockTool("write")], sub_agents=[sub])
    runner = MockRunner(agent=root)
    plugin.register(runner)
    token = plugin.get_agent_token("worker")
    assert token is not None


def test_nested_sub_agents():
    plugin = AIPAdkPlugin(AIPConfig(app_name="test-app"))
    leaf = MockAgent(name="leaf", tools=[MockTool("compute")])
    mid = MockAgent(name="mid", tools=[MockTool("compute"), MockTool("fetch")], sub_agents=[leaf])
    root = MockAgent(name="root", tools=[MockTool("compute"), MockTool("fetch"), MockTool("store")], sub_agents=[mid])
    runner = MockRunner(agent=root)
    plugin.register(runner)
    assert plugin.identity_manager.get("root") is not None
    assert plugin.identity_manager.get("mid") is not None
    assert plugin.identity_manager.get("leaf") is not None
    assert plugin.get_chain_depth("root") == 0
    assert plugin.get_chain_depth("mid") == 1
    assert plugin.get_chain_depth("leaf") == 2


def test_scope_derived_from_tools():
    plugin = AIPAdkPlugin(AIPConfig(app_name="test-app"))
    agent = MockAgent(name="agent", tools=[MockTool("web_search"), MockTool("calculator")])
    runner = MockRunner(agent=agent)
    plugin.register(runner)
    scope = plugin.get_agent_scope("agent")
    assert "web_search" in scope
    assert "calculator" in scope


def test_tool_call_headers():
    plugin = AIPAdkPlugin(AIPConfig(app_name="test-app"))
    agent = MockAgent(name="agent", tools=[MockTool("search")])
    runner = MockRunner(agent=agent)
    plugin.register(runner)
    headers = plugin.get_tool_call_headers("agent")
    assert "X-AIP-Token" in headers
