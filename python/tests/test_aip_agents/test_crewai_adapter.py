from dataclasses import dataclass, field
from aip_agents.core.config import AIPConfig
from aip_agents.adapters.crewai.plugin import AIPCrewPlugin


@dataclass
class MockTool:
    name: str


@dataclass
class MockAgent:
    role: str
    tools: list = field(default_factory=list)
    allow_delegation: bool = False


@dataclass
class MockTask:
    description: str
    agent: MockAgent | None = None
    tools: list = field(default_factory=list)


class MockCrew:
    def __init__(self, agents, tasks):
        self.agents = agents
        self.tasks = tasks
        self.step_callback = None


def test_register_assigns_identities():
    plugin = AIPCrewPlugin(AIPConfig(app_name="test-crew"))
    agent_a = MockAgent(role="researcher", tools=[MockTool("web_search")])
    agent_b = MockAgent(role="writer", tools=[MockTool("file_write")])
    crew = MockCrew(agents=[agent_a, agent_b], tasks=[])
    plugin.register(crew)
    assert plugin.identity_manager.get("researcher") is not None
    assert plugin.identity_manager.get("writer") is not None


def test_register_creates_root_identity():
    plugin = AIPCrewPlugin(AIPConfig(app_name="my-crew"))
    crew = MockCrew(agents=[MockAgent(role="agent-1")], tasks=[])
    plugin.register(crew)
    root = plugin.identity_manager.root_identity()
    assert root.name == "my-crew"


def test_get_agent_token():
    plugin = AIPCrewPlugin(AIPConfig(app_name="test-crew"))
    agent = MockAgent(role="researcher", tools=[MockTool("web_search")])
    crew = MockCrew(agents=[agent], tasks=[])
    plugin.register(crew)
    token = plugin.get_agent_token("researcher")
    assert token is not None
    assert isinstance(token, str)


def test_get_delegation_token():
    plugin = AIPCrewPlugin(AIPConfig(app_name="test-crew", auto_delegation=True))
    manager = MockAgent(
        role="manager",
        tools=[MockTool("web_search"), MockTool("summarize")],
        allow_delegation=True,
    )
    researcher = MockAgent(role="researcher", tools=[MockTool("web_search")])
    task = MockTask(description="Research AI identity", agent=researcher, tools=[MockTool("web_search")])
    crew = MockCrew(agents=[manager, researcher], tasks=[task])
    plugin.register(crew)
    delegation_token = plugin.create_delegation(
        parent_role="manager",
        child_role="researcher",
        task_description="Research AI identity",
        scope=["web_search"],
    )
    assert delegation_token is not None
    assert isinstance(delegation_token, str)


def test_scope_from_agent_tools():
    plugin = AIPCrewPlugin(AIPConfig(app_name="test-crew"))
    agent = MockAgent(role="researcher", tools=[MockTool("web_search"), MockTool("calculator")])
    crew = MockCrew(agents=[agent], tasks=[])
    plugin.register(crew)
    scope = plugin.get_agent_scope("researcher")
    assert "web_search" in scope
    assert "calculator" in scope
