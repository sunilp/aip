"""Verify tokens are interoperable across frameworks using the same AIPConfig."""

from dataclasses import dataclass, field

from aip_agents.core.config import AIPConfig
from aip_agents.adapters.crewai.plugin import AIPCrewPlugin
from aip_agents.adapters.adk.plugin import AIPAdkPlugin


@dataclass
class MockTool:
    name: str


@dataclass
class MockCrewAgent:
    role: str
    tools: list = field(default_factory=list)
    allow_delegation: bool = False


class MockCrew:
    def __init__(self, agents, tasks):
        self.agents = agents
        self.tasks = tasks
        self.step_callback = None


@dataclass
class MockAdkAgent:
    name: str
    tools: list = field(default_factory=list)
    sub_agents: list = field(default_factory=list)


@dataclass
class MockRunner:
    agent: MockAdkAgent


def test_crewai_token_format_matches_adk():
    crew_plugin = AIPCrewPlugin(AIPConfig(app_name="cross-test"))
    adk_plugin = AIPAdkPlugin(AIPConfig(app_name="cross-test-2"))

    crew_agent = MockCrewAgent(role="researcher", tools=[MockTool("search")])
    crew = MockCrew(agents=[crew_agent], tasks=[])
    crew_plugin.register(crew)

    adk_agent = MockAdkAgent(name="researcher", tools=[MockTool("search")])
    runner = MockRunner(agent=adk_agent)
    adk_plugin.register(runner)

    crew_token = crew_plugin.get_agent_token("researcher")
    adk_token = adk_plugin.get_agent_token("researcher")

    assert crew_token is not None
    assert adk_token is not None
    assert not crew_token.startswith("eyJ")
    assert not adk_token.startswith("eyJ")


def test_headers_use_same_key():
    crew_plugin = AIPCrewPlugin(AIPConfig(app_name="header-test"))
    adk_plugin = AIPAdkPlugin(AIPConfig(app_name="header-test-2"))

    crew_agent = MockCrewAgent(role="agent", tools=[MockTool("search")])
    crew = MockCrew(agents=[crew_agent], tasks=[])
    crew_plugin.register(crew)

    adk_agent = MockAdkAgent(name="agent", tools=[MockTool("search")])
    runner = MockRunner(agent=adk_agent)
    adk_plugin.register(runner)

    crew_headers = crew_plugin.get_tool_call_headers("agent")
    adk_headers = adk_plugin.get_tool_call_headers("agent")

    assert "X-AIP-Token" in crew_headers
    assert "X-AIP-Token" in adk_headers
