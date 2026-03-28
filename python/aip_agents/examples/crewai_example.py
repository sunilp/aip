"""Example: Add AIP identity and delegation to a CrewAI crew.

Usage:
    pip install aip-agents[crewai]
    python crewai_example.py
"""

from crewai import Agent, Crew, Task, Process
from aip_agents import AIPConfig
from aip_agents.adapters.crewai import AIPCrewPlugin

# 1. Create the plugin (with logging to see what happens)
plugin = AIPCrewPlugin(AIPConfig(
    app_name="research-crew",
    log_tokens=True,
))

# 2. Define your agents as normal
researcher = Agent(
    role="researcher",
    goal="Find accurate information about AI agent identity protocols",
    backstory="Expert at web research and source verification",
    tools=[],
    allow_delegation=False,
)

writer = Agent(
    role="writer",
    goal="Write clear, concise summaries of research findings",
    backstory="Technical writer specializing in AI systems",
    tools=[],
    allow_delegation=False,
)

# 3. Define tasks
research_task = Task(
    description="Research the current state of AI agent identity protocols",
    expected_output="A summary of existing protocols and gaps",
    agent=researcher,
)

write_task = Task(
    description="Write a blog post based on the research",
    expected_output="A 500-word blog post",
    agent=writer,
)

# 4. Create crew and register plugin
crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, write_task],
    process=Process.sequential,
)

plugin.register(crew)

# 5. Access tokens programmatically
print("\n--- Agent Identities ---")
for agent_name in ["researcher", "writer"]:
    identity = plugin.identity_manager.get(agent_name)
    print(f"{agent_name}: {identity.aip_id}")

print("\n--- Tool Call Headers ---")
headers = plugin.get_tool_call_headers("researcher")
print(f"X-AIP-Token: {headers.get('X-AIP-Token', 'N/A')[:50]}...")

# 6. Create delegation
delegation_token = plugin.create_delegation(
    parent_role="researcher",
    child_role="writer",
    task_description="Write summary based on research findings",
    scope=["write", "summarize"],
)
print(f"\nDelegation chain depth: {plugin.token_manager.chain_depth(delegation_token)}")
