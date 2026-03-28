"""Example: Add AIP identity and delegation to Google ADK agents.

Usage:
    pip install aip-agents[adk]
    python adk_example.py
"""

from google.adk import Agent, Runner
from aip_agents import AIPConfig
from aip_agents.adapters.adk import AIPAdkPlugin

# 1. Create the plugin
plugin = AIPAdkPlugin(AIPConfig(
    app_name="research-pipeline",
    log_tokens=True,
))

# 2. Define sub-agents
summarizer = Agent(
    name="summarizer",
    model="gemini-2.5-flash",
    instruction="Summarize the research findings concisely.",
    description="Summarization specialist",
    tools=[],
)

fact_checker = Agent(
    name="fact_checker",
    model="gemini-2.5-flash",
    instruction="Verify claims against sources.",
    description="Fact verification agent",
    tools=[],
)

# 3. Define coordinator with sub-agents
coordinator = Agent(
    name="coordinator",
    model="gemini-2.5-flash",
    instruction="Route tasks to the appropriate sub-agent.",
    description="Task coordinator",
    tools=[],
    sub_agents=[summarizer, fact_checker],
)

# 4. Create runner and register plugin
runner = Runner(agent=coordinator)
plugin.register(runner)

# 5. Inspect delegation chains
print("\n--- Delegation Chain Depths ---")
for name in ["coordinator", "summarizer", "fact_checker"]:
    depth = plugin.get_chain_depth(name)
    print(f"{name}: depth {depth}")

print("\n--- Tool Call Headers ---")
headers = plugin.get_tool_call_headers("summarizer")
print(f"X-AIP-Token: {headers.get('X-AIP-Token', 'N/A')[:50]}...")
