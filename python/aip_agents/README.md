# aip-agents

AIP identity and delegation for AI agent frameworks. Add cryptographic identity, scoped delegation chains, and audit-ready token flows to your agents in 5 lines of code.

Supports **CrewAI**, **Google ADK**, and **LangChain**.

## Install

```bash
pip install aip-agents[crewai]    # CrewAI
pip install aip-agents[adk]       # Google ADK
pip install aip-agents[langchain] # LangChain
pip install aip-agents[all]       # All frameworks
```

## Quick Start: CrewAI

```python
from crewai import Crew, Agent, Task
from aip_agents.adapters.crewai import AIPCrewPlugin

plugin = AIPCrewPlugin()

researcher = Agent(role="researcher", ...)
writer = Agent(role="writer", ...)
crew = Crew(agents=[researcher, writer], tasks=[...])

plugin.register(crew)  # Each agent gets an AIP identity + delegation token
crew.kickoff()
```

## Quick Start: Google ADK

```python
from google.adk import Agent, Runner
from aip_agents.adapters.adk import AIPAdkPlugin

plugin = AIPAdkPlugin()

agent = Agent(name="coordinator", sub_agents=[worker1, worker2], ...)
runner = Runner(agent=agent)

plugin.register(runner)  # Walks agent tree, creates delegation chains
runner.run("task")
```

## Quick Start: LangChain

```python
from langchain.agents import AgentExecutor, create_tool_calling_agent
from aip_agents.adapters.langchain import AIPLangChainPlugin

plugin = AIPLangChainPlugin()

# Register single agent
plugin.register(agent_executor, name="researcher")

# Or register multiple agents (supervisor pattern)
plugin.register_agents({
    "researcher": researcher_executor,
    "writer": writer_executor,
})

# Get headers for tool calls
headers = plugin.get_tool_call_headers("researcher")
# {"X-AIP-Token": "eyJ..."}
```

## What You Get

When you register a plugin, every agent gets:

1. **Cryptographic identity** - An Ed25519 keypair and AIP identifier (`aip:key:ed25519:z...`)
2. **Delegation chain** - When a parent agent delegates to a sub-agent, a Biscuit token chain records the delegation with attenuated scope
3. **Tool call headers** - `X-AIP-Token` headers ready to attach to outgoing tool/MCP calls

Enable logging to see it in action:

```python
from aip_agents import AIPConfig

plugin = AIPCrewPlugin(AIPConfig(log_tokens=True))
```

Output:
```
[AIP] Identity created: researcher -> aip:key:ed25519:z6Fk3...
[AIP] Delegation: manager -> researcher [scope: web_search] [chain depth: 2]
[AIP] Tool call: researcher -> web_search [chain depth: 3, verified]
```

## Configuration

```python
AIPConfig(
    app_name="my-app",          # Root identity label
    auto_identity=True,          # Auto-assign identity to every agent
    auto_delegation=True,        # Auto-create delegation chains
    persist_keys=False,          # Save keys to ~/.aip/keys/
    log_tokens=False,            # Log token operations
    default_scope=None,          # Default scope for root token
)
```

## How It Works

- **Identity**: Each agent gets an Ed25519 keypair. The public key becomes the agent's AIP identifier.
- **Tokens**: Authority tokens use [Biscuit](https://www.biscuitsec.org/) - an append-only cryptographic token that enforces scope can only narrow, never widen.
- **Delegation**: When Agent A delegates to Agent B, a new block is appended to A's token with B's identity and attenuated scope. The chain is cryptographically verifiable.
- **Tool calls**: Tokens are attached via `X-AIP-Token` header, compatible with [AIP MCP middleware](https://github.com/sunilp/aip) for end-to-end verification.

## Links

- [AIP Specification](https://github.com/sunilp/aip/tree/main/spec)
- [AIP Paper (arXiv:2603.24775)](https://arxiv.org/abs/2603.24775)
- [GitHub](https://github.com/sunilp/aip)
