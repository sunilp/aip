# The Agent Identity Gap: Why MCP and A2A Need Verifiable Delegation

*Building AI Systems Newsletter*

---

Your agent just called a tool. Which agent authorized it? Through how many hops? With what budget? Can you prove any of this after the fact?

You can't. Not today.

## The problem is obvious. The fix isn't.

MCP lets agents call tools. A2A lets agents talk to other agents. Neither verifies who the agent is. A Knostic scan of roughly 2,000 MCP servers found every single one lacked authentication.

MCP added OAuth 2.1 this year, which helps for single-hop client-to-server auth. But when an orchestrator delegates to a specialist that calls a tool, OAuth authenticates the last hop. The delegation chain that led there? Gone. No record. No constraints. No audit trail.

This matters because multi-agent systems are becoming the default architecture. An orchestrator decomposes a task. Specialists execute. Sub-agents handle edge cases. Each handoff is a trust boundary with no identity flowing across it.

## What I built

I spent the last few months designing and implementing the Agent Identity Protocol (AIP). The core idea: a single token that answers four questions at once.

**Who authorized this?** The root authority block, signed by the human or system that started the chain.

**Through which agents?** Each delegation appends a block that narrows scope. You can delegate "search only, $1 budget, 3 hops max" and the token enforces it cryptographically. Scope can only narrow, never widen.

**What constraints applied?** Datalog policy evaluation at each hop. Simple mode generates the rules for you. You specify values, the library writes the Datalog.

**What was the outcome?** An optional completion block records the result hash, cost, and verification status, linking authorization to provenance.

Two wire formats serve different needs:

- **Compact mode** is a JWT with EdDSA signature. Single hop. Standard JWT libraries can verify it. Drop it into an MCP server in 10 minutes.

- **Chained mode** uses Biscuit tokens with append-only blocks. Multi-hop delegation with scope attenuation at every level. Each block is signed independently. The chain is tamper-evident.

## Show me the code

```python
from aip_core.crypto import KeyPair
from aip_token.chained import ChainedToken

# Orchestrator creates authority token
root_kp = KeyPair.generate()
token = ChainedToken.create_authority(
    issuer="aip:web:myorg.com/orchestrator",
    scopes=["tool:search", "tool:email"],
    budget_cents=500,
    max_depth=3,
    ttl_seconds=3600,
    keypair=root_kp,
)

# Delegate to specialist: only search, lower budget
delegated = token.delegate(
    delegator="aip:web:myorg.com/orchestrator",
    delegate="aip:web:myorg.com/specialist",
    scopes=["tool:search"],  # email removed
    budget_cents=100,
    context="research task for user query",
)

# Specialist verifies before calling tool
delegated.authorize("tool:search", root_kp.public_key_bytes())  # passes
delegated.authorize("tool:email", root_kp.public_key_bytes())   # raises
```

The specialist can search but not email. That constraint is cryptographic, not a policy document someone might ignore.

## Does it actually work?

I ran three experiments:

**Real MCP deployment.** AIP adds 0.22ms of overhead to a real HTTP tool call. That is sub-millisecond identity verification on every request.

**Real LLM multi-agent chain.** With Gemini 2.5 Flash handling the inference, AIP accounts for 0.086% of total end-to-end latency. Less than a tenth of a percent. Identity is not the bottleneck.

**Adversarial security.** I threw 600 attacks across 6 categories at AIP: scope widening, depth violation, token replay, wrong key, empty context, token forgery. 100% rejection rate. Two of those attack categories (delegation depth violation and audit evasion through empty context) are uniquely caught by AIP. Plain JWT deployments miss them entirely.

## Why not just use OAuth? Or DIDs? Or SPIFFE?

I surveyed 11 existing approaches. Each gets something right but misses something essential for agent delegation:

- **OAuth** requires a central authorization server per trust domain. No holder-side attenuation.
- **W3C DIDs** need blockchain and wallets. Agents are software, not humans.
- **Macaroons** use shared secrets. Every verifier becomes a potential forger.
- **SPIFFE** requires dedicated infrastructure. Incompatible with ephemeral agent creation.
- **Biscuit** gets the token format right but has no identity resolution, no protocol bindings, no provenance model.

AIP builds on Biscuit's cryptographic foundation (Ed25519, Datalog, append-only blocks) and adds what's missing: an identity scheme, MCP/A2A/HTTP bindings, completion blocks for provenance, and a compact JWT mode for simple cases.

The full comparison is in the paper (Table 1, seven dimensions across eleven approaches).

## Part of a bigger picture

AIP is the third protocol in a trust stack I have been building:

- **LDP** handles provenance: what did the agent produce and how reliably?
- **DCI** handles reasoning: how did agents deliberate to reach a decision?
- **AIP** handles identity: who is this agent and what is it authorized to do?

Each protocol works independently. Together they provide a complete trust infrastructure for multi-agent systems.

## What's next

The paper is on arXiv: [arXiv:2603.24775](https://arxiv.org/abs/2603.24775)

The code is open source: [github.com/sunilp/aip](https://github.com/sunilp/aip)

Reference implementations in Python (primary SDK) and Rust. Apache 2.0 license. Cross-language interoperability verified.

Three things I want to explore next:
1. Validating the A2A binding against real agent-to-agent workflows
2. Formalizing the LDP provenance bridge (linking authorization chains to quality evidence)
3. A controlled comparison against a real OAuth 2.1 baseline

If you are building multi-agent systems on MCP or A2A, I'd like to hear what identity problems you are running into. The protocol is designed to be practical, not theoretical. Feedback on real use cases is the fastest way to make it better.

---

*Sunil Prakash is a researcher at the Indian School of Business working on trust infrastructure for AI agent systems. His prior work includes LDP (agent provenance) and DCI (collective reasoning).*
