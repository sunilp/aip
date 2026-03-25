# arXiv Submission Checklist

## Submission File
- `arxiv-submission.tar.gz` (21KB, single main.tex with inlined bibliography)
- Compiles with `pdflatex` (two passes needed for references)
- 17 pages, 22 references

## arXiv Metadata

**Title:** AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A

**Authors:** Sunil Prakash

**Abstract:** (copy from main.tex abstract, remove LaTeX macros)

AI agents increasingly call tools via the Model Context Protocol (MCP) and delegate to other agents via Agent-to-Agent (A2A), yet neither protocol verifies agent identity. A scan of approximately 2,000 MCP servers found all lacked authentication. In our survey, we did not identify a prior implemented protocol that jointly combines public-key verifiable delegation, holder-side attenuation, expressive chained policy, transport bindings across MCP/A2A/HTTP, and provenance-oriented completion records. We introduce Invocation-Bound Capability Tokens (IBCTs), a primitive that fuses identity, attenuated authorization, and provenance binding into a single append-only token chain. IBCTs operate in two wire formats: compact mode (a signed JWT for single-hop cases) and chained mode (a Biscuit token with Datalog policies for multi-hop delegation). We provide reference implementations in Python and Rust with full cross-language interoperability. Compact mode verification takes 0.049ms (Rust) and 0.189ms (Python), with 0.22ms overhead over no-auth in real MCP-over-HTTP deployment. In a real multi-agent deployment with Gemini 2.5 Flash, AIP adds 2.35ms of overhead (0.086% of total end-to-end latency). Adversarial evaluation across 600 attack attempts shows 100% rejection rate, with two attack categories (delegation depth violation and audit evasion through empty context) uniquely caught by AIP's chained delegation model that neither unsigned nor plain JWT deployments detect.

**Primary category:** cs.AI (Artificial Intelligence)
**Cross-list:** cs.CR (Cryptography and Security)

**Comments:** 17 pages, 10 tables, 2 figures

**ACM classes:**
- D.4.6 Security and Protection -- Authentication
- C.2.0 General -- Security and protection
- I.2.11 Distributed Artificial Intelligence -- Multiagent systems

**MSC classes:** 68M12, 94A60

**Journal reference:** (leave blank)

**DOI:** (leave blank)

**Report number:** (leave blank)

## Submission Steps

1. Go to https://arxiv.org/submit
2. Select "New submission"
3. Choose category: cs.AI
4. Upload `arxiv-submission.tar.gz`
5. Fill in metadata from above
6. Add cross-list: cs.CR
7. Preview the compiled PDF
8. Verify: all listings render, all tables complete, all citations resolve
9. Submit

## Post-Submission

After arXiv assigns an ID (e.g., arXiv:26XX.XXXXX):
1. Make repo public: `gh repo edit sunilp/aip --visibility public --accept-visibility-change-consequences`
2. Update README with arXiv link
3. Publish blog post on "Building AI Systems" LinkedIn newsletter
4. Update GitHub profile README with the paper
5. Add to Google Scholar profile
