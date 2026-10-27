# Papers: sandboxing and isolation for LLM agents

Downloaded from arXiv on 2026-10-27. Files are named `<arXiv id>-<short title>.pdf`.

## Execution sandboxes for agent-generated code (most relevant to nsbx)

| arXiv | Title | Relevance |
|-------|-------|-----------|
| [2606.08433](https://arxiv.org/abs/2606.08433) | AI Code Sandboxes: A Comparative Security Study, Part 1: Engine-Level Properties | Compares sandbox engines on attack surface, CVE history and fuzzing. Input to the backend choice (doc 02) and residual risks (doc 13) |
| [2603.02277](https://arxiv.org/abs/2603.02277) | Quantifying Frontier LLM Capabilities for Container Sandbox Escape (SandboxEscapeBench) | Measures how well LLMs escape container sandboxes. Supports the A1 adversary model (doc 01) |
| [2607.05743](https://arxiv.org/abs/2607.05743) | The Balkanization of Execution-Security Research for AI Coding Agents | Survey of isolation, access control and TOCTOU issues. TOCTOU is relevant to artefact collection (doc 05) |
| [2610.02456](https://arxiv.org/abs/2610.02456) | SideKernel: A Usable microVM Sandbox for AI Coding Agents on macOS | MicroVM vs shared-kernel trade-offs (doc 02, backend E) |
| [2512.12806](https://arxiv.org/abs/2512.12806) | Fault-Tolerant Sandboxing for AI Coding Agents: A Transactional Approach | Transactional filesystem snapshots. Relevant to open decision D6 on disk workspaces |
| [2605.09721](https://arxiv.org/abs/2605.09721) | Security Risks in Tool-Enabled AI Agents: Privileged Execution Environments | Threat-model input |
| [2604.03515](https://arxiv.org/abs/2604.03515) | Inside the Scaffold: A Source-Code Taxonomy of Coding Agent Architectures | How existing agents isolate execution in practice |
| [2512.04367](https://arxiv.org/abs/2512.04367) | AgentBay: A Hybrid Interaction Sandbox | Sandbox product with human takeover |
| [2510.21236](https://arxiv.org/abs/2510.21236) | AgentBound: Securing Execution Boundaries of AI Agents | Container-wrapped MCP servers with declared permissions |
| [2512.12594](https://arxiv.org/abs/2512.12594) | ceLLMate: Sandboxing Browser AI Agents | Browser-agent sandboxing |

## Privilege control, capabilities and containment at the agent layer

| arXiv | Title |
|-------|-------|
| [2403.04960](https://arxiv.org/abs/2403.04960) | IsolateGPT: An Execution Isolation Architecture for LLM-Based Agentic Systems |
| [2504.11703](https://arxiv.org/abs/2504.11703) | Progent: Securing AI Agents with Privilege Control |
| [2601.11893](https://arxiv.org/abs/2601.11893) | Taming Various Privilege Escalation in LLM-Based Agent Systems: A Mandatory Access Control Framework |
| [2604.11839](https://arxiv.org/abs/2604.11839) | Beyond Static Sandboxing: Learned Capability Governance for Autonomous AI Agents |
| [2606.22504](https://arxiv.org/abs/2606.22504) | Lingering Authority: Revocable Resource-and-Effect Capabilities for Coding Agents |
| [2604.12986](https://arxiv.org/abs/2604.12986) | Parallax: Why AI Agents That Think Must Never Act |
| [2509.08646](https://arxiv.org/abs/2509.08646) | Architecting Resilient LLM Agents: A Guide to Secure Plan-then-Execute Implementations |
| [2607.23999](https://arxiv.org/abs/2607.23999) | ContainmentBench: Trace-Based Evaluation of Post-Exposure Containment in Tool-Using LLM Agents |
| [2309.15817](https://arxiv.org/abs/2309.15817) | Identifying the Risks of LM Agents with an LM-Emulated Sandbox (ToolEmu) |

The relevance notes come from titles and abstracts; the papers have not been reviewed yet.
