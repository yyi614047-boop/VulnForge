# VulnForge architecture

The product direction, target architecture, and migration sequence are maintained in [architecture-v2.md](architecture-v2.md).

## Product decisions

- Product: **Agent-driven Vulnerability Reproduction Platform**.
- PoC scope: existing PoCs and exploit modules only; autonomous PoC authoring is out of scope.
- Primary PoC source and planned execution backend: **Metasploit Framework**.
- Secondary PoC sources: GitHub, Exploit-DB, and upstream project repositories.
- Primary vulnerable-environment source: **Vulhub**; its native PoCs are optional, not assumed.

## Current implementation status

- LangGraph is the only workflow engine; LangChain + OpenAI remains the model integration.
- Canonical domain `ExecutionPlan` is shared by Planner, Pipeline, and Executor.
- ExecutionPolicy, source fingerprint validation, provider-neutral evidence verification, and bounded retry/abort behavior are implemented.
- Metasploit-first discovery, Metasploit RPC execution, secondary PoC discovery/adapters, and container egress isolation are planned and must not be represented as already implemented.

See [architecture-v2.md](architecture-v2.md) for the complete workflow, adapter boundaries, security requirements, and acceptance sequence.
