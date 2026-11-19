# Agent Vulnerability Reproduction Workflow

A local Docker lab workflow with persistent retrieval, validated plans, script
execution, independent evidence checks, bounded recovery and durable reports.
The examples are synthetic demonstrations, not real CVEs.

## Install and test

Python 3.11+, Docker Engine and Docker Compose v2 are required for real lab runs.

```powershell
python -m venv .venv
python -m pip install -e ".[dev]"
python -m pytest
```

## Run a complete lab

```powershell
python -m app.lab.cli engine
python -m app.lab.cli plan DEMO-SCRIPT-LAB --knowledge examples/script_lab/knowledge
python -m app.lab.cli run DEMO-SCRIPT-LAB --knowledge examples/script_lab/knowledge --timeout 300 --report reports/script-001.json
```

The CLI checks Docker and attempts local engine startup when needed. OS permissions
still apply. It selects an available loopback port if the card port cannot bind;
use `--fixed-port` to require the specified port. Use a new report name each run.
Script exit code zero is insufficient: independent HTTP/file assertions must pass.
Containers and networks are cleaned up unless ordinary `run` uses `--keep`.

## Core CLI

| Action | Purpose |
| --- | --- |
| `engine` | Check or start Docker |
| `index`, `search`, `research` | Index and research local knowledge |
| `plan`, `run`, `inspect` | Plan, execute and inspect a lab run |

Model features require `OPENAI_API_KEY` and `PLANNER_MODEL`; optionally set
`OPENAI_BASE_URL`. `--dense` additionally requires `RAG_EMBEDDING_MODEL`.
The project does not implicitly load `.env`.

The authoring, recovery, comparison, batch, case assistant and evaluation
components remain available as Python APIs and integration examples.

## Documentation

- [Agent context isolation implementation report](docs/agent-context-isolation.md)
- [Generation, recovery, research, comparison and queues](docs/autonomous-workflow.md)
- [Script tools, Docker builds and mounts](docs/script-tools.md)
- [Retrieval, planning and execution architecture](docs/architecture.md)
- [Code reading guide (Chinese)](docs/code-reading-guide.md)

## Integration checks

```powershell
python -m examples.authoring_smoke
python -m examples.advanced_smoke
```

These use real Docker with fixed model responses, testing orchestration rather
than live-model quality. Real model/embedding evaluation and real CVE packages
remain unverified. Web evidence is not automatically trusted execution config.

## Layout

- `app/lab/`: main pipeline, authoring, recovery, comparison, queues and CLI
- `app/rag/`: persistent retrieval, providers and external research
- `app/tools/`: Docker lifecycle, startup, file and web tools
- `app/agents/`: case research assistant
- `knowledge/`, `examples/`, `tests/`: fixtures, demos and tests

The primary CLI uses `app.lab.pipeline`.
