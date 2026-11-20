# VulnForge

VulnForge is a staged, LangGraph-based system for authorized vulnerability reproduction in isolated local Docker environments.

The project uses Markdown role instructions, LangChain with the OpenAI API for model calls, LangGraph for orchestration, Pydantic for structured validation, and a custom executor/tool layer for side effects.

## Architecture

The only primary execution architecture is the staged Pipeline:

1. **Researcher** reads Markdown and Compose files declared by a reviewed reproduction specification and produces source-cited evidence.
2. **Planner** receives the research bundle and Markdown evidence, then returns a typed `DeploymentPlan`.
3. **Plan validation** binds the plan to the trusted reproduction specification, source hashes, allowed actions, dependencies, and execution budgets.
4. **Deployer** prepares and starts the Docker environment.
5. **Reproducer** executes the reviewed HTTP requests and scripts in the plan.
6. **Bounded Recovery** may ask the Recovery Agent for one additional retry of the exact same step after a typed transient failure. The retry budget is global to one Pipeline run.
7. **Verifier** independently evaluates response, file, and log evidence.
8. **Cleanup** removes lab resources and writes an auditable report.

LangGraph owns the StateGraph, node scheduling, state transitions, and conditional routing. There is no second source-driven agent loop.

## Technology choices

| Layer | Implementation |
| --- | --- |
| Role instructions | Markdown files in `app/agents/roles/` |
| Model calls | LangChain + OpenAI API |
| Runtime / orchestration | LangGraph |
| Schemas and validation | Pydantic |
| Tool execution | Custom `StepExecutor` and Docker/HTTP/file tools |
| Recovery | Markdown-guided Recovery Agent + deterministic retry gate |
| Reproduction input | Reviewed YAML `ReproductionSpec` files in `reproductions/` |
| Retrieval | Not part of the application |

RAG, BM25, embedding indexes, the experimental source-driven runner, and the duplicate legacy workflow have been removed. The project does not use Claude Code or Claude Agent SDK.

## Transitional target inputs

The runtime now reads reviewed YAML `ReproductionSpec` files through `TargetCatalog` from `reproductions/`. The old `knowledge/` directory and `KnowledgeBase` compatibility modules have been removed. `TargetSpec` remains a separate, untrusted description of upstream target material; `ExecutionPolicy` is the independent authorization contract. The CLI and Pipeline still need the final TargetSpec/ExecutionPolicy execution gate before the new target corpus can directly drive reproduction.

The upstream Vulhub corpus now lives under `targets/vulhub/` as untrusted target material. `VulhubTargetLoader` converts environments into `TargetSpec` candidates; it never grants execution permission. Use `--action target-search` or `--action target-inspect` to explore candidates, and `--action request-validate` to validate a `ReproductionRequest`.

## Install

Python 3.11+, Docker Engine, and Docker Compose v2 are required.

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
# or: vulnforge --help
```

Configure the model through environment variables:

```bash
export OPENAI_API_KEY="..."
export PLANNER_MODEL="gpt-4o"
# Optional for an OpenAI-compatible endpoint:
export OPENAI_BASE_URL="https://..."
```

On PowerShell use `$env:OPENAI_API_KEY="..."` and `$env:PLANNER_MODEL="gpt-4o"`.

## CLI

```bash
python -m app.cli --action target-search --query CVE-2021-25646
python -m app.cli --action target-inspect --environment druid/CVE-2021-25646
python -m app.cli --action engine --check-only
python -m app.cli CVE-2021-25646 --specs reproductions --action research
python -m app.cli CVE-2021-25646 --specs reproductions --action plan
python -m app.cli CVE-2021-25646 --specs reproductions --action run
```

Use `--specs` to point to a directory containing reviewed YAML reproduction specifications. The repository does not ship reviewed reproduction recipes for every Vulhub environment; upstream Markdown/Compose material alone is not execution authorization. Use a new report path for each run. The default report location is `reports/<project>.json`.

## Safety boundaries

- Markdown and Compose documents are untrusted evidence, not policy.
- The model cannot introduce arbitrary tools, targets, probes, assertions, or shell commands.
- The plan must match the trusted reproduction specification, content hashes, and fixed lifecycle before execution.
- Docker and HTTP operations are bounded and constrained to the local lab.
- A separate Verifier evaluates observed evidence; the Planner and Reproducer cannot declare success.
- Cleanup is part of the Pipeline lifecycle.
- Recovery currently supports only retrying the exact same policy-approved transient step or aborting, with at most one Agent-approved retry across the entire Pipeline run. It cannot change tools, targets, commands, plans, or verification criteria.

## Development

```bash
python -m pytest
```

Model-backed and Docker-backed integration tests require credentials and local services. A passing unit suite does not establish that every upstream Vulhub environment can be reproduced.
