# VulnForge

A local Docker-based Agent workflow for authorized vulnerability reproduction.
The primary CLI reads local Vulhub source documents, plans a bounded reproduction,
runs it in an isolated Compose project, independently evaluates the observed effect,
and records an auditable report.

The primary workflow does **not** depend on RAG, BM25, embeddings, or a vector index.
Trusted YAML knowledge/evaluation cards and their declared source files remain the
source of execution constraints. Retrieval experiments are kept separate from the
production path; see [experimental retrieval](docs/embedding-experiment.md).

## Install and test

Python 3.11+, Docker Engine and Docker Compose v2 are required for real lab runs.

```powershell
python -m venv .venv
python -m pip install -e ".[dev]"
python -m pytest
```

## Run a Vulhub experiment

```powershell
python -m app.lab.cli CVE-2021-25646
python -m app.lab.cli CVE-2021-25646 --action plan
python -m app.lab.cli CVE-2021-25646 --timeout 300 --report reports/druid-001.json
```

A bare CVE identifier starts a complete experiment. The source researcher reads the
matching local Vulhub environment's Compose and Markdown files directly. The planner
creates a bounded, source-cited plan. The runner snapshots the environment into
`.labs`, binds published ports to loopback, and starts the Docker Compose project.
A LangGraph agent/tool loop then chooses the next allowed HTTP request, container
command, source read, log inspection, finish, or abort action based on actual
observations. Finishing submits the attempt to a separate evaluator; it does not
declare success. The evaluator compares the observed behavior with a separate
reviewed evaluation card. Missing or ambiguous evidence yields `inconclusive`.

Each report has a sibling `<report-stem>.trace.jsonl` containing ordered model calls,
tool inputs/results/errors, agent decisions and cleanup events. `--max-steps` limits
agent decisions (default 30). `--engine sequential` runs the same decision/tool loop
without LangGraph.

## Core CLI

| Action | Purpose |
| --- | --- |
| `engine` | Check or start Docker |
| `search` | Exact keyword/CVE search across local Vulhub environment names and Markdown |
| `research` | Read the matched environment's complete Compose and Markdown sources |
| `plan` | Generate and validate a source-cited reproduction plan |
| `run` | Execute, independently evaluate, clean up and write a report |
| `inspect` | Pretty-print an existing JSON report |

Examples:

```powershell
python -m app.lab.cli CVE-2021-25646 --action search
python -m app.lab.cli CVE-2021-25646 --action research
python -m app.lab.cli CVE-2021-25646 --action research --model
python -m app.lab.cli CVE-2021-25646 --action plan
python -m app.lab.cli CVE-2021-25646 --engine sequential
python -m app.lab.cli inspect reports/run-001.json
```

Model features require `OPENAI_API_KEY` and `PLANNER_MODEL`; optionally set
`OPENAI_BASE_URL`. The existing `LLM_API_KEY`, `LLM_BASE_URL`, and `LLM_MODEL`
aliases are also supported by the runner. Process environment variables take
precedence over the project's `.env` settings where applicable.

The CLI checks Docker and attempts local engine startup when needed. It selects an
available loopback port if the card port cannot bind; use `--fixed-port` to require
the specified port. Use a new report name each run. Script exit code zero is
insufficient: independent response/file assertions must pass. Containers, networks
and project volumes are cleaned up unless `run` uses `--keep`.

## Main architecture

- `app/lab/vulhub_researcher.py`: direct local source reading and citation checking
- `app/lab/vulhub_run.py`: source planning, bounded reproduction loop, independent evaluation and cleanup
- `app/lab/knowledge.py`: typed trusted knowledge cards and local knowledge loading
- `app/lab/planning.py`, `step_executor.py`: constrained plans, policy checks and execution
- `app/lab/hashing.py`: content hashes used to bind plans to their source inputs
- `app/tools/`: Docker, filesystem, web and Vulhub source tools
- `app/rag/`: experimental retrieval code only; not imported by the primary CLI/runtime

The card-based `Pipeline` API remains available for staged execution. Both execution
paths use explicit evidence, bounded operations and cleanup. See
[architecture](docs/architecture.md), [autonomous workflow](docs/autonomous-workflow.md),
[script tools](docs/script-tools.md), and the [Chinese code-reading guide](docs/code-reading-guide.md).

## Other capabilities

Authoring, recovery, comparison, batch queues, case assistant and documentary review
remain available as Python APIs and integration examples. Their availability does
not make them part of the minimal primary CLI path.

## Integration checks

```powershell
python -m examples.authoring_smoke
python -m examples.advanced_smoke
```

These use fixed model responses and real Docker to test orchestration, not live-model
quality. Real model quality and real CVE package behavior still require separate
validation. Web evidence is not automatically trusted execution configuration.

## Extract Vulhub candidates

The optional extractor writes schema-validated candidate YAML cards and copies
source environments into a separate directory. It does not add candidates to the
production knowledge directory automatically. Review source citations, Compose
assets, ports, reproduction steps and evidence before accepting a candidate.
