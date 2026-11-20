# Agent Vulnerability Reproduction Workflow

A local Docker lab workflow with persistent retrieval, validated plans, script
execution, independent evidence checks, bounded recovery and durable reports.
The CLI reads local Vulhub environments and uses separate knowledge cards for evaluation.

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
python -m app.lab.cli run CVE-2021-25646 --timeout 300 --report reports/druid-001.json
```

A bare CVE identifier starts a complete experiment. The source planner reads
`knowledge/vulhub/<product>/<environment>/docker-compose.yml` and its Markdown files.
The runner snapshots the environment into `.labs` and binds published ports to
loopback. A LangGraph agent/tool loop reads observations and chooses subsequent
HTTP requests, container commands, source reads or log inspection. The agent's
finish action submits the attempt for evaluation against the corresponding root
YAML card. Missing evaluation evidence produces an `inconclusive` result.
Execution and cleanup evidence are saved in the report.

Each report has a sibling `<report-stem>.trace.jsonl` containing timestamped,
ordered model calls, tool inputs/results/errors, agent decisions and cleanup.
Model responses include raw provider metadata when supplied. Events are flushed
to disk as they occur. `--max-steps` limits agent decisions (default 30).
`--engine sequential` runs the same decision/tool loop without LangGraph.

## Run a complete lab

```powershell
python -m app.lab.cli engine
python -m app.lab.cli CVE-2021-25646 --action plan
python -m app.lab.cli CVE-2021-25646 --timeout 300 --report reports/druid-002.json
```

The CLI checks Docker and attempts local engine startup when needed. OS permissions
still apply. It selects an available loopback port if the card port cannot bind;
use `--fixed-port` to require the specified port. Use a new report name each run.
Script exit code zero is insufficient: independent HTTP/file assertions must pass.
Containers, networks and project volumes are cleaned up unless `run` uses `--keep`.

## Core CLI

Search copied Vulhub environments and read their complete Compose and Markdown sources:

```powershell
python -m app.lab.cli CVE-2021-25646 --action search
python -m app.lab.cli CVE-2021-25646 --action research
python -m app.lab.cli CVE-2021-25646 --action research --model
```

These search and research commands use `knowledge/vulhub/<product>/<environment>/`.
The research model receives the environment's Compose and Markdown files, with
source paths for citations. YAML evaluation cards are excluded from that input.
`--model` enables model synthesis for research. Planning and running always use
the source model. The source model supports `LLM_API_KEY`, `LLM_BASE_URL` and
`LLM_MODEL` in the project `.env`, and their process environment equivalents.
Process settings take precedence. `OPENAI_API_KEY`, `OPENAI_BASE_URL` and
`PLANNER_MODEL` are also supported.

| Action | Purpose |
| --- | --- |
| `engine` | Check or start Docker |
| `index`, `search`, `research` | Index and research local knowledge |
| `plan`, `run`, `inspect` | Plan, execute and inspect a lab run |

Model features require `OPENAI_API_KEY` and `PLANNER_MODEL`; optionally set
`OPENAI_BASE_URL`. `--dense` additionally requires `RAG_EMBEDDING_MODEL`.
The legacy embedding providers use process environment settings.

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

## Extract Vulhub candidates

For an existing documentary card with one web step and one fenced HTTP/JSON
example in its source README, compare the card with the document from the
repository root:

```powershell
.\.venv\Scripts\python.exe -m app.lab.document_evidence knowledge-candidates/documented/1panel-CVE-2024-39907.yaml
```

Each row reports the field, comparison rule, expected value, observed metadata,
and result. A mismatch produces a nonzero exit code. Add `--enrich` to replace
the step's method and request shape from the document. These checks describe
agreement with the source text; runtime outcomes remain unobserved.

The optional extractor sends each Vulhub environment's text files to an
OpenAI-compatible model and writes schema-validated YAML candidates plus the
original environment files to a separate directory. Configure the model in
PowerShell (the project does not automatically load `.env`):

```powershell
$env:OPENAI_API_KEY = '<your key>'
$env:OPENAI_BASE_URL = 'https://your-provider.example/v1'
$env:PLANNER_MODEL = '<model name>'
.\.venv\Scripts\python.exe -m app.lab.extract_vulhub --vulhub vulhub --output knowledge-candidates/vulhub --limit 2
```

Remove `--limit` to scan all environments. Existing candidates/assets are
skipped, so a stopped run can be resumed. Failures are listed in
`extraction-failures.json`; a nonzero exit status indicates at least one
failure. Text files are sent to the configured provider and calls may incur
costs. Review sources, Compose assets, ports, reproduction steps and evidence
before using a candidate; schema validation does not establish factual accuracy
or successful reproduction. The extractor cannot represent every Vulhub case.
Candidates are not automatically added to the production knowledge directory.
