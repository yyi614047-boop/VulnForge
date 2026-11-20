# VulnForge code-reading guide

Read the project in the same order as one Pipeline run.

## 1. Start with role instructions

Read `app/agents/roles/researcher.md` and `app/agents/roles/planner.md`. These Markdown files define responsibilities and constraints supplied to the model. They are guidance, not the enforcement boundary.

## 2. Follow the runtime

Start at `app/lab/cli.py`, then read `app/lab/pipeline.py`. The Pipeline builds the LangGraph StateGraph and defines the Researcher, Planner, Deployer, Reproducer, Verifier, and Cleanup nodes.

## 3. Understand research and planning

Read `app/lab/research.py`, `app/lab/planning.py`, and `app/lab/knowledge.py`. Researcher reads only declared source files. StructuredPlanner creates a typed plan. The validator binds the plan to the trusted card, hashes, citations, and lifecycle.

## 4. Understand side effects

Read `app/lab/step_executor.py`, `app/lab/recovery_controller.py`, `app/agents/roles/recovery.md`, `app/tools/docker_lab.py`, `app/tools/docker_engine.py`, `app/tools/registry.py`, and `app/lab/http.py`. The Recovery Agent can recommend only retry or abort; the executor enforces retryability and a one-attempt recovery budget.

## 5. Understand state and model context

Read `app/agent_context.py` for node state boundaries and per-agent invocation context. Read `app/trace.py` for model/tool trace recording.

## 6. Optional Pipeline extensions

Explore `authoring.py`, `environment_authoring.py`, `recovery.py`, `comparison.py`, and `batch.py`. These reuse the staged Pipeline; they do not introduce another primary runtime.

## 7. Run tests

```bash
python -m pytest -q
```

Tests do not replace validation against real Docker environments and actual vulnerable software versions.
