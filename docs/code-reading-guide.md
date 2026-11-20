# VulnForge code-reading guide

Read the project in the same order as one authorized reproduction run.

## 1. Product boundary and domain contracts

Start with `README.md` and `docs/architecture-v2.md`. Then read:

- `app/domain/requests.py`
- `app/domain/targets.py`
- `app/domain/reproduction.py`
- `app/domain/plans.py`
- `app/domain/policies.py`
- `app/domain/results.py`

These define the shared data contracts. Target descriptions and discovered PoCs are not execution authorization; the reviewed policy is the permission boundary.

## 2. Follow the runtime

Start at `app/cli.py`, then `app/workflows/reproduction/graph.py` and `app/workflows/reproduction/state.py`. LangGraph owns orchestration, state transitions, and conditional routing.

## 3. Understand discovery and planning

Read `app/agents/researcher.py`, `app/agents/planner.py`, and their Markdown role instructions. Researcher gathers source-backed target facts; Planner selects from existing reproduction material and emits the canonical `ExecutionPlan`.

Metasploit-first discovery and its controlled RPC adapter are planned integrations, not current completed features.

## 4. Understand policy and side effects

Read `app/execution/executor.py`, `app/execution/recovery.py`, `app/agents/recovery.py`, `app/environments/docker/manager.py`, `app/environments/docker/network.py`, and `app/tools/dispatcher.py`. Deterministic policy validation controls what the Executor may do.

## 5. Understand evidence and verification

Read `app/execution/verifier.py` and `app/execution/artifacts.py`. The Verifier evaluates collected evidence independently; an Agent or backend success message is not sufficient proof.

## 6. Run tests

```bash
python -m pytest -q
```

Unit tests do not replace real Docker-backed reproduction, Metasploit integration, or security-isolation testing.
