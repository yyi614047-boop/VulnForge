# VulnForge architecture

The target architecture and migration sequence are maintained in [architecture-v2.md](architecture-v2.md).

## Current migration status

- LangGraph is the only workflow engine.
- LangChain + OpenAI remains the model integration.
- RAG, BM25, embedding indexes, the duplicate sequential runner, and documentary evaluation cards have been removed.
- Pure domain contracts live under `app/domain/`: `ReproductionRequest`, `TargetSpec`, `ExecutionPolicy`, `ExecutionPlan`, and execution/evidence result models.
- Canonical package boundaries now exist under `app/agents/`, `app/workflows/`, `app/execution/`, `app/environments/`, `app/tools/builtin/`, `app/runtime/`, and `app/evaluation/`.
- The old `app/lab/` and `app/tools/` entry points are compatibility imports; the legacy YAML card adapter is isolated under `app/targets/vulhub/legacy_cards.py`.
- The upstream Vulhub corpus is preserved under `targets/vulhub/`; candidate loading does not grant execution permission.
- The legacy Pipeline still depends on `app/lab/knowledge.py` and is not yet fully wired to the new domain contracts. That compatibility path must be removed only after the executor and workflows enforce `ExecutionPolicy`.

Do not describe the runtime migration as complete until the new request, target, policy, plan, and report contracts are used by the actual CLI-to-executor path and the integration tests pass.
