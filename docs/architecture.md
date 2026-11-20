# Architecture status

The proposed target architecture is documented in [architecture-v2.md](architecture-v2.md). It is the design source of truth for the ongoing refactor.

## Transitional implementation

The current branch still runs the legacy LangGraph Pipeline under `app/lab/`. It temporarily consumes reviewed YAML cards through `app/lab/knowledge.py`; this is a migration dependency, not a commitment to retain the KnowledgeBase design.

The next migration replaces that input contract with `ReproductionRequest`, `TargetSpec`, and a separately trusted `ExecutionPolicy`. Until that slice is implemented and tested, do not delete the remaining legacy card loader or its required assets.

RAG, BM25, embeddings, the duplicate sequential workflow path, and the documentary-card evaluation utilities are not part of the target system.
