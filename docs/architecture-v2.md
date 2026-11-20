# VulnForge Architecture v2 (Draft)

 > Status: active target architecture; implementation is in progress. Completed and pending migration slices are tracked below.
> Runtime: LangGraph. Model integration: LangChain + OpenAI API. Metasploit integration: undecided; see Verification.

## 1. Product boundary

VulnForge is an agent-assisted vulnerability reproduction and verification framework.

It accepts a reproduction request, researches the target, produces a constrained execution plan, provisions an isolated environment, executes approved actions, gathers evidence, verifies the result, and cleans up.

The system supports both:
- Dynamic research from a CVE identifier, repository URL, or vulnerability description.
- A user-supplied target specification for reproducible, controlled runs.

The upstream Vulhub repository is retained under `targets/vulhub/` as target material, not treated as a KnowledgeBase or RAG corpus.

## 2. Architecture principles

1. Agents propose and reason; Python policy and execution code enforce permissions.
2. LangGraph owns workflow orchestration and explicit state transitions.
3. Domain models define shared business data, not orchestration or I/O.
4. Tools expose narrow capabilities through one registry/dispatcher and policy boundary.
5. Execution is auditable: plans, tool calls, decisions, evidence, and cleanup outcomes are recorded.
6. Recovery is bounded. Any changed plan must pass validation again.
7. Keep modules cohesive; do not create files or abstractions for trivial wrappers.

## 3. Target package layout

```text
app/
  agents/
    roles/
      researcher.md
      planner.md
      recovery.md
      verifier.md
      authoring.md
    researcher.py
    planner.py
    recovery.py
    verifier.py
    authoring.py
    prompts.py

  domain/
    requests.py       # ReproductionRequest
    targets.py        # TargetSpec, source and environment descriptors
    plans.py          # ExecutionPlan, ExecutionStep
    policies.py       # ExecutionPolicy and allowed capabilities
    results.py        # ExecutionResult, Evidence, ExecutionReport

  workflows/
    reproduction/
      graph.py        # LangGraph construction and routing
      state.py        # ReproductionState
      nodes.py        # thin orchestration nodes
    authoring.py
    batch.py

  execution/
    executor.py       # deterministic execution of validated steps
    recovery.py       # retry/replan/switch/abort policy coordination
    probes.py         # HTTP and other probes
    artifacts.py      # files, hashes, snapshots and artifact metadata

  tools/
    registry.py
    dispatcher.py
    policies.py
    builtin/
      docker.py
      http.py
      filesystem.py

  environments/
    docker/
      engine.py
      manager.py
      network.py

  evaluation/
    comparison.py
    benchmark.py
    metrics.py

  runtime/
    context.py
    models.py         # LangChain model construction/configuration
    tracing.py

  cli.py

targets/
  vulhub/             # retained upstream target material, including its license

workspace/             # generated per-run working data
reports/               # exported reports (or generated under workspace; choose one canonical location)
tests/
  unit/
  integration/
  security/
docs/
  architecture-v2.md
```

This is a target layout, not a requirement to create every file immediately. Merge tiny modules when that keeps a single cohesive responsibility.

## 4. Module responsibilities and dependency direction

- `agents`: role instructions and LLM-backed decisions. No direct Docker or unrestricted host I/O.
- `domain`: Pydantic models and pure business invariants. No LangGraph, LangChain, Docker, filesystem, or network dependencies.
- `workflows`: LangGraph nodes, edges, routing, and state lifecycle. Calls agents and execution services; does not implement low-level tools.
- `execution`: executes validated plans, gathers raw evidence, tracks artifacts, and coordinates bounded recovery.
- `tools`: narrow callable capabilities, schemas, dispatch, and policy enforcement.
- `environments`: Docker lifecycle, network/port allocation, and isolation.
- `runtime`: shared model configuration, context propagation, and tracing.
- `evaluation`: benchmark orchestration, metrics, and comparisons; it must not be required for a single reproduction run.

Dependency rule: domain is lowest-level; agents and tools depend on domain contracts; execution composes tools and environments; workflows orchestrate the services; CLI is an entry point. Avoid circular imports.

## 5. Core domain models

Initial shared contracts:

- `ReproductionRequest`: user intent, CVE/repository/description, optional supplied target specification.
- `TargetSpec`: target identity, source references, version, environment inputs, and reproduction entry points. It is a target description, not a permission grant.
- `ExecutionPolicy`: trusted allowlist of targets, tools/actions, network scope, resource limits, timeouts, and retry budget.
- `ExecutionPlan`: ordered steps, dependencies, expected observations, and verification intent.
- `ExecutionStep`: typed action and validated parameters.
- `ExecutionResult`: status, timestamps, output references, and failure classification.
- `Evidence`: provenance, collection method, content/reference, and integrity metadata.
- `RecoveryDecision`: retry, replan, switch-tool, or abort proposal plus rationale; policy remains authoritative.
- `ExecutionReport`: plan, step results, decisions, evidence, verification outcome, and cleanup status.

Models should be introduced only when a real cross-module contract needs them. Do not duplicate a field across multiple incompatible schemas.

## 6. Main workflow

1. Parse and validate `ReproductionRequest`.
2. Research target sources and build a provenance-aware `TargetSpec`.
3. Planner proposes an `ExecutionPlan`.
4. Python validates plan schema, target binding, policy, dependencies, budgets, and permitted tools.
5. LangGraph drives deployment and reproduction; Executor executes one validated step at a time.
6. Collect observations and evidence.
7. On failure, Recovery may propose a bounded action. Retry repeats an approved step; Replan creates a new plan that must pass validation; Switch Tool selects only from policy-approved alternatives; Abort stops execution.
8. Verification evaluates evidence independently of the Planner's claims.
9. Cleanup runs on success, failure, and cancellation; report is finalized.

## 7. Verification design — decision required

Do not hard-code Metasploit as the sole verifier yet.

Keep verification behind a stable interface that can accept evidence from:
- deterministic HTTP/file/log assertions;
- target-specific verification scripts;
- optional external verification adapters, potentially Metasploit.

Before implementing a Metasploit adapter, decide:
- whether it is a primary verifier, an optional exploit/check provider, or a corroborating evidence source;
- how module selection and version compatibility are controlled;
- whether only `check` is allowed by default and under what explicit authorization `run` may be used;
- how target scope, payloads, sessions, timeouts, and cleanup are constrained;
- how Metasploit results combine with independent evidence and how inconclusive results are reported.

Until that decision is made, keep the verifier interface provider-neutral and do not add a mandatory Metasploit dependency.

## 8. Legacy migration map

| Existing module | Target responsibility |
|---|---|
| `app/lab/pipeline.py` | `workflows/reproduction/graph.py` |
| `app/lab/research.py` | `agents/researcher.py` |
| `app/lab/planning.py` | split between `agents/planner.py` and `domain/plans.py` |
| `app/lab/step_executor.py` | `execution/executor.py` |
| `app/lab/recovery_controller.py` | `agents/recovery.py` decision interface |
| `app/lab/recovery.py` | inspect and split into authoring/recovery services; do not blindly move |
| `app/lab/http.py` | `execution/probes.py` |
| `app/lab/assets.py` + `app/lab/hashing.py` | `execution/artifacts.py` |
| `app/lab/ports.py` | `environments/docker/network.py` |
| `app/lab/authoring.py` + `environment_authoring.py` | `agents/authoring.py` plus authoring workflow |
| `app/lab/batch.py` | `workflows/batch.py` |
| `app/lab/comparison.py` | `evaluation/comparison.py` |
| `app/tools/docker_engine.py` + `docker_lab.py` | `environments/docker/` and Docker tool adapter |
| `app/tools/files.py` | filesystem tool adapter / artifact service, depending on call site |
| `app/lab/knowledge.py` | retire KnowledgeBase/Card abstraction; preserve useful target parsing as TargetSpec/source adapters |

## 9. Removal and retention policy

Remove obsolete RAG/BM25/embedding code, duplicate workflow implementations, and documentary-card evaluation code only after confirming no live imports or CLI references remain.

Completed: preserve the upstream Vulhub tree and license under `targets/vulhub/` without rewriting upstream files.

Do not delete target assets, scripts, Compose files, or configuration merely because they currently live under a directory named `knowledge`.

## 10. Migration sequence and acceptance criteria

1. Finalize this architecture and dependency boundaries.
2. Inventory imports, entry points, tests, and data dependencies; remove confirmed dead code.
3. Move modules incrementally, keeping compatibility only where needed and updating imports in the same commit.
4. Run unit tests after each migration slice; preserve a working CLI and one end-to-end reproduction path.
5. Confirm verification design, then implement provider-neutral verifier and any approved Metasploit adapter.
6. Expand bounded recovery and security tests.
7. Run unit, integration, and security suites; update docs; only then consider merging to main.

No mass deletion or main-branch merge should happen before the relevant migration slice passes its tests.


## 11. Implementation ledger

### Completed

- Removed the obsolete RAG/source-driven and documentary-card paths.
- Removed the duplicate sequential execution engine; LangGraph is the only runtime.
- Added pure domain contracts for requests, targets, policies, plans, evidence, and reports.
- Added a Vulhub target adapter that emits untrusted candidates and preserves source provenance.
- Moved the upstream Vulhub corpus, including its license, to `targets/vulhub/`.
- Added unit tests for domain invariants and target-loader path safety, plus a GitHub Actions unit-test workflow.

### Pending before calling the migration complete

- Wire the new request/target/policy/plan/report contracts through the actual CLI, LangGraph workflow, and executor.
- Replace the legacy YAML Card/KnowledgeBase dependency; remove `app/lab/knowledge.py` only after all call sites are migrated.
- Move workflow, agent, execution, tool, and Docker environment implementations into the target package layout without duplicate implementations.
- Add independent verifier interface and security tests; keep Metasploit optional pending a separate design decision.
- Run the CI suite and Docker-backed integration path, inspect the reports, and resolve all failures.
