# VulnForge Architecture v2

> Product direction: **Agent-driven Vulnerability Reproduction Platform**.
> Implementation status: the core LangGraph reproduction path and canonical execution-plan migration exist; Read-only Metasploit CVE discovery and module inspection plus opt-in Researcher/Planner candidate selection are implemented on this branch; RPC execution is implemented behind policy gates; Docker internal-network target attestation is now wired, while live Docker/Metasploit validation remains pending.

> PoC scope: discover, inspect, select, validate, execute, and verify **existing** PoCs and exploit modules. Autonomous PoC authoring is out of scope.

## 1. Product boundary

VulnForge is an Agent-driven vulnerability reproduction platform. Given a CVE or approved target request, it discovers existing PoCs and exploit modules, assesses their provenance and compatibility, prepares a matching vulnerable environment, executes an explicitly authorized candidate, independently verifies the result, and produces an auditable report.

The product goal is automated vulnerability reproduction. The engineering foundation is a policy-enforced Agent workflow with deterministic execution, bounded recovery, and evidence-based verification. VulnForge does not generate PoC code from scratch.

The system supports both:
- Dynamic research from a CVE identifier, repository URL, or vulnerability description.
- A user-supplied target specification for reproducible, controlled runs.

The upstream Vulhub repository is retained under `targets/vulhub/` primarily as vulnerable-environment material and reproduction documentation, not as a KnowledgeBase or RAG corpus. Vulhub entries may include native PoCs, but Vulhub is not assumed to provide a PoC for every CVE.

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
    researcher.py
    planner.py
    recovery.py
    verifier.py
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
- `PoCCandidate`: typed discovered candidate with source/module identity, CVE references, type, parsed metadata/options, and raw-metadata fingerprint. Candidate-to-plan selection remains pending.
- `PoCExecutionSpec` (planned): selected candidate, backend, approved parameters, execution mode, and expected outputs.
- `ExecutionPlan`: ordered steps, dependencies, selected candidate/backend, target binding, expected observations, and verification intent.
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
7. On failure, Recovery may propose a bounded action. Retry repeats an approved step; Replan creates a new plan that must pass validation; Switch Backend selects only from pre-approved compatible PoC candidates/backends; Abort stops execution.
8. Verification evaluates evidence independently of the Planner's claims.
9. Cleanup runs on success, failure, and cancellation; report is finalized.

## 7. PoC discovery and backend integration

Metasploit is the **primary PoC source**; read-only CVE discovery and module inspection are implemented, while execution backend integration remains planned. It is not a separate Agent and it is not the whole application. Search results are candidates, not proof of compatibility or authorization.

Discovery priority:
1. Metasploit Framework: search CVE references; inspect module identity, type, description, supported targets, product/version constraints, options, check support, payload/session requirements, side effects, and provenance.
2. GitHub, Exploit-DB, and upstream project repositories: find existing standalone PoCs when no suitable Metasploit module exists.
3. Vulhub: primarily identify a compatible local vulnerable environment and its version/configuration/reproduction documentation; use bundled native PoCs when present.

A Metasploit module mentioning a CVE does not prove that it affects the selected version or can reproduce the issue in the selected environment. Missing modules, unsupported targets, missing options, and inconclusive checks must be reported honestly. Do not invent parameters or treat a search hit as proof of exploitability.

Keep verification provider-neutral. A module's own success message or session creation is not, by itself, sufficient proof; the Verifier must independently assess target-specific HTTP, file, log, or other evidence.

The current discovery service invokes only `msfconsole search` and `info` with validated inputs and `shell=False`. It does not run `check` or `exploit`. The next execution integration should use a controlled API such as msfrpcd/RPC, then add policy-gated `check` and explicitly approved exploit execution. Do not expose unrestricted msfconsole commands to the Agent. Payloads, sessions, credentials, timeouts, side effects, and cleanup require explicit controls.

## 8. Legacy migration map

| Existing module | Target responsibility |
|---|---|
| `app/lab/pipeline.py` | `workflows/reproduction/graph.py` (moved; old path is compatibility import) |
| `app/lab/research.py` | `agents/researcher.py` (moved; old path is compatibility import) |
| `app/lab/planning.py` | `agents/planner.py` (moved); legacy deployment-plan schema still awaits replacement by `domain/plans.py` |
| `app/lab/step_executor.py` | `execution/executor.py` (moved; old path is compatibility import) |
| `app/lab/recovery_controller.py` | `agents/recovery.py` (moved; currently retry/abort only) |
| `app/lab/recovery.py` | removed; superseded by bounded `agents/recovery.py` and `execution/recovery.py` |
| `app/lab/http.py` | `execution/probes.py` (moved) |
| `app/lab/assets.py` + `app/lab/hashing.py` | `execution/artifacts.py` (moved) |
| `app/lab/ports.py` | `environments/docker/network.py` (moved) |
| `app/lab/authoring.py` + `environment_authoring.py` | removed; autonomous PoC and environment authoring are outside the product scope |
| `app/lab/batch.py` | `workflows/batch.py` |
| `app/lab/comparison.py` | `evaluation/comparison.py` |
| `app/tools/docker_engine.py` + `docker_lab.py` | `environments/docker/` (moved; old paths are compatibility imports) |
| `app/tools/files.py` | `tools/builtin/filesystem.py` (moved; old path is compatibility import) |
| `app/lab/knowledge.py` | removed; reviewed YAML specs are loaded by `targets/vulhub/catalog.py` |

## 9. Removal and retention policy

Remove obsolete RAG/BM25/embedding code, duplicate workflow implementations, and documentary-card evaluation code only after confirming no live imports or CLI references remain.

Completed: preserve the upstream Vulhub tree and license under `targets/vulhub/` without rewriting upstream files.

Do not delete target assets, scripts, Compose files, or configuration merely because they currently live under a directory named `knowledge`.

## 10. Product direction and implementation sequence

Product identity: **Agent-driven Vulnerability Reproduction Platform**. Metasploit is the primary PoC source and planned exploit execution backend; GitHub/Exploit-DB/upstream repositories are secondary PoC sources; Vulhub is primarily the vulnerable-environment source. PoC generation is out of scope.

1. Keep the canonical `ExecutionPlan`, `ExecutionPolicy`, and LangGraph path stable.
2. Define `PoCCandidate` and `PoCExecutionSpec` against real Metasploit and standalone-PoC requirements.
3. Implement Metasploit CVE/module discovery and read-only metadata/options inspection first.
4. Add policy-bound Metasploit `check` support where available; document module-specific side effects and limitations.
5. Add controlled RPC exploit execution with explicit approval, isolated target binding, timeout, output capture, and session cleanup.
6. Add secondary existing-PoC sources and a constrained standalone script adapter.
7. Keep Vulhub environment selection independent from PoC source selection; connect candidates to compatible local targets.
8. Add container egress isolation, safe backend switching, and independent evidence checks.
9. Build a CVE reproduction benchmark covering discovery coverage, candidate compatibility, reproduction success, false-positive rate, execution time, and cleanup reliability.
10. Run unit, integration, Docker-backed, and security suites before merging.

Do not make Metasploit a mandatory runtime dependency until its adapter and security boundary are implemented and tested. No mass deletion or main-branch merge should happen before the relevant migration slice passes its tests.


## 11. Implementation ledger

### Completed

- Removed the obsolete RAG/source-driven and documentary-card paths.
- Removed the duplicate sequential execution engine; LangGraph is the only runtime.
- Added pure domain contracts for requests, targets, policies, plans, evidence, and reports.
- Added a Vulhub target adapter that emits untrusted candidates and preserves source provenance.
- Moved the upstream Vulhub corpus, including its license, to `targets/vulhub/`.
- Added unit tests for domain invariants, target-loader path safety, policy enforcement, and a fake-Docker end-to-end Pipeline path; the latest CI run passed 29 tests.
- Planner emits canonical `ExecutionPlan` directly; LangGraph and Executor share that contract. The legacy plan adapter has been removed.
- Added `policy-preview`, explicit policy-file requirements, content-hashed target approval, fixed loopback ports, policy-gated retries, and provider-neutral evidence verification.

### Pending before calling the migration complete

- Finish the last import/dead-code audit and retain only thin compatibility wrappers for the old `app.lab` and `app.tools` paths.
- Add container egress isolation so `network_scope` constrains Docker pull/build and container traffic, not only loopback HTTP probes.
- Decide whether Metasploit is an optional check provider or corroborating verifier; do not make it mandatory before the safety contract is defined.
- Run a real Docker-backed reproduction through deployment, verification, and cleanup; the repository currently contains no reviewed reproduction YAML fixture, and the fake-Docker Pipeline test is not a substitute for this.

 
### Latest migration slice

- Added `ReproductionSpec` to `app/domain/reproduction.py` for reviewed reproduction probes, scripts, and independent assertions.
- Added `TargetCatalog` as the filesystem adapter for reviewed reproduction specs; runtime agents, execution, workflows, and environment adapters now import domain schemas and the catalog directly.
- Removed the deprecated `legacy_cards.py` and `app/lab/knowledge.py` compatibility modules and the empty `knowledge/` directory.
- CLI now accepts `--specs` and defaults to `reproductions/`.

### Still required

- Run a representative, explicitly reviewed local reproduction through Docker, including cleanup and independent verification; this repository currently contains no reviewed reproduction YAML fixture, so an end-to-end Docker run cannot be honestly claimed.


### Policy and verification integration update

- Added `policy-preview` to emit target and reproduction fingerprints plus a review-only JSON policy template; both `plan` and `run` require an explicit policy file.
- Bound `TargetSpec`, `ReproductionSpec`, `ExecutionPolicy`, and the canonical `ExecutionPlan` in the LangGraph planning stage.
- The executor re-derives the target and reproduction fingerprints from the current catalog before opening the lab, then revalidates every planned action and retry budget.
- Target source files and Compose inputs are content-hashed; policy approval rejects unpinned remote sources and non-loopback published ports.
- Recovery retries now require the action to be explicitly marked retryable in policy and remain within the policy recovery budget.
- The provider-neutral `EvidenceVerifier` is wired into the execution verification phase for reviewed HTTP, file, and log assertions.
- Policy-bound execution uses fixed target ports because automatic port rewriting would invalidate the approved fingerprint.


## 12. Product decisions (2026-11-20)

- Product goal: reliable automated reproduction of known vulnerabilities.
- Primary PoC source/backend: Metasploit Framework.
- Secondary PoC sources: GitHub, Exploit-DB, and upstream project repositories.
- Primary vulnerable-environment source: Vulhub; native Vulhub PoCs are optional rather than assumed.
- PoC authoring/generation: explicitly out of scope.
- Separation of concerns: Researcher discovers and inspects; Planner selects and plans; deterministic policy authorizes; Executor invokes adapters; Verifier independently evaluates evidence; Recovery coordinates bounded retry/replan/backend-switch/abort.
- Read-only Metasploit CVE discovery and module metadata inspection are implemented through `app/discovery/metasploit.py` and the `metasploit-search` / `metasploit-inspect` CLI actions.
- The policy-gated RPC adapter and target-bound `PoCExecutionSpec` are implemented. The optional LangGraph stage now connects Planner selection to Check and conditionally Execute; independent verification still runs through the existing StepExecutor verifier. Live end-to-end validation against a running local Metasploit service and Docker lab remains outstanding.


## Metasploit LangGraph execution stage

The LangGraph run can optionally execute a Planner-selected Metasploit candidate. This is opt-in and restricted to the current loopback-only V1 policy boundary.

- Discover candidates with `--discover-metasploit`.
- Review the exact candidate metadata SHA-256 and add it to `approved_poc_candidates` in the policy file.
- Explicitly set `allow_metasploit_check` and `allow_metasploit_execute` to `true`. Unknown product/version compatibility requires its own explicit policy approval.
- Configure `MSFRPC_USER`, `MSFRPC_PASS`, and optionally `MSFRPC_HOST=127.0.0.1`, `MSFRPC_PORT=55553`, `MSFRPC_SSL=true`, `MSFRPC_URI=/api/`.
- Run with both `--discover-metasploit` and `--enable-metasploit-execution`.

The stage revalidates the plan, research-bundle fingerprint, target/reproduction fingerprints, and exact candidate metadata. It calls `module.check` first; `module.execute` is reachable only after a completed `vulnerable` check and the same adapter instance confirms the check binding. Safe results stop the Metasploit path; unsupported/unknown results remain inconclusive.

The existing StepExecutor verification phase evaluates reviewed target assertions independently. A completed Metasploit job is not proof of vulnerability: final success still depends on independent evidence. Cleanup remains in the normal pipeline finalizer.

The V1 integration uses the RPC adapter loopback target restriction. The private Docker-network endpoint resolver is available separately, but private-address attestation is not yet wired into the RPC authorization contract. Do not broaden policy to arbitrary private or public targets to work around this limitation.


## Isolated Metasploit target networking

Metasploit no longer receives an arbitrary private IP. The optional execution path requires a reviewed Compose service attached to an explicitly internal network and a separately running Metasploit container attached only to that same network.

Example Compose fragment:

```yaml
services:
  web:
    image: example/web:1.2
    ports:
      - "127.0.0.1:18080:8080/tcp"
    networks: [exploit-lab]
networks:
  exploit-lab:
    internal: true
    name: lab-demo-isolated
```

The operator must set `approved_lab_networks` in the execution policy, mapping the exact target ID to the explicit Docker network name, and set `MSF_CONTAINER_NAME` to the already-running Metasploit container. The Metasploit RPC HTTP endpoint remains host-loopback-only; only the module target address uses the attested private container IP.

Before creating a `PoCExecutionSpec`, Docker inspection verifies:
- The named Docker network exists and Docker reports `Internal: true`.
- The target and Metasploit containers are running and share the exact inspected network ID.
- Each container has exactly one network attachment, preventing an additional bridge/host-facing network from bypassing internal-network egress isolation.
- The target service and published TCP port match the reviewed Compose configuration and policy.
- The Compose fingerprint matches the research bundle; the resulting attestation binds both container IDs, private IPs, network ID, and published-to-container port mapping.

Private target addresses are rejected unless this attestation is present and the exact network name is approved in policy. The runtime does not infer authorization from RFC1918 addressing. Callback payloads remain separately disabled unless policy explicitly enables them.

Live Docker daemon, Metasploit RPC, exploit execution, and teardown validation remain required; fake-Docker tests prove the authorization checks, not real-world isolation.


Run the opt-in real-Docker network integration test with `VULNFORGE_DOCKER_INTEGRATION=1 python -m pytest -q tests/test_docker_isolation_integration.py`. It verifies peer reachability on the internal lab network, blocked external egress, and the one-network-only container attachment invariant. The default unit suite skips this test unless explicitly enabled.
