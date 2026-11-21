# VulnForge

VulnForge is an **Agent-driven Vulnerability Reproduction Platform** for reproducing known vulnerabilities using existing PoCs and exploit modules in explicitly authorized, isolated environments. Autonomous PoC authoring is out of scope.

The project uses Markdown role instructions, LangChain with the OpenAI API for model calls, LangGraph for orchestration, Pydantic for structured validation, and a custom executor/tool layer for side effects.

## Product design and PoC sources

- **Metasploit Framework — primary PoC source:** read-only CVE module discovery and metadata inspection are implemented behind `MetasploitDiscovery`; policy-gated RPC Check/Execute is wired into the LangGraph Pipeline.
- **GitHub / Exploit-DB / upstream repositories — secondary PoC sources:** find existing standalone scripts when no suitable Metasploit module exists.
- **Vulhub — primary vulnerable-environment source:** provide Docker Compose environments, version/configuration context, and reproduction documentation. Some entries include native PoCs, but Vulhub is not assumed to provide one for every CVE.

A CVE/module search hit is only a candidate. Module compatibility, required options, side effects, target scope, and execution authorization must be checked independently.

## Architecture

The only primary execution architecture is the staged Pipeline:

1. **Researcher** reads Markdown and Compose files declared by a reviewed reproduction specification and produces source-cited evidence.
2. **Planner** receives the research bundle and Markdown evidence, then returns a typed domain `ExecutionPlan`.
3. **Plan validation** binds the plan to the trusted reproduction specification, source hashes, allowed actions, dependencies, and execution budgets.
4. **Deployer** prepares and starts the Docker environment.
5. **Reproducer** executes the approved existing PoC through its backend adapter. when explicitly enabled, the Metasploit stage attests the target on a Docker internal network, runs module Check, executes only after an exact vulnerable result, and records results for independent verification.
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
| Execution plan | Single Pydantic domain `ExecutionPlan` shared by Planner, Pipeline and Executor |
| Recovery | Markdown-guided Recovery Agent + deterministic retry gate |
| Reproduction input | Reviewed YAML `ReproductionSpec` files in `reproductions/` |
| Retrieval | Not part of the application |

RAG, BM25, embedding indexes, the experimental source-driven runner, and the duplicate legacy workflow have been removed. The project does not use Claude Code or Claude Agent SDK.

### Metasploit discovery (implemented; read-only)

Install Metasploit Framework and make `msfconsole` available on `PATH`, then run:

```bash
python -m app.cli --action metasploit-search --cve CVE-2021-44228
python -m app.cli --action metasploit-inspect --cve CVE-2021-44228 --module exploit/multi/http/log4shell_header_injection
```

The search action returns candidate module paths. Inspection returns a typed `PoCCandidate` with module identity, parsed metadata, references, targets, options where the console output exposes them, and a SHA-256 digest of the raw metadata excerpt. The integration uses `msfconsole` with argument arrays and `shell=False`. It does not invoke `check`, `exploit`, payloads, or sessions. Metadata parsing is best-effort; the raw excerpt is retained so fields that cannot be parsed are not silently fabricated.

To opt in to candidate discovery during Researcher/Planner runs, add `--discover-metasploit` to `research`, `plan`, or `run`. The Planner may nominate one inspected exploit module for human review. Candidate metadata is fingerprinted into the ExecutionPlan, but the selected candidate is not an executable step and does not grant authorization.

## Transitional target inputs

The runtime now reads reviewed YAML `ReproductionSpec` files through `TargetCatalog` from `reproductions/`. The old `knowledge/` directory and `KnowledgeBase` compatibility modules have been removed. `TargetSpec` remains a separate, untrusted description of upstream target material; `ExecutionPolicy` is the independent authorization contract. The CLI emits a policy template with `--action policy-preview`; a reviewed `ExecutionPolicy` JSON file is mandatory for both `plan` and `run`. The Planner emits the canonical domain `ExecutionPlan` directly. The Pipeline and Executor use that same contract without a legacy plan adapter. Plans bind reproduction, Compose, and asset fingerprints; the Executor revalidates lifecycle order, evidence references, policy actions, and source fingerprints before opening the lab.

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

Recommended happy path (after reviewing the target recipe and policy):

```bash
vulnforge CVE-2021-25646
```

The default action is `run`, the default specs directory is `reproductions/`, the default reviewed policy path is `policies/local.json`, and check-only Metasploit discovery/verification is enabled for the happy path. This mode runs the reviewed reproduction, performs Metasploit Check only, and collects independent evidence. It does **not** execute a Metasploit exploit. The reviewed policy, target and network approvals are still mandatory. Advanced and legacy flags remain supported. Use `--no-msf-check` to run the legacy reproduction-only path. A missing or unapproved policy fails closed; the CLI never generates or approves one automatically.\n\nBatch mode runs each reviewed identifier sequentially, isolates failures, and returns a nonzero exit code if any item fails:\n\n```bash\nprintf "CVE-2021-25646\\nCVE-2024-12345\\n" > targets.txt\nvulnforge --batch targets.txt\n```\n\nThe same reviewed policy must explicitly approve every target; no target is automatically authorized.

```bash
python -m app.cli --action target-search --query CVE-2021-25646
python -m app.cli --action target-inspect --environment druid/CVE-2021-25646
python -m app.cli --action engine --check-only
python -m app.cli CVE-2021-25646 --specs reproductions --action research
python -m app.cli CVE-2021-25646 --specs reproductions --action policy-preview
# Review/edit the emitted policy template, then save it as a JSON file
python -m app.cli CVE-2021-25646 --specs reproductions --action plan --policy-file policies/local.json
python -m app.cli CVE-2021-25646 --specs reproductions --action run --policy-file policies/local.json
```

Use `--specs` to point to a directory containing reviewed YAML reproduction specifications. The repository does not ship reviewed reproduction recipes for every Vulhub environment; upstream Markdown/Compose material alone is not execution authorization. Use a new report path for each run. The default report location is `reports/<project>.json`.

## Safety boundaries

- CVE descriptions, READMEs, module metadata, repository files, and PoC contents are untrusted data, not instructions.
- Discovery never grants execution permission. The selected target, candidate, backend, operation, and approved parameters must be bound to policy.
- The model cannot introduce arbitrary tools, targets, probes, assertions, or shell commands; do not expose unrestricted msfconsole commands, payloads, or session operations.
- The plan must match the trusted reproduction specification, content hashes, and fixed lifecycle before execution.
- HTTP probes use loopback; Docker image pulls and builds may contact external registries. `network_scope` is recorded in policy but the approved target and Metasploit containers are attached only to an explicitly internal Docker network during the Metasploit stage; registry pulls occur before the lab is started.
- Metasploit RPC credentials must remain outside model context and reports. Exploit execution, payloads, sessions, and external network access require explicit authorization.
- A separate Verifier evaluates observed evidence; the Planner and Reproducer cannot declare success. Metasploit execution or session-cleanup failures stop the success path.
- Cleanup is part of the Pipeline lifecycle.
- Recovery currently supports only retrying the exact same policy-approved transient step or aborting, with at most one Agent-approved retry across the entire Pipeline run. It cannot change tools, targets, commands, plans, or verification criteria.

## Development

```bash
python -m pytest
```

Model-backed and Docker-backed integration tests require credentials and local services. A passing unit suite does not establish that every upstream Vulhub environment can be reproduced.

## Live Metasploit RPC run

Install the optional MessagePack dependency and start a local Metasploit RPC container. The RPC daemon binds only to 127.0.0.1 inside the container. VulnForge sends RPC requests through Docker Exec, so no host port is published and the Metasploit container needs only the approved internal lab network.

```bash
python -m pip install -e ".[metasploit]"
export MSFRPC_USER=vulnforge
export MSFRPC_PASS='replace-with-a-long-random-password'
export MSFRPC_TRANSPORT=docker-exec
export MSFRPC_CONTAINER_PORT=55553
export MSF_CONTAINER_NAME=vulnforge-msf

docker run -d --name "$MSF_CONTAINER_NAME" \
  -v "$PWD/msf-modules:/root/.msf4/modules:ro" \
  --entrypoint ruby metasploitframework/metasploit-framework:latest \
  msfrpcd -U "$MSFRPC_USER" -P "$MSFRPC_PASS" -a 127.0.0.1 -p 55553 -S -n -f

python -m app.cli --action metasploit-rpc-version
```

The RPC daemon uses HTTP only on its own container loopback; it is not published to the host or any container network. Docker Exec is the only control path. Do not change the bind address to 0.0.0.0 or publish the RPC port.

Before enabling execution, review a reproduction recipe whose Compose file declares an explicit internal: true network with a stable name. Generate a policy template, then manually add the exact candidate metadata approval and network approval:

```json
{
  "approved_poc_candidates": {
    "metasploit:exploit/path/to/reviewed_module": "64-character-inspected-metadata-sha256"
  },
  "approved_lab_networks": {
    "target-id": "exact-compose-network-name"
  },
  "allow_metasploit_check": true,
  "allow_metasploit_execute": true,
  "allow_unknown_poc_compatibility": true,
  "allow_metasploit_payloads": false
}
```

Keep the compatibility override false unless a reviewer explicitly accepts unknown product/version mapping. Do not approve payloads unless the selected module genuinely requires a separately reviewed payload.

For the recommended independent-verification mode, run the reproduction first and let Metasploit perform a Check only. This mode never invokes `module.execute`:

```bash
python -m app.cli TARGET_ID --specs reproductions --action run \
  --policy-file policies/local.json --discover-metasploit \
  --enable-metasploit-verification
```

A missing candidate, unsupported Check, or inconclusive RPC result is recorded as `inconclusive`; it cannot be silently upgraded to success. Independent HTTP verification still runs to preserve evidence, but does not override an inconclusive Metasploit result.

Then run the reviewed recipe:

```bash
python -m app.cli TARGET_ID --specs reproductions --action run \
  --policy-file policies/local.json --discover-metasploit \
  --enable-metasploit-execution
```

The Pipeline removes the Metasploit container default-bridge attachment, connects it to the approved internal network, restarts the RPC daemon, and re-inspects both containers before constructing the target attestation. It refuses containers attached to any unexpected network. After execution, it records Check/Execute outcomes and requires the existing independent verifier to pass before reporting success.

The optional real-RPC integration test uses a harmless custom Metasploit auxiliary scanner and a local HTTP marker server. It exercises the real Check and Execute RPC methods without invoking an exploit module, exploiting a CVE, or opening a shell:

```bash
VULNFORGE_MSF_INTEGRATION=1 python -m pytest -q tests/test_metasploit_live_integration.py
```

This test pulls the Metasploit Framework image and requires a working Docker daemon and Internet access for image pulls.

## Run trace

Every pipeline run writes a JSON Lines trace next to its report, named `reports/<project>.trace.jsonl`. The JSON report includes `trace_path`. The trace contains ordered stage transitions and model/tool call timing and status, with input/output payloads omitted by default to avoid recording prompts, credentials, or sensitive exploit data. This is an execution audit trail, **not** a deterministic replay engine.

## Real CVE acceptance test

CI includes an opt-in real Docker test for Apache HTTP Server CVE-2021-41773 using the retained Vulhub Dockerfile. It tests read-only local file disclosure (no RCE), independent HTTP evidence, cleanup, and trace persistence. The test constructs an ephemeral, hash-bound policy for its dedicated loopback lab only; this is not a general-purpose approval or a shipped `policies/local.json`. Run locally with `VULNFORGE_REAL_CVE_E2E=1 python -m pytest -q tests/test_real_cve_e2e.py`. The normal CLI happy path still requires a separately reviewed reproduction specification and policy.
