# Metasploit and Docker Deployment Architecture

> Status: **partially implemented**. The read-only RPC Discovery and Target Compatibility MVPs exist. The container deployment boundary, Docker network isolation, Check/Exploit integration, and production deployment remain design proposals or future work.

## 1. Decision

VulnForge does **not** need Docker-in-Docker (DinD) merely because Metasploit runs in a container.

The recommended initial topology is:

- VulnForge runs as an application container.
- Metasploit Framework runs as a separate, dedicated container and exposes its RPC API only on a private management network.
- Vulnerable targets run in separate lab containers/networks.
- A trusted Docker control boundary manages lab lifecycle on the host Docker Engine (or a separately provisioned remote Engine).
- Metasploit does not receive the Docker socket and does not manage Docker containers itself.

This separates orchestration, exploit tooling, and vulnerable targets. It also avoids adding a second Docker daemon before there is a concrete need for one.

## 2. Logical topology

```text
                         Host / Lab Infrastructure
+-------------------------------------------------------------------+
|                                                                   |
|  +--------------------+       Management Network                 |
|  | VulnForge          | <----------------------------------+      |
|  | LangGraph /        |                                    |      |
|  | Planner / Executor |                         +----------v---+  |
|  +---------+----------+                         | Metasploit   |  |
|            |                                    | RPC service  |  |
|            |                                    | (no Docker   |  |
|            |                                    |  socket)     |  |
|            |                                    +------+-------+  |
|            |                                           |          |
|            |             Controlled Attack Network    |          |
|            |                                    +------v-------+  |
|            +---- Docker control boundary ------>| Lab targets  |  |
|                  (host Engine / gateway)         | Vulhub       |  |
|                                                  +--------------+  |
|                                                                   |
+-------------------------------------------------------------------+
```

The diagram is logical, not a requirement that every component share one Docker network. In particular, the Metasploit RPC management interface and its target-facing attack interface must be separated.

### Network planes

| Plane | Members | Purpose | Rule |
| --- | --- | --- | --- |
| Management | VulnForge ↔ Metasploit RPC | Authentication, discovery, module inspection, approved control requests | Never publish RPC to the public Internet |
| Attack | Metasploit ↔ selected lab target(s) | Reach only the explicitly selected target services | Per-run allowlist; no broad route into management services |
| Target/internal | Vulnerable service and its required dependencies | Target application traffic | No implicit access to management plane or Internet |
| Provisioning/egress (optional) | Trusted image/build infrastructure | Pull approved images and dependencies | Separate from exploit-time target connectivity |

Do not attach every service to one shared bridge network. A multi-homed Metasploit service may join the management network for RPC and a narrowly scoped attack network for the current lab. The target must not gain a route back to the management network.

## 3. Docker Engine ownership

The host Docker Engine owns container lifecycle. VulnForge's Executor requests only the operations needed to create, inspect, start, stop, and remove an approved lab.

Metasploit is an RPC-controlled tool service. It does not need Docker Engine access to scan or exploit a target reachable over the attack network.

### Preferred initial approach

Use the existing host Engine through a trusted Docker control boundary:

1. Keep Docker control credentials/socket out of the Metasploit container.
2. If VulnForge itself talks to the Engine, treat that connection as a high-privilege capability: Docker socket access is effectively host-level control.
3. Prefer a narrowly configured Docker API gateway/socket proxy or a separate remote Engine endpoint protected by mutual TLS, exposing only the required lifecycle operations.
4. Validate every requested image, Compose project, mount, port binding, network attachment, and cleanup operation in Python before it reaches the Engine.
5. Do not expose an unauthenticated Docker TCP endpoint.

A socket proxy is defense-in-depth, not a complete sandbox. Its allowed API surface must be reviewed and tested; access to Docker create/exec/mount capabilities can still be highly dangerous.

### Why not DinD initially?

DinD introduces a second daemon, extra storage/network complexity, daemon lifecycle and cleanup concerns, and often requires privileged container capabilities. It is useful when a job genuinely needs its own isolated Docker daemon or nested build environment, but Metasploit RPC does not create that requirement.

Revisit DinD only if VulnForge needs per-run daemon isolation that cannot be achieved with a dedicated remote Engine or disposable VM. Do not run the Metasploit service as a privileged DinD host.

## 4. Metasploit RPC boundary

VulnForge communicates with Metasploit over an authenticated RPC client. The client belongs under `app/integrations/metasploit/` and should expose narrow typed operations rather than a generic arbitrary-method interface.

Proposed responsibilities:

- `client.py`: transport, TLS verification, request serialization, response parsing, timeouts.
- `auth.py`: login/token lifecycle and secret retrieval.
- `discovery.py`: CVE/module candidate search.
- `module_inspector.py`: module metadata, supported targets, required/optional options, check capability and side-effect metadata.
- `models.py`: `PoCCandidate`, module metadata and normalized discovery results.

The adapter should initially implement read-only discovery and inspection. Add check and exploit execution as separate capabilities only after their authorization contracts and integration tests exist.

### RPC security requirements

- Bind RPC to a private interface and private network; do not publish it publicly.
- Use TLS with certificate verification across host boundaries. Do not disable verification to make development easier.
- Store credentials in environment-injected secrets or a secret manager; never place them in prompts, reports, source control, or tool output.
- Restrict which VulnForge service identity can reach RPC.
- Use explicit connection/read timeouts, bounded retries, structured error handling, and token expiry handling.
- Do not expose unrestricted `msfconsole`, arbitrary RPC method names, arbitrary module names, or raw option dictionaries to an LLM.
- Pin the Metasploit image/version (prefer an immutable image digest) and record the version in each run report.
- Treat module metadata, descriptions, references, output, sessions, and target responses as untrusted data.

Metasploit RPC is a powerful control interface. A container boundary alone does not make it safe; compromise of the RPC service may enable code execution in the Metasploit container. Keep that container unprivileged, without host mounts or Docker socket access, and with minimal capabilities and filesystem access.

## 5. VulnForge workflow integration

The intended flow is:

1. **Research** identifies the CVE and gathers source-backed target/environment information.
2. **PoC Discovery** queries Metasploit and secondary existing-PoC sources.
3. **Candidate Normalization** emits a `PoCCandidate` with module identity, CVE references, provenance, target/version constraints, required options, check support and known side effects.
4. **Compatibility Assessment** compares the candidate with the reviewed `TargetSpec` and `ReproductionSpec`. A CVE search hit is not proof of compatibility or exploitability.
5. **Policy Authorization** binds the approved candidate, target, backend, operation, exact option set, network scope, timeouts and resource limits.
6. **Planning** includes the selected backend operation in the canonical `ExecutionPlan`.
7. **Execution** calls a narrow Metasploit adapter operation. It does not invoke arbitrary console commands.
8. **Verification** independently checks observed evidence. A module return value or claimed session alone is not proof of successful reproduction.
9. **Cleanup** terminates approved jobs/sessions and removes lab resources, recording cleanup outcomes.

The Agent may propose a candidate and parameters. Deterministic Python code must validate the candidate identity, target binding, parameter schema, authorization, and budget before any side effect.

## 6. Capability rollout

| Phase | Capability | Acceptance criteria |
| --- | --- | --- |
| 0 | Deployment and RPC health check | Private RPC connectivity, TLS/auth checks, version reporting, no public exposure |
| 1 | Read-only CVE/module discovery | **Implemented MVP:** RPC login, CVE search, normalized candidates, module info/options inspection; fake-client unit tests. Live RPC smoke test remains pending |
| 2 | Module inspection and option preparation | **Implemented MVP:** inspect metadata/options, preserve defaults, fill explicit target host/port, report missing required options; automatic Docker endpoint resolution remains pending |
| 3 | Policy-gated check | Explicit target/option authorization, timeout, side-effect documentation, auditable output |
| 4 | Policy-gated exploit execution | Explicit approval, isolated attack network, controlled payload/session lifecycle, evidence verification and cleanup |
| 5 | Isolation hardening | Security tests for cross-network reachability, egress restrictions, credential exposure and Docker API permissions |

Do not make Metasploit a mandatory dependency for all runs until the adapter and deployment boundary are implemented and tested. A run may use an approved secondary PoC backend when no suitable Metasploit module exists.

## 7. Required configuration (illustrative)

Use deployment secrets rather than committing credentials:

```dotenv
METASPLOIT_RPC_URL=https://metasploit-rpc.internal:55553/api/
METASPLOIT_RPC_USERNAME=vulnforge
METASPLOIT_RPC_PASSWORD=<injected-secret>
METASPLOIT_RPC_CA_BUNDLE=/run/secrets/metasploit-rpc-ca.pem
```

The exact URL path, TLS termination, and RPC listener configuration must match the selected Metasploit Framework version and deployment. Do not assume a host port mapping is necessary for containers on the same private network.

## 8. Security and operational acceptance checklist

- [ ] Metasploit has no Docker socket, host Docker credentials, privileged mode, or unnecessary host mounts.
- [ ] RPC is reachable only from the VulnForge management identity/network.
- [ ] RPC credentials and tokens never enter model context, logs, traces, reports, or Git.
- [ ] TLS certificate verification is enabled for cross-host RPC.
- [ ] The attack network reaches only the approved target and required ports.
- [ ] Targets cannot reach the management network or arbitrary external destinations.
- [ ] Docker Engine access is isolated behind a reviewed, narrow control boundary.
- [ ] Docker API is never exposed as unauthenticated TCP.
- [ ] Image pulls/builds use a separately controlled provisioning/egress path.
- [ ] Candidate discovery cannot trigger check/exploit execution.
- [ ] Check/exploit operations require explicit policy approval and bounded budgets.
- [ ] Session/job termination and lab cleanup are tested, including failure paths.
- [ ] Reports record module identity, framework version, approved options (with secrets redacted), target binding, timestamps, evidence and cleanup status.

## 9. Explicit non-goals for the first integration slice

- No DinD requirement.
- No unrestricted `msfconsole` command tool for the Agent.
- No automatic exploit execution immediately after CVE discovery.
- No Metasploit Docker socket mount.
- No claim that Docker egress isolation or Metasploit RPC integration is already implemented.
- No assumption that a module mentioning a CVE is compatible with every target version.

## 10. Related architecture

This deployment proposal complements [Architecture v2](architecture-v2.md). The implementation should follow the existing principle: Agents propose; domain policy and deterministic Python code authorize and execute.


## 11. Current implementation progress\n\nThe first read-only Discovery MVP is now present in `app/integrations/metasploit/`: RPC client, CVE discovery, normalized candidate/metadata models, CLI search command, and focused fake-client tests. See [Metasploit Discovery MVP](metasploit-discovery-mvp.md) for setup and usage. A live RPC smoke test and LangGraph integration are still pending.\n\n## 12. Implementation philosophy: incremental MVP first

**Working principle: implement a small, runnable slice first; improve hardening and completeness after the functionality works. Avoid designing the entire platform before the first end-to-end integration exists.**

The Metasploit integration must be delivered in small, verifiable increments:

1. Connect to a running local/private RPC endpoint and confirm authentication.
2. Search modules by CVE and return a usable candidate list.
3. Inspect one candidate and return its metadata and options.
4. Add a basic compatibility assessment against a selected target.
5. Add a real, controlled module check.
6. Only then consider policy-gated exploit execution and session lifecycle.

Each increment should have a runnable example and focused tests. Once that slice works, update the relevant Markdown documentation and push the code and documentation together. Do not block a working feature on unrelated production-hardening work.

### What to keep simple in the first MVP

- Use the existing Metasploit RPC authentication flow; implement only the token handling needed for the current client.
- Use a straightforward Python HTTP + MessagePack client and a small number of typed methods.
- Start with a local/private development endpoint. Add CA-bundle configuration and cross-host TLS deployment details when the deployment requires them.
- Keep errors understandable and avoid leaking passwords or tokens, but defer elaborate secret-management and token-refresh infrastructure.
- Return the fields needed by the next VulnForge stage; do not attempt to normalize every possible Metasploit module field.
- Keep discovery read-only. Do not add generic arbitrary-RPC access to the Agent.

### Minimum safety baseline (not a reason to over-engineer)

- Do not commit RPC credentials.
- Do not expose the RPC listener to the public Internet.
- Do not give the Metasploit container the Docker socket.
- Do not let CVE discovery automatically trigger a check or exploit.
- Keep check/exploit as explicit later capabilities.

These are baseline guardrails. Broader TLS deployment, network segmentation automation, Docker API proxy hardening, detailed audit schemas, and exhaustive security testing can be handled in later iterations when the corresponding capability is being implemented.

### Delivery rule

At the end of each meaningful implementation increment:

- Run the focused unit tests and any relevant existing tests.
- Record exactly what works, what was tested, and what remains incomplete.
- Update this document (or the relevant implementation guide).
- Commit and push the code and Markdown together.
- Do not claim future phases are implemented.

The goal is continuous working software, not a large design-only milestone.


## Current delivery: Target Compatibility MVP

The next incremental slice adds evidence-based compatibility assessment in `app/integrations/metasploit/compatibility.py` and the `metasploit-assess` CLI action. It inspects discovered candidates and compares explicit CVE references, product identity, affected-version evidence, and remote host/port option availability against a reviewed reproduction spec. Results are `compatible`, `partial`, `incompatible`, or `unknown`, with matched signals, unknowns, mismatches, and a suggested next step.

This remains read-only. It does not call Metasploit Check or execute modules. The assessment deliberately avoids treating Metasploit rank or a CVE search hit as proof of target compatibility. See [Metasploit Discovery MVP](metasploit-discovery-mvp.md).



## Current delivery: Option Preparation MVP

A small option preparation helper is implemented in `app/integrations/metasploit/options.py`, with a `metasploit-prepare` CLI action. It inspects the first CVE search result by default, preserves module defaults, fills only declared target host/port options from an explicitly supplied reachable host and the reviewed reproduction port, and reports any remaining required options. It does not guess container IP addresses or execute modules. See [Metasploit Discovery MVP](metasploit-discovery-mvp.md) for the command and Python API.
