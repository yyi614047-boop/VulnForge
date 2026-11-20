# Metasploit Discovery MVP

> Status: Discovery is read-only; a separate explicitly approved check-only adapter is implemented. A live Metasploit RPC instance and running Docker lab are required for an end-to-end smoke test.

## Install

```bash
pip install -e '.[metasploit]'
```

## Configure a local/private RPC endpoint

```bash
export METASPLOIT_RPC_URL='http://127.0.0.1:55553/api/'
export METASPLOIT_RPC_USERNAME='msf'
export METASPLOIT_RPC_PASSWORD='your-local-password'
```

Use HTTPS when connecting across hosts. Do not commit credentials.

## Search modules by CVE

```bash
vulnforge --action metasploit-search --cve CVE-2021-44228
```

The command logs in, calls Metasploit `module.search`, filters module types, and prints normalized `PoCCandidate` JSON. It does not execute modules.

## Use from Python

```python
import os
from app.integrations.metasploit import MetasploitRPCClient, MetasploitDiscovery

client = MetasploitRPCClient(
    os.environ["METASPLOIT_RPC_URL"],
    os.environ["METASPLOIT_RPC_USERNAME"],
    os.environ["METASPLOIT_RPC_PASSWORD"],
)
try:
    discovery = MetasploitDiscovery(client)
    candidates = discovery.search_cve("CVE-2021-44228")
    for candidate in candidates:
        print(candidate.model_dump(mode="json"))

    if candidates:
        metadata = discovery.inspect(candidates[0])
        print(metadata.model_dump(mode="json"))
finally:
    client.close()
```

## Current scope

- Implemented: RPC login, version query, CVE module search, module info/options, module.check and module.results.
- Implemented: normalized candidate and metadata models, compatibility assessment, and option preparation.
- Implemented: fake-client tests for discovery, option preparation, and approved check result polling.
- Implemented: Docker private endpoint resolution and shared-network membership checks for a running target and Metasploit container.
- Not implemented: live RPC integration test, exploit execution, session lifecycle, LangGraph integration, automated network provisioning/isolation, or production deployment.

Module descriptions and options are untrusted external data. Discovery output is a candidate list, not proof that a module applies to a target or permission to run it.


## Target compatibility assessment

Compare every discovered candidate with a reviewed reproduction specification:

```bash
vulnforge --action metasploit-assess CVE-2021-44228-log4j
```

The positional identifier is the reproduction-spec ID. The command loads its TargetSpec and ReproductionSpec, searches Metasploit for the target CVE (or accepts `--cve` explicitly), inspects each returned module, and prints a compatibility assessment.

Optional flags:

```bash
vulnforge --action metasploit-assess CVE-2021-44228-log4j --candidate-limit 10
vulnforge --action metasploit-assess CVE-2021-44228-log4j --cve CVE-2021-44228
```

Assessment statuses:

- `compatible`: explicit CVE, product, and affected-version evidence align.
- `partial`: some evidence aligns, but one or more important signals are unknown.
- `incompatible`: explicit module CVE references conflict with the target CVE.
- `unknown`: there is not enough evidence to assess the candidate.

This is intentionally conservative. Metasploit module rank is not target compatibility. A CVE search hit is not proof that the module applies to a target. Module metadata often omits affected product versions, so a result may remain `partial`; that is preferable to inventing certainty. The command is read-only and does not invoke module check or exploit execution.

## Current compatibility MVP scope

- Implemented: explicit CVE-reference comparison, product-name signal, affected-version text signal, and remote-host/port option presence.
- Implemented: per-candidate explanations, matched/unknown/mismatch signals, and next-step guidance.
- Implemented: CLI assessment against a reviewed reproduction spec.
- Not implemented: fuzzy product/version matching, target fingerprinting, exploit execution, or LangGraph routing.

## Option Preparation MVP

Prepare the first Metasploit candidate's target-bound options without executing the module:

```bash
vulnforge --action metasploit-prepare CVE-2021-44228-log4j \
  --target-host 127.0.0.1
```

The command uses the reproduction spec's reviewed service port by default. Override it only when the lab's actual reachable port differs:

```bash
vulnforge --action metasploit-prepare CVE-2021-44228-log4j \
  --target-host 127.0.0.1 --target-port 8080
```

The command searches the CVE, inspects the first result (default candidate limit is one), preserves declared module defaults, fills declared `RHOSTS`/`RHOST` and `RPORT`/`RPORTS` from the explicit target host/port, and reports missing required options. Optional non-target values can be supplied through the Python API's `overrides` argument, but only for options declared by the module. Target host/port fields cannot be overridden.

Python API:

```python
from app.integrations.metasploit import prepare_module_options

prepared = prepare_module_options(
    candidate,
    metadata,
    target_host="127.0.0.1",
    target_port=8080,
)
print(prepared.model_dump(mode="json"))
```

The result includes `ready`, `options`, `missing_required`, and `notes`. `ready=True` means only that required options are populated; it is not an exploitability verdict or execution authorization.

This MVP requires an explicit reachable target host. It does not guess container IPs, start labs, call Module Check, execute an exploit, create sessions, or verify a vulnerability. A future integration can resolve the target endpoint from the Docker lab runtime and pass it to this pure preparation function.


## Docker target resolution and approved check-only execution

The next slice resolves the private endpoint of one already-running lab service and adds a narrowly scoped Metasploit module.check adapter. It does not execute an exploit.

### 1. Attach Metasploit to the lab's dedicated attack network

The Metasploit container must already be running, have its RPC management connection configured separately, and be attached to the selected lab network. The target service must also be on that network. Use a dedicated network for the lab; do not attach Metasploit to an unrelated shared application network.

For example, if the Compose project network is lab-demo_default:

\`\`\`bash
docker network connect lab-demo_default metasploit
\`\`\`

The command below verifies that both containers are running and attached to the exact same network. It only resolves an address from that selected network and requires the target's reviewed published TCP port to bind to 127.0.0.1.

### 2. Resolve the container endpoint

\`\`\`bash
vulnforge --action docker-target-resolve CVE-2021-44228-log4j \\
  --workspace .labs \\
  --project lab-demo \\
  --metasploit-network lab-demo_default \\
  --metasploit-container metasploit
\`\`\`

The output includes the target's private container IP and internal TCP port. This address is intended for Metasploit on the shared attack network; it is not the host's loopback-published port.

### 3. Prepare module options and review the approval template

\`\`\`bash
vulnforge --action metasploit-prepare CVE-2021-44228-log4j \\
  --target-host 172.20.0.2 \\
  --target-port 8080 \\
  --candidate-limit 20
\`\`\`

Select the exact candidate by its module_type and module_name. The output includes options_sha256 and an approval_template. Copy the template to a local JSON file, replace policy_id with the reviewed approval identifier, and review the module and every option. Do not commit the approval file or sensitive option values.

For additional declared module options, provide a JSON object with --module-options-file to both the prepare and check commands. The options hash must match exactly.

### 4. Run only the approved module check

\`\`\`bash
vulnforge --action metasploit-check CVE-2021-44228-log4j \\
  --project lab-demo \\
  --metasploit-network lab-demo_default \\
  --metasploit-container metasploit \\
  --module-type exploit \\
  --module-name multi/http/example \\
  --approval-file ./local-check-approval.json
\`\`\`

The check command:
- Re-resolves the running target endpoint; it does not trust a host address copied from an earlier run.
- Requires an exact module type/name match in the CVE search results.
- Rebuilds the option set and checks its SHA-256 fingerprint against the approval file.
- Requires the approval to match the target ID, private IP, internal port, candidate ID, and exact options.
- Calls Metasploit module.check and polls module.results within the approved time budget.
- Reports the check code and job result without exposing the option values.

Example approval file shape (replace all example values after reviewing the generated template):

\`\`\`json
{
  "policy_id": "reviewed-local-lab-check-001",
  "candidate_id": "metasploit:exploit:multi/http/example",
  "target_id": "CVE-2021-44228-log4j",
  "target_host": "172.20.0.2",
  "target_port": 8080,
  "options_sha256": "<sha256-from-prepare-output>",
  "max_wait_seconds": 60
}
\`\`\`

### Scope and safety boundary

- Implemented: Docker endpoint resolution for one declared service, one loopback-published TCP port, one explicitly selected private IPv4 network, and verification that the Metasploit container shares that network.
- Implemented: module.check and bounded result polling for explicitly approved exploit and auxiliary modules.
- Implemented: exact approval binding over candidate, target, host, port, and option fingerprint.
- Not implemented: automatic Docker network creation or isolation policy, automatic Metasploit container deployment, LangGraph routing, exploit execution, session management, or post-exploit verification.
- A Metasploit Vulnerable check code is check evidence, not an independent VulnForge reproduction verdict. Appears, Detected, Safe, Unknown, unsupported checks, RPC errors, and timeouts must remain distinguishable.
