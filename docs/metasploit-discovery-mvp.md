# Metasploit Discovery MVP

> Status: implemented as a small read-only adapter. A live Metasploit RPC instance is required for an end-to-end smoke test.

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

- Implemented: RPC login, version query, CVE module search, module info, module options.
- Implemented: normalized candidate and metadata models.
- Implemented: fake-client unit tests for search, validation and inspection.
- Not implemented: live RPC integration test, target compatibility scoring, Check, Exploit, Session lifecycle, LangGraph integration.
- Not implemented: production deployment orchestration or container network isolation.

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
- Not implemented: fuzzy product/version matching, target fingerprinting, automated option population, module Check, exploit execution, or LangGraph routing.

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
