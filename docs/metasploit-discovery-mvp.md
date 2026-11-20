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
