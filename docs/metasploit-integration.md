# Metasploit integration

## Current status

Metasploit discovery, policy-gated RPC, and the Docker-isolated lab integration are implemented. The primary workflow supports two distinct modes:

- **Independent verification (recommended):** run the reproduction first, then call the inspected Metasploit module's non-invasive `check` method. No exploit is executed by this mode.
- **Explicit exploit execution (opt-in):** run `check`, and only after a completed `vulnerable` result, invoke `module.execute`. This is a separate, higher-risk mode and requires its own policy approval.

The live CI fixture is a harmless custom Auxiliary scanner. It validates the real Framework RPC protocol and Docker isolation; it is not a real CVE exploit and does not establish a shell session.

## Components

- `app/discovery/metasploit.py`: CVE search and module inspection through `msfconsole`.
- `app/domain/poc.py`: typed, provenance-aware `PoCCandidate` records.
- `app/domain/poc_execution.py`: target-bound execution specification, compatibility assessment, and Docker network attestation.
- `app/execution/metasploit_rpc.py`: allowlisted MessagePack RPC client, Docker Exec transport, and policy-gated adapter.
- `app/workflows/reproduction/metasploit.py`: candidate validation and check-only / check-then-execute orchestration.
- `app/workflows/reproduction/graph.py`: LangGraph lifecycle and fail-closed stage gates.

## Discovery and inspection

Install the Framework separately; VulnForge does not bundle it. Ensure `msfconsole` is available.

Search and inspect modules for a CVE:

```bash
python -m app.cli --action metasploit-search --cve CVE-2021-44228
python -m app.cli --action metasploit-inspect --cve CVE-2021-44228 \
  --module exploit/multi/http/log4shell_header_injection
```

Discovery is opt-in in the main workflow:

```bash
python -m app.cli CVE-2021-44228 --action research --discover-metasploit
python -m app.cli CVE-2021-44228 --action plan --policy-file policies/local.json --discover-metasploit
```

The Researcher stores inspected candidates and their metadata hashes in its bundle. The Planner may select a candidate for review, but selection is not compatibility proof or execution authorization. Product/version compatibility remains `unknown` unless independently supported by evidence.

## Docker Exec RPC setup

Install the optional dependency:

```bash
python -m pip install -e ".[metasploit]"
```

Run a Metasploit container with its RPC daemon bound only to container loopback. Do not publish port 55553:

```bash
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

The Docker Exec transport forwards bounded MessagePack requests through the Docker daemon to `127.0.0.1:55553` inside the Metasploit container. VulnForge rejects containers with a published RPC port, detaches the container from Docker's default bridge, and attaches it only to the exact approved `internal: true` lab network. It attests that the target and Metasploit containers share only that network before sending module requests.

The alternate HTTP transport is restricted to loopback and verifies TLS certificates by default. Never expose the RPC daemon on `0.0.0.0`.

## Independent verification mode (recommended)

The lifecycle is:

```text
Deploy target
  -> Run reviewed reproduction steps
  -> Metasploit module.check (no exploit execution)
  -> Independent HTTP/evidence verification
  -> Cleanup
```

Run with discovery and check-only verification:

```bash
python -m app.cli TARGET_ID --specs reproductions --action run \
  --policy-file policies/local.json --discover-metasploit \
  --enable-metasploit-verification
```

The selected candidate must be present exactly once in the Researcher bundle, be an inspected Metasploit exploit module, and independently reference the target CVE. The candidate metadata hash, target fingerprint, reproduction fingerprint, and Docker network attestation are revalidated at runtime.

A completed `vulnerable` check allows the independent verifier to run. A `safe` result is reported as `not_reproduced`. Missing candidates, unsupported checks, unknown results, and RPC failures remain `inconclusive` or failed; they are never silently converted into success. Independent HTTP evidence is still collected after an inconclusive or negative Metasploit result, but it cannot override that status.

## Explicit exploit execution mode

Exploit execution is separate from check-only verification:

```bash
python -m app.cli TARGET_ID --specs reproductions --action run \
  --policy-file policies/local.json --discover-metasploit \
  --enable-metasploit-execution
```

All Metasploit permissions default to disabled. A reviewed policy must bind the exact candidate ID to its inspected metadata SHA-256 in `approved_poc_candidates`, approve the target fingerprint and exact internal network, and explicitly enable the required action flags:

- `allow_metasploit_check`
- `allow_metasploit_execute`
- `allow_unknown_poc_compatibility` only when a reviewer explicitly accepts unknown product/version compatibility
- `allow_metasploit_payloads` only when a reviewed module genuinely requires a payload

The adapter exposes an RPC method allowlist, binds `RHOSTS`/`RPORT` to the attested private target endpoint, requires a vulnerable Check from the same adapter instance before Execute, and attempts to stop only sessions created by the selected module for the exact target. Cleanup failures are reported and prevent success.

## Validation

Default CI covers unit tests and real Docker internal-network isolation. The dedicated live Metasploit CI step pulls the Framework image and exercises the real MessagePack RPC login/version path, module Check and Execute calls using a harmless Auxiliary fixture, and independent marker verification. It does not claim real-CVE exploit coverage.

To run the live integration locally:

```bash
VULNFORGE_MSF_INTEGRATION=1 python -m pytest -q tests/test_metasploit_live_integration.py
```

This requires a working Docker daemon and Internet access for image pulls.
