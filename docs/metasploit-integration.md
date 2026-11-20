# Metasploit integration

## Scope and status

Metasploit is VulnForge's primary source for existing exploit modules. The first integration milestone provides **read-only CVE discovery and module inspection**. It does not execute module checks or exploit payloads, and it is not yet connected to the LangGraph reproduction execution path.

## Components

- `app/domain/poc.py`: typed `PoCCandidate` and `PoCOption` domain contracts.
- `app/discovery/metasploit.py`: deterministic `MetasploitDiscovery` service.
- `app/cli.py`: `metasploit-search` and `metasploit-inspect` commands.
- `tests/test_metasploit_discovery.py`: offline tests using a fake subprocess runner.

## Setup

Install Metasploit Framework separately and ensure `msfconsole` is on `PATH`. VulnForge does not install or bundle the Framework.

## Usage

Search modules referencing a CVE:

```bash
python -m app.cli --action metasploit-search --cve CVE-2021-44228
```

Inspect one module:

```bash
python -m app.cli --action metasploit-inspect --cve CVE-2021-44228 --module exploit/multi/http/log4shell_header_injection
```

Override the executable and timeout when needed:

```bash
python -m app.cli --action metasploit-search --cve CVE-2021-44228 --msfconsole /opt/metasploit-framework/msfconsole --msf-timeout 240
```

## Candidate contract

An inspected module becomes a `PoCCandidate` containing:

- stable candidate ID and source/module identity;
- requested CVE and module type;
- name, description, rank, disclosure date, and references when available;
- target names and parsed module options when exposed by console output;
- explicit check-support metadata only when the output says so;
- bounded raw metadata excerpt and SHA-256 digest.

The parser is intentionally conservative. Missing fields remain empty/unknown; it does not infer supported product versions or check capability from a module name. Raw metadata is retained for later inspection and auditing.

## Safety boundary

- CVE values and module paths are validated before they are inserted into a console command.
- Commands are passed as an argument vector with `shell=False`; arbitrary shell input is not accepted.
- Only `search` and `info` are invoked in this milestone.
- No `check`, `exploit`, `run`, payload, session, or arbitrary console command is exposed.
- Discovery is not authorization. A returned candidate must still be assessed against the approved target and explicit execution policy.
- A search result is not proof that a module supports the target version or can reproduce the CVE.

## Next milestones

1. Connect candidates to the Researcher bundle and let Planner compare existing PoC candidates against the selected target.
2. Add target compatibility checks based on module references, targets, options, and reviewed target facts; unknown compatibility must remain unknown.
3. Implement a dedicated Metasploit RPC transport and policy-gated non-invasive `check` operation where supported.
4. Add exploit execution only after explicit action-level authorization, target binding, timeout/resource limits, output capture, and session cleanup are tested.
5. Feed structured results into the independent Verifier; module success text or a session alone is not sufficient evidence.
