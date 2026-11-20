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


## Researcher and Planner integration (second milestone)

Metasploit discovery is opt-in in the primary CLI workflow:

```bash
python -m app.cli CVE-2021-44228 --action research --discover-metasploit
python -m app.cli CVE-2021-44228 --action plan --policy-file policies/local.json --discover-metasploit
python -m app.cli CVE-2021-44228 --action run --policy-file policies/local.json --discover-metasploit
```

When enabled, the Researcher adds up to 10 inspected candidates to its bundle. Provider errors fail the research stage rather than being silently represented as an empty result. When disabled, existing workflows do not require Metasploit to be installed.

The Planner receives compact candidate metadata and may propose one candidate for human review. Deterministic checks require that the candidate:
- is present in the Researcher bundle;
- is an inspected Metasploit `exploit` module (not an auxiliary scanner);
- explicitly references the target CVE.

The selected candidate ID and rationale are recorded in the canonical `ExecutionPlan`. The candidate list's SHA-256 fingerprint is also included in `input_fingerprints`, and is revalidated before deployment. Raw module excerpts are excluded from the Planner prompt to keep the context bounded, but remain in the Researcher report for audit.

This selection is **not** a compatibility determination or execution authorization. Product/version compatibility remains unverified unless separately grounded. The selected candidate is not executed; the existing fixed reproduction lifecycle is unchanged. If no LLM is configured, candidates are surfaced for manual review and no automatic selection is made.


## Execution proposal and compatibility gate (third milestone)

The domain now defines `PoCExecutionSpec` and `CompatibilityAssessment` in `app/domain/poc_execution.py`.

A proposal binds one inspected Metasploit exploit to:
- the exact target ID and target fingerprint;
- the CVE independently present in module metadata;
- a loopback target host and a port declared by the selected lab environment;
- known module options, with `RHOSTS` and `RPORT` derived from the bound target;
- the inspected module metadata SHA-256.

The compatibility gate rejects non-Metasploit/non-exploit candidates, uninspected modules, missing or mismatched module CVE references, non-loopback destinations, undeclared ports, unknown option names, caller overrides of `RHOSTS`/`RPORT`, and missing required options.

**Compatibility remains `unknown` unless independent product/version evidence exists.** Metasploit's target labels and rank are retained as metadata, but are not treated as proof that the module supports the lab's product/version.

The spec always carries `approval_required=true`. This milestone only constructs and validates a review proposal; it does not invoke `check`, `exploit`, RPC, payloads, or sessions. Execution remains blocked until a separately authorized RPC adapter and explicit policy gate are implemented.


## Policy-gated RPC adapter (fourth milestone)

The optional `app/execution/metasploit_rpc.py` adapter uses Metasploit's HTTP MessagePack RPC API. Install the optional dependency with:

```bash
pip install -e ".[metasploit]"
```

Start the Metasploit Framework RPC daemon bound to loopback, for example:

```bash
msfrpcd -U vulnforge -P '<strong-password>' -a 127.0.0.1 -p 55553 -S -f
```

Configure credentials through environment variables (never commit them):

- `MSFRPC_HOST=127.0.0.1`
- `MSFRPC_PORT=55553`
- `MSFRPC_SSL=true`
- `MSFRPC_URI=/api/`
- `MSFRPC_USER`
- `MSFRPC_PASS`

The adapter exposes no arbitrary console/RPC passthrough. It only supports the named flow:
1. `module.check` on an inspected exploit with Check support;
2. wait for the module result and require the exact `vulnerable` result code;
3. `module.execute` only when the same adapter instance has recorded that successful check;
4. inspect newly created sessions and stop only sessions matching the exact target host and exploit module.

The RPC endpoint itself must be loopback. TLS certificate verification is enabled by default. The transport accepts no non-loopback RPC host.

### Additional explicit policy fields

All Metasploit permissions default to disabled. A reviewed policy must include the exact candidate ID and inspected metadata SHA-256 in `approved_poc_candidates`, then explicitly enable the required flags:

- `allow_metasploit_check`
- `allow_metasploit_execute`
- `allow_unknown_poc_compatibility` (only if the reviewer accepts unknown product/version compatibility)
- `allow_metasploit_payloads` (only when a reviewed module requires a payload option)

The active policy must also approve the target fingerprint, loopback host, and published port. A changed module metadata hash invalidates candidate approval.

### Current limitations

This adapter is not yet wired into LangGraph's Executor or CLI. Its RPC and policy behavior is unit-tested with a fake client; no live Metasploit daemon/module has been exercised by CI. Automatic candidate fallback and end-to-end verifier/report integration are the next milestones.
