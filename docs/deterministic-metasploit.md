# Markdown-first deterministic reproduction

## Primary inputs

The primary CLI reads the original Vulhub environment at
`knowledge/vulhub/<product>/<CVE>/`. The environment's Docker Compose file and
Markdown documents remain the source of truth. The workflow does not require
`knowledge/evaluation-cards/`.

## LLM boundary

The only LLM call in the primary `plan` / `run` path is
`source_planner` in `VulhubRun.plan()`. It translates documented steps into
the `SourcePlan` schema. Each operation must cite an exact quote from one of
the source Markdown files. Planning does not decide whether the vulnerability
was reproduced.

After planning, execution is deterministic:

1. Snapshot the selected Vulhub environment and rewrite published ports to
   loopback-only bindings.
2. Start the Docker Compose project.
3. Execute the validated operations in their listed order.
4. Search Metasploit for modules tagged with the CVE.
5. Run each candidate module's native `check` method against the local mapped
   port and classify explicit Check outcomes.
6. Save the report and clean up the Compose project.

No LLM is called during steps 2–6. A failed documented step is recorded and
stops subsequent documented steps; it is not repaired by an LLM.

## Metasploit result semantics

The first implementation deliberately runs **native Metasploit Check methods
only**. It does not execute an exploit payload. This is a conservative
verification stage, not a claim that every Metasploit module provides a
non-destructive check or that Check is equivalent to successful exploitation.

| Metasploit outcome | VulnForge outcome |
| --- | --- |
| Explicit `CheckCode::Vulnerable` | `success` (vulnerability confirmed by Check) |
| All candidate modules explicitly report safe | `not_reproduced` |
| No CVE-tagged module or all checks unsupported | `unsupported` |
| Detected, unknown, timeout, malformed or mixed evidence | `inconclusive` |

The report includes `verification_method=metasploit_native_check`,
`verification_type=native_check_only` and
`exploit_payload_executed=false`. Do not interpret `success` here as an
exploit payload having run.

The Metasploit adapter rejects non-loopback targets and invokes `msfconsole`
without a shell. The primary workflow targets the published loopback port of
the local Docker lab only.

## Dependencies and limitations

- Install Metasploit Framework and ensure `msfconsole` is on `PATH`.
- Docker Engine and Docker Compose v2 are required for lab execution.
- A CVE must have a searchable Metasploit module and a useful native Check
  implementation to receive a definitive result.
- Some modules need additional target options or have no Check implementation;
  these remain unsupported or inconclusive rather than being guessed by an LLM.
- The current verifier selects the first documented reproduction HTTP target.
  Multi-service CVEs may need an explicit target-to-module mapping in a later
  iteration.
- The full test suite and real Docker/Metasploit integration have not been run
  in this editing environment. Unit tests use fake subprocess results.
