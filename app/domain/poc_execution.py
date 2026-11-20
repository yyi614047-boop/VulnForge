"""Execution contracts for running existing Metasploit modules against approved lab targets.

These contracts describe a proposed invocation. They do not execute modules
or grant authorization; the active ExecutionPolicy and an explicit approval
step remain mandatory at the execution boundary.
"""
from __future__ import annotations

import ipaddress
import hashlib
import json
from typing import Literal

from pydantic import Field, model_validator

from app.domain.poc import PoCCandidate
from app.domain.targets import DomainModel, TargetSpec


class CompatibilityAssessment(DomainModel):
    candidate_id: str = Field(min_length=1, max_length=256)
    target_id: str = Field(min_length=1, max_length=200)
    status: Literal["compatible", "incompatible", "unknown"]
    blockers: list[str] = Field(default_factory=list, max_length=30)
    unknowns: list[str] = Field(default_factory=list, max_length=30)
    checked_fields: list[str] = Field(default_factory=list, max_length=30)


class LabNetworkAttestation(DomainModel):
    """Runtime evidence binding a target endpoint to one internal Docker network."""
    project: str = Field(pattern=r"^lab-[a-z0-9][a-z0-9_-]{0,48}$")
    service: str = Field(min_length=1, max_length=64)
    compose_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_container_id: str = Field(min_length=12, max_length=128)
    target_host: str = Field(min_length=7, max_length=45)
    target_port: int = Field(ge=1, le=65535)
    published_host_port: int = Field(ge=1, le=65535)
    network_name: str = Field(min_length=1, max_length=128)
    network_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    network_internal: Literal[True] = True
    target_networks: list[str] = Field(min_length=1, max_length=8)
    metasploit_container_id: str = Field(min_length=12, max_length=128)
    metasploit_host: str = Field(min_length=7, max_length=45)
    metasploit_networks: list[str] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def validate_isolated_network(self):
        for value, label in ((self.target_host, "target"), (self.metasploit_host, "Metasploit")):
            address = ipaddress.ip_address(value)
            if address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local:
                raise ValueError(f"{label} endpoint must be a private, non-loopback IPv4 address")
        if self.target_networks != [self.network_name] or self.metasploit_networks != [self.network_name]:
            raise ValueError("Both containers must be attached only to the attested internal network")
        if self.target_container_id == self.metasploit_container_id:
            raise ValueError("Target and Metasploit must be separate containers")
        return self

    def fingerprint(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

class PoCExecutionSpec(DomainModel):
    """A concrete, target-bound invocation proposal for one existing module."""

    schema_version: Literal[1] = 1
    backend: Literal["metasploit"] = "metasploit"
    candidate_id: str = Field(min_length=1, max_length=256)
    module_path: str = Field(pattern=r"^exploit/[A-Za-z0-9_./-]+$", max_length=512)
    module_metadata_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_id: str = Field(min_length=1, max_length=200)
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_attestation: LabNetworkAttestation | None = None
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    target_host: str = Field(min_length=1, max_length=253)
    target_port: int = Field(ge=1, le=65535)
    options: dict[str, str] = Field(default_factory=dict, max_length=100)
    compatibility_status: Literal["compatible", "incompatible", "unknown"] = "unknown"
    approval_required: Literal[True] = True

    @model_validator(mode="after")
    def validate_options(self):
        parts = self.module_path.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise ValueError("Metasploit module path cannot contain empty or traversal segments")
        if any(not key or len(key) > 128 or not key.replace("_", "").isalnum() for key in self.options):
            raise ValueError("Metasploit option names must be simple identifiers")
        if any(len(value) > 4000 for value in self.options.values()):
            raise ValueError("Metasploit option values exceed the supported length")
        if self.target_attestation is not None and (
            self.target_host != self.target_attestation.target_host
            or self.target_port != self.target_attestation.target_port
        ):
            raise ValueError("Execution target endpoint must match the Docker network attestation")
        return self


def assess_metasploit_compatibility(
    candidate: PoCCandidate,
    target: TargetSpec,
    *,
    target_host: str = "127.0.0.1",
    target_port: int,
    target_attestation: LabNetworkAttestation | None = None,
    supplied_options: dict[str, str] | None = None,
) -> CompatibilityAssessment:
    """Check deterministic prerequisites without guessing product/version compatibility."""
    blockers: list[str] = []
    unknowns: list[str] = []
    checked: list[str] = []

    if candidate.source != "metasploit" or candidate.module_type != "exploit":
        blockers.append("Candidate is not a Metasploit exploit module.")
    if not candidate.inspected:
        blockers.append("Module metadata has not been inspected.")
    if not target.vulnerability_id:
        blockers.append("Target has no declared CVE identifier.")
    elif target.vulnerability_id.upper() not in {value.upper() for value in candidate.cve_ids}:
        blockers.append("Inspected module metadata does not independently reference the target CVE.")
    else:
        checked.append("module_metadata_cve_reference")

    if target_attestation is None:
        try:
            address = ipaddress.ip_address(target_host)
            if not address.is_loopback:
                blockers.append("Without Docker attestation, V1 permits loopback targets only.")
        except ValueError:
            if target_host != "localhost":
                blockers.append("Without Docker attestation, target host must be localhost or loopback.")
        if target_port not in {port for ports in target.environment.published_ports.values() for port in ports}:
            blockers.append("Target port is not declared in the selected target environment.")
    else:
        target_host = target_attestation.target_host
        if target_port != target_attestation.target_port:
            blockers.append("Target port does not match the Docker network attestation.")
        if target_attestation.published_host_port not in {
            port for ports in target.environment.published_ports.values() for port in ports
        }:
            blockers.append("Attested published host port is not declared by the selected target environment.")
    checked.append("target_endpoint_attestation")

    known_options = {option.name: option for option in candidate.options}
    supplied = supplied_options or {}
    unknown_names = set(supplied) - set(known_options)
    if unknown_names:
        blockers.append("Unknown module options supplied: " + ", ".join(sorted(unknown_names)))
    checked.append("module_option_names")

    effective = dict(supplied)
    # Network destination is always derived from the approved TargetSpec input,
    # never accepted as an arbitrary free-form module option.
    if "RHOSTS" in known_options:
        if "RHOSTS" in supplied:
            blockers.append("RHOSTS must be derived from the bound target, not supplied independently.")
        effective["RHOSTS"] = target_host
    if "RPORT" in known_options:
        if "RPORT" in supplied:
            blockers.append("RPORT must be derived from the bound target, not supplied independently.")
        effective["RPORT"] = str(target_port)

    missing = [
        option.name for option in candidate.options
        if option.required and not (effective.get(option.name) or option.current_value)
    ]
    if missing:
        blockers.append("Required module options are missing: " + ", ".join(sorted(missing)))
    checked.append("required_module_options")

    # Metasploit Targets labels are not reliable product/version evidence.
    # Do not infer compatibility from module names or the Rank field.
    unknowns.append("Product and affected-version compatibility has not been independently established.")
    if candidate.targets:
        unknowns.append("Metasploit target labels were recorded but not mapped to the lab product/version.")
    checked.append("product_version_compatibility")

    return CompatibilityAssessment(
        candidate_id=candidate.candidate_id,
        target_id=target.target_id,
        status="incompatible" if blockers else "unknown",
        blockers=blockers,
        unknowns=unknowns,
        checked_fields=checked,
    )


def build_poc_execution_spec(
    candidate: PoCCandidate,
    target: TargetSpec,
    *,
    target_host: str = "127.0.0.1",
    target_port: int,
    target_attestation: LabNetworkAttestation | None = None,
    supplied_options: dict[str, str] | None = None,
) -> tuple[PoCExecutionSpec, CompatibilityAssessment]:
    """Build a review-only invocation proposal after deterministic prerequisite checks."""
    if target_attestation is not None:
        target_host = target_attestation.target_host
        target_port = target_attestation.target_port
    assessment = assess_metasploit_compatibility(
        candidate, target, target_host=target_host, target_port=target_port,
        target_attestation=target_attestation, supplied_options=supplied_options,
    )
    if assessment.blockers:
        raise ValueError("PoC execution spec rejected: " + " ".join(assessment.blockers))

    options = dict(supplied_options or {})
    available = {option.name: option for option in candidate.options}
    if "RHOSTS" in available:
        options["RHOSTS"] = target_host
    if "RPORT" in available:
        options["RPORT"] = str(target_port)
    for option in candidate.options:
        if option.required and option.name not in options and option.current_value:
            options[option.name] = option.current_value

    spec = PoCExecutionSpec(
        candidate_id=candidate.candidate_id,
        module_path=candidate.module_path,
        module_metadata_sha256=candidate.metadata_sha256,
        target_id=target.target_id,
        target_fingerprint=target.fingerprint(),
        target_attestation=target_attestation,
        cve_id=target.vulnerability_id,
        target_host=target_host,
        target_port=target_port,
        options=options,
        compatibility_status=assessment.status,
    )
    return spec, assessment


class MetasploitCheckOutcome(DomainModel):
    candidate_id: str
    module_metadata_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_id: str
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    job_uuid: str = Field(min_length=1, max_length=128)
    status: Literal["completed", "failed"]
    result_code: Literal["vulnerable", "safe", "detected", "appears", "unknown", "not_vulnerable", "unsupported"] = "unknown"
    result: dict = Field(default_factory=dict, max_length=100)


class MetasploitExecutionOutcome(DomainModel):
    candidate_id: str
    target_id: str
    job_uuid: str = Field(min_length=1, max_length=128)
    status: Literal["completed", "failed"]
    result: dict = Field(default_factory=dict, max_length=100)
    cleaned_session_ids: list[int] = Field(default_factory=list, max_length=100)
