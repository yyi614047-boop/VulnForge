"""Deterministic authorization contracts; target descriptions never grant permissions."""
from typing import Literal

from pydantic import Field, model_validator

from app.domain.plans import ExecutionAction
from app.domain.reproduction import ReproductionSpec
from app.domain.targets import DomainModel, TargetSpec


class ExecutionPolicy(DomainModel):
    policy_id: str = Field(min_length=1, max_length=128)
    approved_target_hashes: dict[str, str] = Field(min_length=1, max_length=500)
    approved_reproduction_hashes: dict[str, str] = Field(default_factory=dict, max_length=500)
    allowed_actions: set[ExecutionAction] = Field(min_length=1, max_length=32)
    retryable_actions: set[ExecutionAction] = Field(default_factory=set)
    allowed_services: set[str] = Field(min_length=1, max_length=100)
    allowed_ports: set[int] = Field(default_factory=set, max_length=100)
    network_scope: Literal["loopback_only", "explicit_allowlist", "disabled"] = "loopback_only"
    allowed_hosts: set[str] = Field(default_factory=lambda: {"127.0.0.1", "localhost"}, max_length=100)
    max_timeout_seconds: int = Field(default=60, ge=1, le=300)
    max_retries_per_step: int = Field(default=1, ge=0, le=3)
    max_recovery_actions: int = Field(default=1, ge=0, le=5)
    allow_image_build: bool = False
    allow_target_scripts: bool = False
    allow_keep_environment: bool = False
    approved_poc_candidates: dict[str, str] = Field(default_factory=dict, max_length=500)
    allow_metasploit_check: bool = False
    allow_metasploit_execute: bool = False
    allow_unknown_poc_compatibility: bool = False

    @model_validator(mode="after")
    def validate_policy(self):
        if not self.retryable_actions <= self.allowed_actions:
            raise ValueError("Retryable actions must also be explicitly allowed")
        hashes = [*self.approved_target_hashes.values(), *self.approved_reproduction_hashes.values(), *self.approved_poc_candidates.values()]
        if any(len(value) != 64 or any(c not in "0123456789abcdef" for c in value) for value in hashes):
            raise ValueError("Approved target and reproduction bindings must be SHA-256 fingerprints")
        if any(port < 1 or port > 65535 for port in self.allowed_ports):
            raise ValueError("Allowed ports must be valid port numbers")
        if self.network_scope == "loopback_only" and not self.allowed_hosts <= {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("Loopback-only policy cannot allow non-loopback hosts")
        if self.network_scope == "disabled" and self.allowed_hosts:
            raise ValueError("Disabled network policy cannot contain allowed hosts")
        return self

    def authorize_target(self, target: TargetSpec, reproduction_spec: ReproductionSpec | None = None) -> None:
        if self.network_scope != "loopback_only":
            raise PermissionError("This runtime currently supports loopback_only network scope exclusively")
        if "127.0.0.1" not in self.allowed_hosts:
            raise PermissionError("Policy must explicitly allow the runtime loopback probe host")
        if any(source.sha256 is None for source in target.sources):
            raise PermissionError("Every target source must be content-hashed before policy approval")
        expected = self.approved_target_hashes.get(target.target_id)
        if expected is None or expected != target.fingerprint():
            raise PermissionError("Target is not approved or its content differs from the policy fingerprint")
        if reproduction_spec is not None:
            if reproduction_spec.id != target.target_id:
                raise PermissionError("Target and reproduction specification IDs do not match")
            approved = self.approved_reproduction_hashes.get(reproduction_spec.id)
            if approved is None or approved != reproduction_spec.fingerprint():
                raise PermissionError("Reproduction specification is not approved or its content changed")
        if not set(target.environment.services) <= self.allowed_services:
            raise PermissionError("Target declares a service outside the execution policy")
        ports = {port for values in target.environment.published_ports.values() for port in values}
        if not ports <= self.allowed_ports:
            raise PermissionError("Target declares a published port outside the execution policy")
        if target.environment.build_required and not self.allow_image_build:
            raise PermissionError("Target requires an image build disabled by policy")
        if target.reproduction_entrypoints and not self.allow_target_scripts:
            raise PermissionError("Target scripts are disabled by execution policy")

    def authorize_metasploit_candidate(
        self, candidate_id: str, metadata_sha256: str, *, action: Literal["check", "execute"],
        compatibility_status: Literal["compatible", "incompatible", "unknown"],
    ) -> None:
        """Require exact candidate approval and action-specific Metasploit permission."""
        approved_hash = self.approved_poc_candidates.get(candidate_id)
        if approved_hash is None or approved_hash != metadata_sha256:
            raise PermissionError("Metasploit candidate is not explicitly approved or its metadata changed")
        if action == "check" and not self.allow_metasploit_check:
            raise PermissionError("Metasploit module checks are disabled by execution policy")
        if action == "execute" and not self.allow_metasploit_execute:
            raise PermissionError("Metasploit exploit execution is disabled by execution policy")
        if compatibility_status == "incompatible":
            raise PermissionError("Metasploit candidate is incompatible with the selected target")
        if action == "execute" and compatibility_status == "unknown" and not self.allow_unknown_poc_compatibility:
            raise PermissionError("Unknown product/version compatibility requires explicit policy approval")

    def authorize_action(self, action: str, *, timeout_seconds: int, retries: int = 0) -> None:
        if action not in self.allowed_actions:
            raise PermissionError(f"Action {action!r} is not allowed")
        if retries and action not in self.retryable_actions:
            raise PermissionError("This action is not approved for retry")
        if not 1 <= timeout_seconds <= self.max_timeout_seconds:
            raise PermissionError("Action timeout exceeds execution policy")
        if not 0 <= retries <= self.max_retries_per_step:
            raise PermissionError("Action retry count exceeds execution policy")
        if action == "build" and not self.allow_image_build:
            raise PermissionError("Image builds are disabled by execution policy")
        if action in {"stage_artifacts", "initialize", "script"} and not self.allow_target_scripts:
            raise PermissionError("Target scripts and artifact staging are disabled by execution policy")
        if action == "keep" and not self.allow_keep_environment:
            raise PermissionError("Keeping the environment is disabled by execution policy")
