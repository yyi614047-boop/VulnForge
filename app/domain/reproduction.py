"""Typed, reviewed reproduction assertions and execution inputs."""
import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Probe(StrictModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]+$")
    path: str = Field(pattern=r"^/[^\r\n]*$")
    method: Literal["GET", "POST"] = "GET"
    body: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    expected_status: int = Field(default=200, ge=100, le=599)
    body_contains: str | None = Field(default=None, min_length=1)
    log_contains: str | None = Field(default=None, min_length=1)
    retry_safe: bool = False


class Script(StrictModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]+$")
    source: str = Field(min_length=1)
    service: str = Field(min_length=1)
    args: list[str] = Field(default_factory=list, max_length=100)
    environment: dict[str, str] = Field(default_factory=dict)


class FileEvidence(StrictModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]+$")
    service: str
    path: str = Field(pattern=r"^/[^\r\n]*$")
    contains: str = Field(min_length=1)


class VersionProbe(StrictModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]+$")
    service: str
    command: list[str] = Field(min_length=1, max_length=30)
    expected_pattern: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def validate_command(self):
        import re
        try:
            re.compile(self.expected_pattern)
        except re.error as exc:
            raise ValueError("Invalid version pattern") from exc
        if any(not part or "\x00" in part or len(part) > 4096 for part in self.command):
            raise ValueError("Invalid version probe argument")
        return self


class ReproductionSpec(StrictModel):
    """Reviewed reproduction recipe; never an execution authorization policy."""
    id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,199}$")
    title: str = Field(min_length=1)
    product: str = Field(min_length=1)
    root_cause: str | None = Field(default=None, max_length=4000)
    affected_versions: list[str] = Field(min_length=1)
    dependencies: list[str] = Field(min_length=1)
    prerequisites: list[str] = Field(min_length=1)
    sources: list[str] = Field(min_length=1)
    environment: str
    service: str
    port: int = Field(ge=1, le=65535)
    health: Probe
    reproduction: list[Probe] = Field(default_factory=list, max_length=20)
    initialization: list[Script] = Field(default_factory=list, max_length=10)
    scripts: list[Script] = Field(default_factory=list, max_length=10)
    verification_requests: list[Probe] = Field(default_factory=list, max_length=20)
    file_evidence: list[FileEvidence] = Field(default_factory=list, max_length=10)
    version_probes: list[VersionProbe] = Field(default_factory=list, max_length=10)
    purpose: Literal["vulnerability_reproduction", "demo"] = "vulnerability_reproduction"

    def fingerprint(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @model_validator(mode="after")
    def validate_probes(self):
        ids = [probe.id for probe in [self.health, *self.reproduction, *self.initialization, *self.scripts,
                                     *self.verification_requests, *self.file_evidence, *self.version_probes]]
        if len(ids) != len(set(ids)):
            raise ValueError("Probe IDs must be unique")
        if self.health.method != "GET" or self.health.log_contains:
            raise ValueError("Health readiness must use an HTTP GET probe")
        if any(not (p.body_contains or p.log_contains) for p in self.reproduction):
            raise ValueError("Reproduction requires response or log evidence beyond HTTP status")
        if not self.reproduction and not self.scripts:
            raise ValueError("Provide reproduction requests or scripts")
        if self.scripts and not (self.verification_requests or self.file_evidence):
            raise ValueError("Scripts require independent verification requests or target file evidence")
        if any(not (p.body_contains or p.log_contains) for p in self.verification_requests):
            raise ValueError("Verification requests require content or log assertions")
        if any(p.method != "GET" for p in self.verification_requests):
            raise ValueError("Independent verification requests must use GET")
        return self


Card = ReproductionSpec
