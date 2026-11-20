"""Target descriptions are untrusted evidence-bearing data, never execution permissions."""
import hashlib
import json
from pathlib import PurePosixPath, PureWindowsPath
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator


def _validate_relative_path(value: str) -> None:
    normalized = value.replace(chr(92), "/")
    if PurePosixPath(normalized).is_absolute() or PureWindowsPath(value).is_absolute() or ".." in PurePosixPath(normalized).parts:
        raise ValueError("Path must be relative and cannot traverse directories")


class DomainModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class TargetSource(DomainModel):
    source_id: str = Field(min_length=1, max_length=128)
    path: str | None = Field(default=None, max_length=512)
    url: HttpUrl | None = None
    media_type: str = Field(default="text/markdown", max_length=100)
    sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def require_location(self):
        if bool(self.path) == bool(self.url):
            raise ValueError("A source must have exactly one of path or URL")
        if self.path:
            _validate_relative_path(self.path)
        if self.url and self.url.scheme != "https":
            raise ValueError("Remote target sources must use HTTPS")
        return self


class EnvironmentSpec(DomainModel):
    kind: Literal["docker_compose"] = "docker_compose"
    compose_file: str = Field(min_length=1, max_length=512)
    services: list[str] = Field(default_factory=list, max_length=100)
    published_ports: dict[str, list[int]] = Field(default_factory=dict)
    build_required: bool = False

    @model_validator(mode="after")
    def validate_environment(self):
        _validate_relative_path(self.compose_file)
        if any(port < 1 or port > 65535 for ports in self.published_ports.values() for port in ports):
            raise ValueError("Published ports must be valid TCP/UDP port numbers")
        if not set(self.published_ports) <= set(self.services):
            raise ValueError("Published ports must belong to declared services")
        if len(self.services) != len(set(self.services)):
            raise ValueError("Environment service names must be unique")
        return self


class TargetSpec(DomainModel):
    schema_version: Literal[1] = 1
    target_id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,199}$")
    title: str = Field(min_length=1, max_length=500)
    product: str = Field(min_length=1, max_length=200)
    vulnerability_id: str | None = Field(default=None, pattern=r"^(CVE-\d{4}-\d{4,}|CNVD-\d{4}-\d+)$")
    affected_versions: list[str] = Field(default_factory=list, max_length=100)
    sources: list[TargetSource] = Field(min_length=1, max_length=100)
    environment: EnvironmentSpec
    reproduction_entrypoints: list[str] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def validate_entrypoints(self):
        if len(self.reproduction_entrypoints) != len(set(self.reproduction_entrypoints)):
            raise ValueError("Reproduction entrypoints must be unique")
        for path in self.reproduction_entrypoints:
            _validate_relative_path(path)
        source_ids = [source.source_id for source in self.sources]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("Target source IDs must be unique")
        return self

    def fingerprint(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
