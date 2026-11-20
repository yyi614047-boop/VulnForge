"""Prepare explicit Metasploit module options from reviewed target details."""
import ipaddress
import re
from typing import Any

from pydantic import Field

from app.domain.targets import DomainModel
from app.integrations.metasploit.models import ModuleMetadata, PoCCandidate


class PreparedModuleOptions(DomainModel):
    candidate_id: str
    target_host: str
    target_port: int = Field(ge=1, le=65535)
    options: dict[str, Any] = Field(default_factory=dict)
    missing_required: list[str] = Field(default_factory=list)
    ready: bool
    notes: list[str] = Field(default_factory=list)


def _validate_target_host(host: str) -> str:
    host = host.strip()
    if not host or len(host) > 253 or any(char.isspace() for char in host):
        raise ValueError("Target host must be an IP address or hostname")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host):
            raise ValueError("Target host must be an IP address or hostname")
        if ".." in host or any(not label or len(label) > 63 for label in host.split(".")):
            raise ValueError("Invalid target hostname")
        return host


def prepare_module_options(
    candidate: PoCCandidate,
    metadata: ModuleMetadata,
    *,
    target_host: str,
    target_port: int,
    overrides: dict[str, Any] | None = None,
) -> PreparedModuleOptions:
    """Fill target-bound fields and module defaults; report, never guess, missing inputs."""
    host = _validate_target_host(target_host)
    if not 1 <= target_port <= 65535:
        raise ValueError("Target port must be between 1 and 65535")
    if (candidate.module_type, candidate.module_name) != (metadata.module_type, metadata.module_name):
        raise ValueError("Candidate and metadata module identities do not match")

    definitions = {str(key).upper(): value for key, value in metadata.options.items()}
    values: dict[str, Any] = {}
    missing: list[str] = []
    notes: list[str] = []

    # Preserve module defaults first. Do not invent values for required options.
    for name, definition in definitions.items():
        if "default" in definition and definition["default"] is not None:
            values[name] = definition["default"]

    # Bind remote target options to the explicitly supplied target.
    host_options = [name for name in ("RHOSTS", "RHOST") if name in definitions]
    if host_options:
        for name in host_options:
            values[name] = host
    else:
        notes.append("Module metadata exposes no RHOSTS/RHOST option; target binding needs manual review.")

    if "RPORT" in definitions:
        values["RPORT"] = target_port
    elif "RPORTS" in definitions:
        values["RPORTS"] = str(target_port)
    else:
        notes.append("Module metadata exposes no RPORT/RPORTS option; target port was not applied.")

    # Overrides are limited to declared options and cannot change the target binding.
    for raw_name, value in (overrides or {}).items():
        name = str(raw_name).upper()
        if name not in definitions:
            raise ValueError(f"Override is not a declared module option: {name}")
        if name in {"RHOST", "RHOSTS", "RPORT", "RPORTS"}:
            raise ValueError(f"Target-bound option cannot be overridden: {name}")
        values[name] = value

    for name, definition in definitions.items():
        if definition.get("required") and (name not in values or values[name] in (None, "")):
            missing.append(name)

    if not host_options:
        missing.append("RHOSTS/RHOST (target binding)")
    if not ({"RPORT", "RPORTS"} & definitions.keys()):
        missing.append("RPORT/RPORTS (target port binding)")

    missing = sorted(set(missing))
    return PreparedModuleOptions(
        candidate_id=candidate.candidate_id,
        target_host=host,
        target_port=target_port,
        options=values,
        missing_required=missing,
        ready=not missing,
        notes=notes,
    )
