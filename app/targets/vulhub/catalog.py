"""Filesystem adapter for reviewed reproduction specifications."""
from hashlib import sha256
from pathlib import Path
import re

import yaml

from app.domain.reproduction import ReproductionSpec
from app.domain.targets import EnvironmentSpec, TargetSource, TargetSpec, VerificationAssertion


class TargetCatalog:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()

    def specs(self):
        for path in sorted(self.root.glob("*.yaml")):
            yield ReproductionSpec.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))

    def get(self, identifier: str) -> ReproductionSpec:
        matches = [spec for spec in self.specs() if spec.id.lower() == identifier.lower()]
        if len(matches) != 1:
            raise ValueError(f"Expected one reproduction spec for {identifier}; found {len(matches)}")
        return matches[0]

    def search(self, query: str) -> list[ReproductionSpec]:
        terms = query.casefold().split()
        return [
            spec for spec in self.specs()
            if all(term in spec.model_dump_json().casefold() for term in terms)
        ]

    def environment(self, spec: ReproductionSpec) -> Path:
        path = (self.root / spec.environment).resolve()
        if not path.is_relative_to(self.root) or not path.is_file():
            raise ValueError("Environment document must exist inside the reproduction catalog")
        return path

    def to_target_spec(self, spec_or_id: ReproductionSpec | str) -> TargetSpec:
        spec = self.get(spec_or_id) if isinstance(spec_or_id, str) else spec_or_id
        compose_path = self.environment(spec)
        compose = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
        services = compose.get("services") or {}
        if not isinstance(services, dict) or not services:
            raise ValueError("Compose file must declare at least one service")

        published_ports = {}
        for service, config in services.items():
            ports = []
            for entry in config.get("ports", []) if isinstance(config, dict) else []:
                if isinstance(entry, str):
                    parts = entry.split("/", 1)[0].split(":")
                    if len(parts) >= 3 and parts[-2].isdigit():
                        if parts[-3] != "127.0.0.1":
                            raise ValueError("Published target ports must bind explicitly to 127.0.0.1")
                        ports.append(int(parts[-2]))
                    elif len(parts) == 2 and parts[-2].isdigit():
                        raise ValueError("Published target ports without an explicit loopback IP are not allowed")
                elif isinstance(entry, dict) and str(entry.get("published", "")).isdigit():
                    if entry.get("host_ip") != "127.0.0.1":
                        raise ValueError("Published target ports must bind explicitly to 127.0.0.1")
                    ports.append(int(entry["published"]))
            if ports:
                published_ports[str(service)] = sorted(set(ports))
        if spec.service not in services or spec.port not in published_ports.get(spec.service, []):
            raise ValueError("Reviewed reproduction service and port must be explicitly published on loopback")

        source_refs = []
        local_sources = {compose_path}
        for source in spec.sources:
            if source.startswith("http://"):
                raise ValueError("Target source URLs must use HTTPS")
            if source.startswith("https://"):
                source_refs.append(TargetSource(source_id=f"source-{len(source_refs)+1}", url=source))
                continue
            path = (self.root / source).resolve()
            if not path.is_relative_to(self.root) or not path.is_file():
                raise ValueError(f"Declared target source is missing or outside catalog: {source}")
            local_sources.add(path)
        for script in [*spec.initialization, *spec.scripts]:
            path = (self.root / script.source).resolve()
            if not path.is_relative_to(self.root) or not path.is_file():
                raise ValueError(f"Script source is missing or outside catalog: {script.source}")
            local_sources.add(path)
        for path in sorted(local_sources):
            relative = path.relative_to(self.root).as_posix()
            media_type = "application/yaml" if path == compose_path else "text/markdown" if path.suffix.lower() == ".md" else "application/octet-stream"
            source_refs.append(TargetSource(
                source_id=f"source-{len(source_refs)+1}", path=relative, media_type=media_type,
                sha256=sha256(path.read_bytes()).hexdigest(),
            ))
        entrypoints = sorted({script.source for script in [*spec.initialization, *spec.scripts]})
        assertions = []
        for probe in spec.verification_requests:
            assertions.append(VerificationAssertion(assertion_id=f"{probe.id.lower()}-status", evidence_kind="http",
                source=f"{probe.path}#status", operator="equals", expected_value=str(probe.expected_status)))
            if probe.body_contains:
                assertions.append(VerificationAssertion(assertion_id=f"{probe.id.lower()}-body", evidence_kind="http",
                    source=f"{probe.path}#body", operator="contains", expected_value=probe.body_contains))
            if probe.log_contains:
                assertions.append(VerificationAssertion(assertion_id=f"{probe.id.lower()}-log", evidence_kind="log",
                    source="compose_logs", operator="contains", expected_value=probe.log_contains))
        for rule in spec.file_evidence:
            assertions.append(VerificationAssertion(assertion_id=rule.id.lower(), evidence_kind="file",
                source=rule.path, operator="contains", expected_value=rule.contains))
        vulnerability = re.search(r"(?:CVE|CNVD)-\d{4}-\d+", spec.id, re.I)

        return TargetSpec(
            target_id=spec.id,
            title=spec.title,
            product=spec.product,
            vulnerability_id=vulnerability.group(0).upper() if vulnerability else None,
            affected_versions=spec.affected_versions,
            sources=source_refs,
            environment=EnvironmentSpec(
                compose_file=compose_path.relative_to(self.root).as_posix(),
                services=sorted(map(str, services)),
                published_ports=published_ports,
                build_required=any(
                    isinstance(value, dict) and "build" in value for value in services.values()
                ),
            ),
            reproduction_entrypoints=entrypoints,
            verification_assertions=assertions,
        )


__all__ = ["TargetCatalog"]
