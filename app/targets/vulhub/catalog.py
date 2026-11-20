"""Filesystem adapter for reviewed reproduction specifications."""
from pathlib import Path
import re

import yaml

from app.domain.reproduction import ReproductionSpec
from app.domain.targets import EnvironmentSpec, TargetSource, TargetSpec


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
                    if len(parts) >= 2 and parts[-2].isdigit():
                        ports.append(int(parts[-2]))
                elif isinstance(entry, dict) and str(entry.get("published", "")).isdigit():
                    ports.append(int(entry["published"]))
            if ports:
                published_ports[str(service)] = sorted(set(ports))

        source_refs = []
        for index, source in enumerate(spec.sources):
            if source.startswith("http://"):
                raise ValueError("Target source URLs must use HTTPS")
            if source.startswith("https://"):
                source_refs.append(TargetSource(source_id=f"source-{index+1}", url=source))
            else:
                source_refs.append(TargetSource(source_id=f"source-{index+1}", path=source))
        source_refs.append(TargetSource(
            source_id="compose",
            path=compose_path.relative_to(self.root).as_posix(),
            media_type="application/yaml",
        ))
        entrypoints = sorted({script.source for script in [*spec.initialization, *spec.scripts]})
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
        )


__all__ = ["TargetCatalog"]
