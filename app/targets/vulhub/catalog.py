"""Filesystem adapter for reviewed, versioned reproduction specifications."""
from pathlib import Path
import yaml
from app.domain.reproduction import ReproductionSpec


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
        return [spec for spec in self.cards()
                if all(term in spec.model_dump_json().casefold() for term in terms)]

    def environment(self, spec: ReproductionSpec) -> Path:
        path = (self.root / spec.environment).resolve()
        if not path.is_relative_to(self.root) or not path.is_file():
            raise ValueError("Environment document must exist inside the target catalog")
        return path


# Transitional alias for the old name; new runtime code uses TargetCatalog.
KnowledgeBase = TargetCatalog
