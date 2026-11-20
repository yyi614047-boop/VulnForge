"""Search local Vulhub environments and read their deployment documentation."""
import json
import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from app.tools.registry import ToolOutput, ToolRegistry


class SearchParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=500)
    limit: int = Field(default=6, ge=1, le=50)


class ReadParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    environment: str = Field(min_length=1)


def vulhub_root(root: Path) -> Path:
    nested = root / "vulhub"
    return nested.resolve() if nested.is_dir() else root.resolve()


class VulhubSources:
    def __init__(self, root: Path):
        self.root = vulhub_root(root)

    def environment(self, name):
        path = (self.root / name).resolve()
        if not path.is_relative_to(self.root) or path == self.root:
            raise ValueError("Environment must be inside the knowledge directory")
        if not (path / "docker-compose.yml").is_file():
            raise ValueError("Environment has no docker-compose.yml")
        return path

    def search(self, params: SearchParams):
        terms = params.query.casefold().split()
        cves = re.findall(r"CVE-\d{4}-\d{4,}", params.query, re.I)
        hits = []
        for compose in sorted(self.root.glob("*/*/docker-compose.yml")):
            environment = self.environment(compose.parent.relative_to(self.root).as_posix())
            name = environment.relative_to(self.root).as_posix()
            documents = []
            text = name.casefold()
            for document in sorted(environment.glob("*.md")):
                if not document.resolve().is_relative_to(self.root):
                    raise ValueError("Document is outside the knowledge directory")
                documents.append(document.relative_to(self.root).as_posix())
                text += "\n" + document.read_text(encoding="utf-8").casefold()
            matches = all(term in text or term in name.casefold().replace("/", "-") for term in terms)
            if cves:
                matches = matches and all(re.search(re.escape(cve) + r"(?![0-9])", text, re.I)
                                          for cve in cves)
            if matches:
                hits.append({"environment": name, "compose": compose.relative_to(self.root).as_posix(),
                             "documents": documents})
        hits.sort(key=lambda hit: (not all(term in hit["environment"].casefold() for term in terms),
                                   hit["environment"]))
        evidence = {"query": params.query, "total": len(hits), "hits": hits[:params.limit]}
        return ToolOutput(json.dumps(evidence, ensure_ascii=False), evidence)

    def read(self, params: ReadParams):
        environment = self.environment(params.environment)
        files = [environment / "docker-compose.yml", *sorted(environment.glob("*.md"))]
        documents = []
        for path in files:
            if not path.resolve().is_relative_to(self.root):
                raise ValueError("Source is outside the knowledge directory")
            if path.stat().st_size > 200_000:
                raise ValueError(f"Source exceeds the read budget: {path.name}")
            documents.append({"source": path.relative_to(self.root).as_posix(),
                              "text": path.read_text(encoding="utf-8")})
        evidence = {"environment": environment.relative_to(self.root).as_posix(),
                    "files": documents,
                    "assets": sorted(p.relative_to(environment).as_posix()
                                     for p in environment.rglob("*") if p.is_file())}
        return ToolOutput(json.dumps(evidence, ensure_ascii=False), evidence)

    def registry(self):
        registry = ToolRegistry()
        registry.register("search_vulhub_environments", SearchParams, self.search)
        registry.register("read_vulhub_environment", ReadParams, self.read)
        return registry
