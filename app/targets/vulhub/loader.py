"""Load Vulhub directories as untrusted TargetSpec candidates; never grant execution rights."""
import re
from pathlib import Path
import yaml
from app.domain.targets import EnvironmentSpec, TargetSource, TargetSpec


class VulhubTargetLoader:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise ValueError("Vulhub root must be an existing directory")

    def _environment(self, relative: str) -> Path:
        path = (self.root / relative).resolve()
        if path == self.root or not path.is_relative_to(self.root):
            raise ValueError("Vulhub environment must stay inside the target corpus")
        compose = path / "docker-compose.yml"
        if compose.is_symlink() or not compose.resolve().is_relative_to(self.root) or not compose.is_file():
            raise ValueError("Vulhub environment must contain an in-root regular docker-compose.yml")
        return path

    def search(self, query: str, *, limit: int = 10) -> list[TargetSpec]:
        if not query.strip() or not 1 <= limit <= 50:
            raise ValueError("Provide a query and a limit between 1 and 50")
        terms = query.casefold().split()
        cves = re.findall(r"(?:CVE|CNVD)-\d{4}-\d+", query, re.I)
        results = []
        for compose in sorted(self.root.glob("*/*/docker-compose.yml")):
            env = self._environment(compose.parent.relative_to(self.root).as_posix())
            docs = sorted(env.glob("*.md"))
            searchable_parts = [env.relative_to(self.root).as_posix()]
            for path in docs:
                if path.is_symlink() or not path.resolve().is_relative_to(self.root):
                    raise ValueError("Vulhub documentation must remain inside the target corpus")
                searchable_parts.append(path.read_text(encoding="utf-8"))
            searchable = "\\n".join(searchable_parts).casefold()
            if not all(term in searchable for term in terms):
                continue
            if cves and not all(re.search(re.escape(cve) + r"(?![0-9])", searchable, re.I) for cve in cves):
                continue
            results.append(self.load(env.relative_to(self.root).as_posix()))
            if len(results) >= limit:
                break
        return results

    def load(self, environment: str) -> TargetSpec:
        env = self._environment(environment)
        compose_path = env / "docker-compose.yml"
        config = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
        services = config.get("services") or {}
        if not isinstance(services, dict) or not services:
            raise ValueError("Compose file must declare at least one service")
        ports = {}
        for service, spec in services.items():
            published = []
            for port in spec.get("ports", []) if isinstance(spec, dict) else []:
                if isinstance(port, int):
                    published.append(port)
                elif isinstance(port, str):
                    parts = port.split("/", 1)[0].split(":")
                    candidate = parts[-2] if len(parts) >= 2 else parts[-1]
                    if candidate.isdigit():
                        published.append(int(candidate))
                elif isinstance(port, dict) and str(port.get("published", "")).isdigit():
                    published.append(int(port["published"]))
            if published:
                ports[str(service)] = sorted(set(published))
        docs = sorted(env.glob("*.md"))
        sources = [TargetSource(source_id="compose", path=compose_path.relative_to(self.root).as_posix(), media_type="application/yaml")]
        for index, path in enumerate(docs):
            if path.is_symlink() or not path.resolve().is_relative_to(self.root):
                raise ValueError("Vulhub documentation must remain inside the target corpus")
            sources.append(TargetSource(source_id=f"doc-{index+1}", path=path.relative_to(self.root).as_posix()))
        readme = next((p for p in docs if p.name.lower() == "readme.md"), docs[0] if docs else None)
        title = env.relative_to(self.root).as_posix()
        if readme:
            for line in readme.read_text(encoding="utf-8").splitlines():
                if line.startswith("#"):
                    title = line.lstrip("# ").strip() or title
                    break
        rel = env.relative_to(self.root).as_posix()
        product = rel.split("/", 1)[0]
        vuln_match = re.search(r"(?:CVE|CNVD)-\d{4}-\d+", rel, re.I)
        scripts = []
        for path in env.rglob("*.py"):
            if path.is_symlink() or not path.resolve().is_relative_to(self.root):
                raise ValueError("Vulhub entrypoints must remain inside the target corpus")
            scripts.append(path.relative_to(self.root).as_posix())
        return TargetSpec(
            target_id=rel.replace("/", ":"), title=title, product=product,
            vulnerability_id=vuln_match.group(0).upper() if vuln_match else None,
            sources=sources,
            environment=EnvironmentSpec(compose_file=compose_path.relative_to(self.root).as_posix(),
                                        services=sorted(map(str, services)), published_ports=ports,
                                        build_required=any(isinstance(v, dict) and "build" in v for v in services.values())),
            reproduction_entrypoints=sorted(scripts), status="candidate")
