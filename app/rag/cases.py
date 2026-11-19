"""Search trusted case files and curated summaries of completed local runs."""
import hashlib
import json
import re
from pathlib import Path

from app.rag.index import RetrievalIndex

_SECRET_NAME = re.compile(r"(?:password|passwd|secret|token|credential|api[_-]?key)", re.I)
_SECRET_ASSIGNMENT = re.compile(
    r"(?im)(\b(?:password|passwd|secret|token|credential|api[_-]?key)\b\s*[:=]\s*)"
    r"(['\"]?)[^'\"\s,}]+",
)


def _redact(value, key=""):
    if _SECRET_NAME.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {name: _redact(item, str(name)) for name, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, key) for item in value]
    if isinstance(value, str):
        return _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", value)
    return value


def _safe_compose(compose):
    services = {}
    for name, config in compose.get("services", {}).items():
        service = {}
        for key in ("image", "build", "ports", "healthcheck", "volumes"):
            if key in config:
                service[key] = _redact(config[key], key)
        environment = config.get("environment", {})
        if isinstance(environment, dict):
            service["environment"] = {
                key: ("[REDACTED]" if _SECRET_NAME.search(key) else value)
                for key, value in environment.items()
            }
        elif isinstance(environment, list):
            service["environment"] = [
                item.split("=", 1)[0] + "=[REDACTED]"
                if "=" in item and _SECRET_NAME.search(item.split("=", 1)[0]) else item
                for item in environment
            ]
        services[name] = service
    return {"services": services}


def _case_markdown(report, report_name):
    research = report.get("research")
    plan = report.get("plan")
    if not isinstance(research, dict) or not isinstance(plan, dict):
        return None
    card = research.get("card")
    if not isinstance(card, dict):
        return None

    sections = [
        f"# Completed local reproduction case: {card.get('id', report.get('id', 'unknown'))}",
        f"Report: {report_name}",
        f"Status: {report.get('status')}; cleanup: {report.get('cleanup')}",
        f"Title: {card.get('title', '')}",
        f"Product: {card.get('product', '')}",
        f"Root cause: {card.get('root_cause') or 'Not explicitly recorded'}",
        "Affected versions: " + ", ".join(map(str, card.get("affected_versions", []))),
        "Dependencies: " + ", ".join(map(str, _redact(card.get("dependencies", [])))),
        "Prerequisites: " + ", ".join(map(str, _redact(card.get("prerequisites", [])))),
    ]
    compose = research.get("compose")
    if isinstance(compose, dict):
        sections.extend([
            "## Environment configuration",
            "```json",
            json.dumps(_safe_compose(compose), ensure_ascii=False, sort_keys=True),
            "```",
        ])
    retrieved = research.get("retrieval", {})
    hits = retrieved.get("hits", []) if isinstance(retrieved, dict) else []
    if hits:
        sections.append("## Case background evidence")
        for hit in hits[:12]:
            if isinstance(hit, dict) and isinstance(hit.get("text"), str):
                evidence_text = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", hit["text"][:6000])
                sections.append(f"### {hit.get('source', 'local source')}\n{evidence_text}")
    steps = plan.get("steps", [])
    if steps:
        sections.append("## Planned reproduction and verification steps")
        for number, step in enumerate(steps, 1):
            if isinstance(step, dict):
                sections.append(
                    f"{number}. phase={step.get('phase')}; action={step.get('action')}; "
                    f"probe={step.get('probe_id')}; reason={step.get('reason')}"
                )
    return "\n\n".join(sections) + "\n"


class CaseKnowledge:
    """Read-only retrieval over trusted knowledge and completed experiment reports."""

    def __init__(self, knowledge: Path, history: Path, workspace: Path, embedder=None):
        self.knowledge = Path(knowledge)
        self.history = Path(history)
        self.workspace = Path(workspace)
        if not self.knowledge.is_dir():
            raise FileNotFoundError(f"Knowledge directory does not exist: {self.knowledge}")
        self.embedder = embedder
        self.cache = self.workspace / "case-history"
        self.knowledge_index = RetrievalIndex(
            self.knowledge, self.workspace / "case-knowledge.sqlite", embedder
        )
        self.history_index = RetrievalIndex(
            self.cache, self.workspace / "case-history.sqlite", embedder
        )

    def build(self):
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.cache.mkdir(parents=True, exist_ok=True)
        expected = set()
        errors = []
        if self.history.exists() and not self.history.is_dir():
            errors.append({"report": str(self.history), "error": "History path is not a directory"})
        elif self.history.exists():
            for path in sorted(self.history.rglob("*.json")):
                try:
                    report = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                    errors.append({
                        "report": str(path.relative_to(self.history)),
                        "error": f"{type(exc).__name__}: {exc}",
                    })
                    continue
                if not isinstance(report, dict):
                    errors.append({
                        "report": str(path.relative_to(self.history)),
                        "error": "Report root must be a JSON object",
                    })
                    continue
                if report.get("status") != "success" or report.get("cleanup") not in {
                    "completed", "not_needed",
                }:
                    continue
                document = _case_markdown(report, path.name)
                if document is None:
                    continue
                key = hashlib.sha256(
                    (str(path.resolve()) + "\0" + document).encode("utf-8")
                ).hexdigest()[:24]
                target = self.cache / f"history-{key}.md"
                target.write_text(document, encoding="utf-8")
                expected.add(target.name)
        else:
            errors.append({"report": str(self.history), "error": "History directory does not exist"})
        for cached in self.cache.glob("history-*.md"):
            if cached.name not in expected:
                cached.unlink()
        return {
            "knowledge": self.knowledge_index.build(),
            "history": self.history_index.build(),
            "indexed_history_cases": len(expected),
            "history_errors": errors,
        }

    def search(self, query: str, *, top_k=6):
        if not 1 <= top_k <= 10:
            raise ValueError("top_k must be between 1 and 10")
        build_result = self.build()
        results = [
            ("knowledge", self.knowledge_index.search(query, top_k=top_k)),
            ("history", self.history_index.search(query, top_k=top_k)),
        ]
        ranked = {}
        for corpus, result in results:
            for rank, hit in enumerate(result["hits"], 1):
                key = (corpus, hit["id"])
                entry = ranked.setdefault(key, {**hit, "corpus": corpus, "score": 0.0})
                entry["score"] += 1 / (60 + rank)
        hits = sorted(ranked.values(), key=lambda hit: (-hit["score"], hit["corpus"], hit["id"]))[:top_k]
        return {
            "query": query,
            "hits": hits,
            "abstained": not hits,
            "corpora": [name for name, result in results if result["hits"]],
            "history_errors": build_result["history_errors"],
        }
