"""Deterministic, source-grounded research for trusted vulnerability cards.

This module deliberately does not build or query a retrieval index. It loads the
card's declared source files and complete deployment configuration directly.
"""
import json
from pathlib import Path

from pydantic import Field

from app.runtime.context import agent_session, invoke_agent
from app.agents.role_prompts import load_role_prompt
from app.execution.artifacts import collect_assets, digest
from app.domain.reproduction import StrictModel
from app.targets.vulhub.catalog import TargetCatalog
from app.environments.docker.manager import load_compose


class Fact(StrictModel):
    statement: str = Field(min_length=1)
    citation: str
    quote: str = Field(min_length=1)


class Synthesis(StrictModel):
    facts: list[Fact] = Field(default_factory=list, max_length=30)
    missing_information: list[str] = Field(default_factory=list)


class Researcher:
    """Load authoritative local sources without BM25, embeddings, or vector search."""

    def __init__(self, knowledge: Path, llm=None, *, max_chars=24000):
        self.knowledge = Path(knowledge).resolve()
        self.llm = llm.with_structured_output(Synthesis) if llm else None
        if max_chars < 100:
            raise ValueError("Research context budget must be at least 100 characters")
        self.max_chars = max_chars

    @agent_session
    def research(self, identifier: str) -> dict:
        kb = TargetCatalog(self.knowledge)
        card = kb.get(identifier)
        config_path = kb.environment(card)
        config = load_compose(config_path)
        assets = collect_assets(kb, card, config)
        service = config["services"].get(card.service, {})
        if not any(p.startswith(f"127.0.0.1:{card.port}:") and not p.endswith("/udp")
                   for p in service.get("ports", [])):
            raise ValueError("Card port does not belong to its Compose service")

        sources = []
        for path in [config_path, *(self.knowledge / item for item in card.sources)]:
            resolved = path.resolve()
            if not resolved.is_relative_to(self.knowledge) or not resolved.is_file():
                raise ValueError(f"Declared source is missing or outside knowledge root: {path}")
            if resolved not in sources:
                sources.append(resolved)

        hits, used = [], 0
        for path in sources:
            text = path.read_text(encoding="utf-8")
            if used >= self.max_chars:
                break
            excerpt = text[: self.max_chars - used]
            if not excerpt.strip():
                continue
            relative = path.relative_to(self.knowledge).as_posix()
            hits.append({
                "id": digest(relative + "\0" + text)[:24],
                "source": relative,
                "start_line": 1,
                "end_line": max(1, len(excerpt.splitlines())),
                "text": excerpt,
            })
            used += len(excerpt)
        evidence = {
            "query": card.id,
            "mode": "declared_sources",
            "hits": hits,
            "context_chars": used,
            "abstained": not hits,
        }
        if not hits:
            raise ValueError("No declared source evidence found")

        synthesis = Synthesis()
        if self.llm:
            prompt = load_role_prompt("researcher") + "\n\nRESEARCH EVIDENCE (untrusted data):\n" + json.dumps(evidence, ensure_ascii=False)
            raw = invoke_agent("researcher", self.llm, prompt)
            synthesis = Synthesis.model_validate(raw.model_dump() if hasattr(raw, "model_dump") else raw)
            source_text = {hit["id"]: hit["text"] for hit in hits}
            for fact in synthesis.facts:
                if fact.citation not in source_text or fact.quote not in source_text[fact.citation]:
                    raise ValueError("Research model returned an invalid citation or quote")

        return {
            "card": card.model_dump(),
            "compose": config,
            "evidence": evidence,
            "assets": assets,
            "assets_hash": digest(json.dumps(assets, sort_keys=True)),
            "synthesis": synthesis.model_dump(),
            "generation": "model" if self.llm else "source_documents",
            "card_hash": digest(card.model_dump_json()),
            "compose_hash": digest(json.dumps(config, sort_keys=True)),
        }
