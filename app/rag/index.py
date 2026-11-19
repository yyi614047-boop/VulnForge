"""Persistent local retrieval: Markdown-aware chunks, BM25, dense search and RRF.

Embeddings are optional real provider vectors, never synthetic semantic scores.
SQLite transactions keep an old index usable if indexing or embedding fails.
"""
import hashlib
import json
import math
import re
import sqlite3
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from app.lab.knowledge import Card, KnowledgeBase


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def tokens(text: str) -> list[str]:
    words = re.findall(r"[a-z0-9]+(?:[-_.][a-z0-9]+)*", text.lower())
    for phrase in re.findall(r"[\u4e00-\u9fff]+", text):
        words.extend(phrase)
        words.extend(phrase[i:i + 2] for i in range(len(phrase) - 1))
    return words


class Embedder(Protocol):
    name: str
    def documents(self, texts: list[str]) -> list[list[float]]: ...
    def query(self, text: str) -> list[float]: ...


class Chunk(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    source: str
    start_line: int
    end_line: int
    heading: str
    text: str
    card_ids: list[str]
    products: list[str]
    versions: list[str]


def split_document(source: str, text: str, cards: list[Card], size=1800) -> list[Chunk]:
    """Keep fences intact; split prose on line boundaries with heading metadata."""
    chunks, buffer = [], []
    heading, start, fenced = "", 1, False
    def flush():
        if not buffer or not "".join(buffer).strip():
            return
        body = "".join(buffer)
        chunks.append(Chunk(id=digest(f"{source}:{start}:{body}")[:24], source=source,
                            start_line=start, end_line=start + len(buffer) - 1,
                            heading=heading, text=body,
                            card_ids=[c.id for c in cards], products=[c.product for c in cards],
                            versions=sorted({v for c in cards for v in c.affected_versions})))
    for number, line in enumerate(text.splitlines(keepends=True), 1):
        if not fenced and buffer and (line.startswith("#") or sum(map(len, buffer)) >= size):
            flush()
            buffer = []
        if not buffer:
            start = number
        if not fenced and line.startswith("#"):
            heading = line.lstrip("#").strip()
        if line.strip().startswith("```"):
            fenced = not fenced
        buffer.append(line)
    flush()
    return chunks


def validate_vectors(vectors, count):
    if len(vectors) != count or not vectors:
        raise ValueError("Embedding count mismatch")
    dimension = len(vectors[0])
    if not dimension or any(len(v) != dimension or not all(math.isfinite(x) for x in v)
                            or not any(v) for v in vectors):
        raise ValueError("Embeddings must be finite, nonzero, and have one dimension")


class RetrievalIndex:
    def __init__(self, root: Path, database: Path, embedder: Embedder | None = None):
        self.root, self.database, self.embedder = root.resolve(), database, embedder
        database.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS documents (path TEXT PRIMARY KEY, hash TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS chunks (id TEXT PRIMARY KEY, path TEXT NOT NULL, payload TEXT NOT NULL, vector TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            previous = db.execute("SELECT value FROM metadata WHERE key='root'").fetchone()
            if previous and previous[0] != str(self.root):
                raise ValueError("Index belongs to another knowledge root")
            db.execute("INSERT OR IGNORE INTO metadata VALUES ('root', ?)", (str(self.root),))

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database, timeout=30)
        try:
            with db:
                yield db
        finally:
            db.close()

    def build(self) -> dict:
        kb = KnowledgeBase(self.root)
        cards = list(kb.cards())
        if len({c.id.casefold() for c in cards}) != len(cards):
            raise ValueError("Duplicate knowledge-card IDs")
        associations = {}
        for card in cards:
            environment = kb.environment(card)
            for source in [str(environment.relative_to(self.root)), *card.sources]:
                path = (self.root / source).resolve()
                if path.is_relative_to(self.root) and path.is_file():
                    associations.setdefault(path.relative_to(self.root).as_posix(), {})[card.id] = card
        paths = sorted(p for p in self.root.rglob("*") if (p.suffix.lower() in {".md", ".yaml", ".yml", ".json", ".txt", ".py"}
                       or p.name == "Dockerfile") and p.is_file())
        mode = self.embedder.name if self.embedder else "lexical"
        changed = removed = 0
        with self.connect() as db:
            old_mode = db.execute("SELECT value FROM metadata WHERE key='embedding'").fetchone()
            rebuild = not old_mode or old_mode[0] != mode
            existing = dict(db.execute("SELECT path, hash FROM documents"))
            seen = set()
            for path in paths:
                if not path.resolve().is_relative_to(self.root):
                    raise ValueError("Knowledge symlink escapes root")
                relative = path.relative_to(self.root).as_posix()
                seen.add(relative)
                text = path.read_text(encoding="utf-8")
                linked = list(associations.get(relative, {}).values())
                if path.parent == self.root and path.suffix == ".yaml":
                    import yaml
                    linked = [Card.model_validate(yaml.safe_load(text))]
                fingerprint = digest(text + json.dumps([c.model_dump() for c in linked], sort_keys=True) + "chunk-v1")
                if not rebuild and existing.get(relative) == fingerprint:
                    continue
                chunks = split_document(relative, text, linked)
                vectors = None
                if self.embedder and chunks:
                    vectors = self.embedder.documents([c.heading + "\n" + c.text for c in chunks])
                    validate_vectors(vectors, len(chunks))
                db.execute("DELETE FROM chunks WHERE path=?", (relative,))
                for i, chunk in enumerate(chunks):
                    db.execute("INSERT INTO chunks VALUES (?, ?, ?, ?)",
                               (chunk.id, relative, chunk.model_dump_json(), json.dumps(vectors[i]) if vectors else None))
                db.execute("INSERT OR REPLACE INTO documents VALUES (?, ?)", (relative, fingerprint))
                changed += 1
            for missing in existing.keys() - seen:
                db.execute("DELETE FROM chunks WHERE path=?", (missing,))
                db.execute("DELETE FROM documents WHERE path=?", (missing,))
                removed += 1
            if self.embedder:
                dimensions = {len(json.loads(row[0])) for row in db.execute("SELECT vector FROM chunks WHERE vector IS NOT NULL")}
                if len(dimensions) > 1:
                    raise ValueError("Embedding dimensions changed within this index")
            db.execute("INSERT OR REPLACE INTO metadata VALUES ('embedding', ?)", (mode,))
            count = db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        return {"changed_documents": changed, "removed_documents": removed, "chunks": count, "mode": mode}

    def search(self, query: str, *, top_k=6, card_id=None, product=None, version=None, max_chars=14000) -> dict:
        if not query.strip() or not 1 <= top_k <= 30 or max_chars < 100:
            raise ValueError("Provide a query, top_k 1..30, and context budget >=100")
        with self.connect() as db:
            rows = db.execute("SELECT payload, vector FROM chunks ORDER BY id").fetchall()
            mode = db.execute("SELECT value FROM metadata WHERE key='embedding'").fetchone()
        entries = [(Chunk.model_validate_json(payload), json.loads(vector) if vector else None) for payload, vector in rows]
        entries = [(c, v) for c, v in entries if (not card_id or card_id.casefold() in [i.casefold() for i in c.card_ids])
                   and (not product or product.casefold() in [p.casefold() for p in c.products])
                   and (not version or version in c.versions)]
        counts = [Counter(tokens(c.heading + "\n" + c.text)) for c, _ in entries]
        lengths = [sum(c.values()) for c in counts]
        average = sum(lengths) / max(len(lengths), 1) or 1
        query_terms = set(tokens(query))
        df = Counter(term for count in counts for term in count)
        lexical = []
        for i, count in enumerate(counts):
            score = 0.0
            for term in query_terms:
                tf = count[term]
                idf = math.log(1 + (len(counts) - df[term] + .5) / (df[term] + .5))
                score += idf * tf * 2.2 / (tf + 1.2 * (.25 + .75 * lengths[i] / average))
            if query.casefold() in [s.casefold() for s in entries[i][0].card_ids]:
                score += 10
            if score > 0:
                lexical.append((i, score))
        lexical.sort(key=lambda item: (-item[1], item[0]))
        dense = []
        if self.embedder:
            if not mode or mode[0] != self.embedder.name:
                raise ValueError("Embedding model changed: rebuild the index")
            qv = self.embedder.query(query)
            validate_vectors([qv], 1)
            for i, (_, vector) in enumerate(entries):
                if vector is None or len(vector) != len(qv):
                    raise ValueError("Index vector dimension mismatch: rebuild index")
                score = sum(a*b for a,b in zip(qv, vector)) / (math.sqrt(sum(a*a for a in qv)) * math.sqrt(sum(b*b for b in vector)))
                if score >= .25:
                    dense.append((i, score))
            dense.sort(key=lambda item: (-item[1], item[0]))
        fused = Counter()
        for ranking in [lexical[:60], dense[:60]]:
            for rank, (i, _) in enumerate(ranking, 1):
                fused[i] += 1 / (60 + rank)
        hits, used, texts = [], 0, set()
        for i, score in sorted(fused.items(), key=lambda item: (-item[1], item[0])):
            chunk = entries[i][0]
            if chunk.text in texts or used + len(chunk.text) > max_chars:
                continue
            hits.append({**chunk.model_dump(), "score": score,
                         "lexical_score": dict(lexical).get(i, 0), "dense_score": dict(dense).get(i)})
            texts.add(chunk.text)
            used += len(chunk.text)
            if len(hits) == top_k:
                break
        return {"query": query, "mode": "hybrid" if self.embedder else "bm25", "hits": hits,
                "context_chars": used, "abstained": not hits}
