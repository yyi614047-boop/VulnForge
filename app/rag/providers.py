"""Optional provider adapters; importing retrieval needs no network packages."""
import os
import math
from pathlib import Path


class LocalEmbeddings:
    """CPU-friendly local BGE embeddings, with explicit model download/cache."""

    def __init__(self, model):
        from sentence_transformers import SentenceTransformer
        cache = Path(os.environ.get("RAG_MODEL_CACHE", ".cache/embedding-models")).resolve()
        self.client = SentenceTransformer(
            model, device=os.environ.get("RAG_EMBEDDING_DEVICE", "cpu"),
            cache_folder=str(cache), trust_remote_code=False,
            local_files_only=os.environ.get("RAG_LOCAL_FILES_ONLY", "0") == "1",
        )
        self.name = "sentence-transformers:" + model + ":window-mean-v1"

    def _encode(self, texts):
        # Split long chunks by tokenizer offsets so code blocks are not silently truncated.
        tokenizer = self.client.tokenizer
        budget = self.client.max_seq_length - tokenizer.num_special_tokens_to_add(pair=False)
        if budget <= 0:
            raise ValueError("Local model has no usable token budget")
        windows, owners = [], []
        for owner, text in enumerate(texts):
            offsets = tokenizer(text, add_special_tokens=False, return_offsets_mapping=True,
                                truncation=False)["offset_mapping"]
            for start in range(0, len(offsets), budget):
                group = offsets[start:start + budget]
                windows.append(text[group[0][0]:group[-1][1]])
                owners.append(owner)
            if not offsets:
                windows.append(text)
                owners.append(owner)
        if not windows:
            return []
        vectors = self.client.encode(windows, batch_size=16, normalize_embeddings=True,
                                     show_progress_bar=False, convert_to_numpy=True)
        result = []
        for owner in range(len(texts)):
            selected = [v for i, v in zip(owners, vectors) if i == owner]
            vector = [sum(float(x) for x in column) / len(selected) for column in zip(*selected)]
            norm = math.sqrt(sum(x * x for x in vector))
            if not math.isfinite(norm) or norm == 0:
                raise ValueError("Local model returned an invalid vector")
            result.append([x / norm for x in vector])
        return result

    def documents(self, texts):
        return self._encode(texts)

    def query(self, text):
        return self._encode(["为这个句子生成表示以用于检索相关文章：" + text])[0]


class ConfiguredEmbeddings:
    def __init__(self):
        model = os.environ.get("RAG_EMBEDDING_MODEL")
        if not model:
            raise ValueError("Set RAG_EMBEDDING_MODEL to enable vector retrieval")
        provider = os.environ.get("RAG_EMBEDDING_PROVIDER", "openai")
        self.local = None
        if provider == "local":
            self.local = LocalEmbeddings(model)
            self.name = self.local.name
            return
        if provider != "openai":
            raise ValueError("RAG_EMBEDDING_PROVIDER must be local or openai")
        from langchain_openai import OpenAIEmbeddings
        self.name = "openai-compatible:" + model + ":" + os.environ.get("OPENAI_BASE_URL", "default")
        self.client = OpenAIEmbeddings(model=model, request_timeout=30, max_retries=1)

    def documents(self, texts):
        if self.local:
            return self.local.documents(texts)
        return self.client.embed_documents(texts)

    def query(self, text):
        if self.local:
            return self.local.query(text)
        return self.client.embed_query(text)


def configured_model():
    from langchain_openai import ChatOpenAI
    model = os.environ.get("PLANNER_MODEL")
    if not model:
        raise ValueError("Set PLANNER_MODEL before selecting --model")
    return ChatOpenAI(model=model, temperature=0, timeout=60, max_retries=1)
