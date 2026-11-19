"""Run a reproducible BM25 versus real local embedding simulation."""
import argparse
import json
import time
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from uuid import uuid4

from app.rag.evaluation import compare_retrieval
from app.rag.index import RetrievalIndex
from app.rag.providers import ConfiguredEmbeddings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--knowledge', type=Path, default=Path('knowledge'))
    parser.add_argument('--cases', type=Path, default=Path('examples/retrieval_cases.json'))
    parser.add_argument('--top-k', type=int, default=5)
    parser.add_argument('--download-only', action='store_true')
    args = parser.parse_args()
    started = time.perf_counter()
    embedder = ConfiguredEmbeddings()
    if args.download_only:
        print(json.dumps({'model': embedder.name, 'dimension': len(embedder.query('test'))}))
        return
    cases = json.loads(args.cases.read_text(encoding='utf-8'))
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid4().hex[:8]
    workspace = Path('.labs/embedding-experiments') / run_id
    lexical = RetrievalIndex(args.knowledge, workspace / 'bm25.sqlite')
    dense = RetrievalIndex(args.knowledge, workspace / 'hybrid.sqlite', embedder)
    builds = {'bm25': lexical.build(), 'hybrid': dense.build()}
    cached = dense.build()
    if cached['changed_documents'] != 0:
        raise RuntimeError('Unchanged documents were unexpectedly reindexed')
    result = compare_retrieval(lexical, dense, cases, top_k=args.top_k)
    result.update(
        status='completed', embedding_model=embedder.name,
        knowledge=str(args.knowledge.resolve()), cases_file=str(args.cases.resolve()),
        builds=builds, cached_build=cached, elapsed_seconds=time.perf_counter() - started,
        packages={name: version(name) for name in ('sentence-transformers', 'torch', 'transformers')},
        limitation='Synthetic demonstration cases only; not a real vulnerability retrieval benchmark.',
    )
    workspace.mkdir(parents=True, exist_ok=True)
    # Keep the exact evaluation inputs alongside the indexes.
    (workspace / 'cases.json').write_text(json.dumps(cases, ensure_ascii=False, indent=2), encoding='utf-8')
    report = Path('reports/embedding') / (run_id + '.json')
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'report': str(report.resolve()), 'baseline': result['baseline'],
                      'candidate': result['candidate'], 'delta': result['delta']}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
