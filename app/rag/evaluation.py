"""Retrieval evaluation against explicit source relevance labels."""

from app.rag.researcher import Researcher


def evaluate(index, cases: list[dict], *, top_k=5) -> dict:
    if not cases:
        raise ValueError("Evaluation dataset is empty")
    rows = []
    recalls, reciprocal_ranks, abstentions = [], [], []
    for case in cases:
        result = index.search(case["query"], top_k=top_k)
        ranked = list(dict.fromkeys(hit["source"] for hit in result["hits"]))
        expected = set(case["expected_sources"])
        if expected:
            recall = len(set(ranked) & expected) / len(expected)
            rank = next((i for i, source in enumerate(ranked, 1) if source in expected), None)
            recalls.append(recall)
            reciprocal_ranks.append(1 / rank if rank else 0)
            rows.append({"query": case["query"], "sources": ranked, "recall": recall, "first_relevant_rank": rank})
        else:
            abstentions.append(result["abstained"])
            rows.append({"query": case["query"], "sources": ranked, "correct_abstention": result["abstained"]})
    return {"top_k": top_k, "cases": len(cases),
            "recall_at_k": sum(recalls) / len(recalls) if recalls else None,
            "mrr": sum(reciprocal_ranks) / len(reciprocal_ranks) if reciprocal_ranks else None,
            "abstention_accuracy": sum(abstentions) / len(abstentions) if abstentions else None,
            "details": rows}


def compare_retrieval(lexical_index, candidate_index, cases: list[dict], *, top_k=5) -> dict:
    """Compare a candidate index with BM25 using the same labeled queries."""
    baseline = evaluate(lexical_index, cases, top_k=top_k)
    candidate = evaluate(candidate_index, cases, top_k=top_k)
    metrics = ("recall_at_k", "mrr", "abstention_accuracy")
    deltas = {
        metric: candidate[metric] - baseline[metric]
        for metric in metrics
        if candidate[metric] is not None and baseline[metric] is not None
    }
    return {
        "top_k": top_k,
        "cases": len(cases),
        "baseline": {"mode": "bm25", **baseline},
        "candidate": {"mode": "hybrid", **candidate},
        "delta": deltas,
    }


def evaluate_research(index, llm, cases: list[dict]) -> dict:
    """Measure live research output's cited-evidence integrity, not factual accuracy."""
    if not cases:
        raise ValueError("Research evaluation dataset is empty")

    rows = []
    total_facts = 0
    aligned_facts = 0
    cases_with_facts = 0
    researcher = Researcher(index, llm)
    for case in cases:
        card_id = case.get("card_id")
        expected_sources = case.get("expected_sources")
        if not isinstance(card_id, str) or not card_id.strip():
            raise ValueError("Each research evaluation case requires a card_id")
        if not isinstance(expected_sources, list) or not expected_sources or not all(
            isinstance(source, str) and source for source in expected_sources
        ):
            raise ValueError(f"Research evaluation case {card_id} requires non-empty expected_sources")

        result = researcher.research(card_id)
        source_by_id = {hit["id"]: hit["source"] for hit in result["retrieval"]["hits"]}
        facts = result["synthesis"]["facts"]
        expected = set(expected_sources)
        matched = sum(source_by_id[fact["citation"]] in expected for fact in facts)
        total_facts += len(facts)
        aligned_facts += matched
        cases_with_facts += bool(facts)
        rows.append({
            "card_id": card_id,
            "facts": len(facts),
            "expected_source_facts": matched,
            "expected_source_rate": matched / len(facts) if facts else None,
            "retrieved_sources": sorted({hit["source"] for hit in result["retrieval"]["hits"]}),
            "missing_information": result["synthesis"]["missing_information"],
        })

    return {
        "cases": len(cases),
        "cases_with_facts": cases_with_facts,
        "facts": total_facts,
        "expected_source_fact_rate": aligned_facts / total_facts if total_facts else None,
        "citation_integrity": "passed" if total_facts else "not_tested",
        "citation_integrity_note": "Researcher rejected any citation or quote not present in retrieved evidence.",
        "factual_accuracy": "not_measured",
        "details": rows,
    }
