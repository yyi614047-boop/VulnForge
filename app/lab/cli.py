"""Core CLI for knowledge retrieval and local lab runs."""
import argparse
import json
from pathlib import Path
from uuid import uuid4

from app.lab.pipeline import Pipeline
from app.rag.index import RetrievalIndex
from app.rag.providers import ConfiguredEmbeddings, configured_model
from app.rag.researcher import Researcher
from app.tools.docker_engine import DockerEngine


def main():
    """解析命令行参数并分派检索、规划或实验运行命令。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["engine", "index", "search", "research", "plan", "run", "inspect"])
    parser.add_argument("query", nargs="?", default="", help="Search text, knowledge card ID, or report path")
    parser.add_argument("--knowledge", type=Path, default=Path("knowledge"))
    parser.add_argument("--workspace", type=Path, default=Path(".labs"))
    parser.add_argument("--project")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--engine", choices=["langgraph", "sequential"], default="langgraph")
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--engine-timeout", type=int, default=120, choices=range(1, 301), metavar="SECONDS")
    parser.add_argument("--check-only", action="store_true", help="Check Docker without starting it")
    parser.add_argument("--fixed-port", action="store_true")
    parser.add_argument("--index", type=Path)
    parser.add_argument("--dense", action="store_true", help="Enable hybrid retrieval")
    parser.add_argument("--model", action="store_true", help="Use a model for research and planning")
    parser.add_argument("--top-k", type=int, default=6)
    parser.add_argument("--card-id")
    parser.add_argument("--product")
    parser.add_argument("--version")
    args = parser.parse_args()

    try:
        if args.action == "engine":
            result = DockerEngine().registry().call("ensure_docker_engine", {
                "start": not args.check_only, "timeout": args.engine_timeout})
            print(json.dumps(result.evidence, ensure_ascii=False, indent=2))
            if not result.evidence["ready"]:
                raise SystemExit(1)
            return
        if args.action == "inspect":
            print(json.dumps(json.loads(Path(args.query).read_text(encoding="utf-8")), ensure_ascii=False, indent=2))
            return

        embedder = ConfiguredEmbeddings() if args.dense else None
        llm = configured_model() if args.model else None
        index_path = args.index or args.workspace / "rag.sqlite"
        if args.action in {"index", "search", "research"}:
            index = RetrievalIndex(args.knowledge, index_path, embedder)
            if args.action == "index":
                result = index.build()
            elif args.action == "search":
                index.build()
                result = index.search(args.query, top_k=args.top_k, card_id=args.card_id,
                                      product=args.product, version=args.version)
            else:
                result = Researcher(index, llm).research(args.query)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return

        project = args.project or f"lab-{uuid4().hex[:12]}"
        workflow = Pipeline(args.knowledge, args.workspace, project, retries=args.retries,
                            timeout=args.timeout, keep=args.keep, index_path=index_path,
                            embedder=embedder, llm=llm, docker_engine=DockerEngine(),
                            engine_timeout=args.engine_timeout, auto_port=not args.fixed_port)
        if args.action == "plan":
            state = {"identifier": args.query}
            state.update(workflow.research(state))
            state.update(workflow.plan(state))
            print(json.dumps(state, ensure_ascii=False, indent=2))
            if state["status"] != "planned":
                raise SystemExit(1)
            return

        path = args.report or Path("reports") / f"{project}.json"
        report = workflow.run(args.query, path, engine=args.engine)
        print(json.dumps({"status": report["status"], "cleanup": report.get("cleanup"),
                          "report": str(path.resolve())}, ensure_ascii=False, indent=2))
        if report["status"] != "success" or report.get("cleanup") == "failed":
            raise SystemExit(1)
    except ImportError as exc:
        parser.exit(2, f"Missing dependency: {exc}. Install the project or use --engine sequential.\n")
    except (ValueError, OSError) as exc:
        parser.exit(2, f"{exc}\n")


if __name__ == "__main__":
    main()
