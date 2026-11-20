"""Core CLI for knowledge retrieval and local lab runs."""
import argparse
import json
import re
from pathlib import Path
from uuid import uuid4

from app.lab.vulhub_run import VulhubRun, source_model
from app.rag.index import RetrievalIndex
from app.rag.providers import ConfiguredEmbeddings
from app.tools.docker_engine import DockerEngine
from app.tools.vulhub_sources import VulhubSources
from app.rag.vulhub_researcher import VulhubResearcher


def main():
    """解析命令行参数并分派检索、规划或实验运行命令。"""
    parser = argparse.ArgumentParser(description=__doc__)
    actions = ["engine", "index", "search", "research", "plan", "run", "inspect"]
    parser.add_argument("subject", nargs="?", help="CVE identifier or legacy action")
    parser.add_argument("query", nargs="?", default="", help="Argument for a legacy action")
    parser.add_argument("--action", choices=actions)
    parser.add_argument("--knowledge", type=Path, default=Path("knowledge"))
    parser.add_argument("--workspace", type=Path, default=Path(".labs"))
    parser.add_argument("--project")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--engine-timeout", type=int, default=120, choices=range(1, 301), metavar="SECONDS")
    parser.add_argument("--check-only", action="store_true", help="Check Docker without starting it")
    parser.add_argument("--fixed-port", action="store_true")
    parser.add_argument("--index", type=Path)
    parser.add_argument("--dense", action="store_true", help="Enable hybrid retrieval")
    parser.add_argument("--top-k", type=int, default=6)
    parser.add_argument("--card-id")
    parser.add_argument("--product")
    parser.add_argument("--version")
    args = parser.parse_args()

    if args.action:
        if args.query:
            parser.error("--action accepts at most one positional argument")
        args.query = args.subject or ""
    elif args.subject in actions:
        args.action = args.subject
    else:
        if args.query or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", args.subject or "", re.I):
            parser.error("enter a CVE identifier or select an action")
        args.action, args.query = "run", args.subject.upper()

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

        if args.action in {"search", "research"}:
            if args.action == "search":
                query = " ".join(filter(None, [args.query, args.product, args.version, args.card_id]))
                result = VulhubSources(args.knowledge).registry().call(
                    "search_vulhub_environments", {"query": query, "limit": args.top_k}).evidence
            else:
                result = VulhubResearcher(args.knowledge).research(args.query)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return

        index_path = args.index or args.workspace / "rag.sqlite"
        if args.action == "index":
            embedder = ConfiguredEmbeddings() if args.dense else None
            index = RetrievalIndex(args.knowledge, index_path, embedder)
            result = index.build()
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return

        project = args.project or f"lab-{uuid4().hex[:12]}"
        workflow = VulhubRun(args.knowledge, args.workspace, project, source_model(), retries=args.retries,
                             timeout=args.timeout, keep=args.keep, docker_engine=DockerEngine(),
                             engine_timeout=args.engine_timeout, auto_port=not args.fixed_port,
                             )
        if args.action == "plan":
            result = workflow.plan(args.query)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            if result["plan"]["missing_information"]:
                raise SystemExit(1)
            return

        path = args.report or Path("reports") / f"{project}.json"
        report = workflow.run(args.query, path)
        print(json.dumps({"status": report["status"], "cleanup": report.get("cleanup"),
                          "report": str(path.resolve()), "trace": report.get("trace")}, ensure_ascii=False, indent=2))
        if report["status"] != "success" or report.get("cleanup") == "failed":
            raise SystemExit(1)
    except ImportError as exc:
        parser.exit(2, f"Missing dependency: {exc}. Install the project dependencies.\n")
    except (ValueError, OSError) as exc:
        parser.exit(2, f"{exc}\n")


if __name__ == "__main__":
    main()
