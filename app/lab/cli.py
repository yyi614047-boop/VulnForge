"""Command-line entry point for the staged LangGraph vulnerability Pipeline."""
import argparse
import json
from pathlib import Path
from uuid import uuid4

from app.lab.model_provider import configured_model
from app.lab.pipeline import Pipeline
from app.lab.planning import StructuredPlanner
from app.lab.research import Researcher
from app.tools.docker_engine import DockerEngine


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("identifier", nargs="?", help="Trusted knowledge-card identifier")
    parser.add_argument("--action", choices=["engine", "research", "plan", "run", "inspect"], default="run")
    parser.add_argument("--knowledge", type=Path, default=Path("knowledge/cards"),
                        help="Directory containing reviewed executable YAML knowledge cards")
    parser.add_argument("--workspace", type=Path, default=Path(".labs"))
    parser.add_argument("--project")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--engine-timeout", type=int, default=120, choices=range(1, 301), metavar="SECONDS")
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--fixed-port", action="store_true")
    parser.add_argument("--inspect", type=Path, help="Existing JSON report to inspect")
    return parser


def main():
    parser = _parser()
    args = parser.parse_args()
    if args.action == "inspect":
        path = args.inspect or (Path(args.identifier) if args.identifier else None)
        if path is None:
            parser.error("--action inspect requires a report path")
        print(json.dumps(json.loads(path.read_text(encoding="utf-8")), ensure_ascii=False, indent=2))
        return
    if args.action == "engine":
        result = DockerEngine().registry().call("ensure_docker_engine", {
            "start": not args.check_only, "timeout": args.engine_timeout})
        print(json.dumps(result.evidence, ensure_ascii=False, indent=2))
        if not result.evidence["ready"]:
            raise SystemExit(1)
        return
    if not args.identifier:
        parser.error("provide a trusted knowledge-card identifier")
    try:
        model = configured_model()
        if args.action == "research":
            result = Researcher(args.knowledge, model).research(args.identifier)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return
        if args.action == "plan":
            bundle = Researcher(args.knowledge, model).research(args.identifier)
            plan = StructuredPlanner(model).generate(
                bundle, retries=args.retries, timeout=args.timeout, keep=args.keep)
            print(json.dumps(plan.model_dump(), ensure_ascii=False, indent=2))
            return
        project = args.project or f"lab-{uuid4().hex[:12]}"
        report_path = args.report or Path("reports") / f"{project}.json"
        pipeline = Pipeline(
            args.knowledge, args.workspace, project, llm=model,
            retries=args.retries, timeout=args.timeout, keep=args.keep,
            docker_engine=DockerEngine(), engine_timeout=args.engine_timeout,
            auto_port=not args.fixed_port,
        )
        report = pipeline.run(args.identifier, report_path)
        print(json.dumps({
            "status": report["status"],
            "cleanup": report.get("cleanup"),
            "report": str(report_path.resolve()),
        }, ensure_ascii=False, indent=2))
        if report["status"] != "success" or report.get("cleanup") == "failed":
            raise SystemExit(1)
    except ImportError as exc:
        parser.exit(2, f"Missing dependency: {exc}. Install the project dependencies.\n")
    except (ValueError, OSError) as exc:
        parser.exit(2, f"{exc}\n")


if __name__ == "__main__":
    main()
