"""Command-line entry point for the staged LangGraph vulnerability Pipeline."""
import argparse
import json
import os
from pathlib import Path
from uuid import uuid4

from app.domain.requests import ReproductionRequest
from app.domain.policies import ExecutionPolicy
from app.targets.vulhub.catalog import TargetCatalog
from app.targets.vulhub import VulhubTargetLoader
from app.runtime.models import configured_model
from app.workflows.reproduction.graph import Pipeline
from app.agents.planner import StructuredPlanner
from app.agents.researcher import Researcher
from app.environments.docker.engine import DockerEngine


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("identifier", nargs="?", help="Reviewed reproduction specification identifier")
    parser.add_argument("--action", choices=["engine", "research", "plan", "run", "inspect", "target-search", "target-inspect", "request-validate", "policy-preview", "metasploit-search", "metasploit-assess", "metasploit-prepare", "metasploit-check", "docker-target-resolve"], default="run")
    parser.add_argument("--targets", type=Path, default=Path("targets/vulhub"),
                        help="Root of the retained Vulhub target corpus")
    parser.add_argument("--query", help="Search query for target-search")
    parser.add_argument("--cve", help="CVE identifier for Metasploit module discovery")
    parser.add_argument("--candidate-limit", type=int, default=1, help="Maximum Metasploit candidates to inspect")
    parser.add_argument("--target-host", help="Explicit reachable target IP/hostname for Metasploit option preparation")
    parser.add_argument("--target-port", type=int, help="Target port (defaults to the reviewed reproduction spec port)")
    parser.add_argument("--module-type", choices=["exploit", "auxiliary"], help="Exact Metasploit module type for check")
    parser.add_argument("--module-name", help="Exact Metasploit module path (without the type prefix)")
    parser.add_argument("--metasploit-network", help="Existing Docker network shared by target and Metasploit")
    parser.add_argument("--metasploit-container", help="Name or ID of the running Metasploit container")
    parser.add_argument("--approval-file", type=Path, help="Explicit JSON approval binding module, target, and options")
    parser.add_argument("--module-options-file", type=Path, help="Optional JSON object of additional declared module options")
    parser.add_argument("--environment", help="Relative target directory for target-inspect")
    parser.add_argument("--request-file", type=Path, help="JSON ReproductionRequest for request-validate")
    parser.add_argument("--policy-file", type=Path, help="Reviewed JSON ExecutionPolicy required for run")
    parser.add_argument("--specs", type=Path, default=Path("reproductions"),
                        help="Directory containing reviewed YAML reproduction specifications")
    parser.add_argument("--workspace", type=Path, default=Path(".labs"))
    parser.add_argument("--project")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--engine-timeout", type=int, default=120, choices=range(1, 301), metavar="SECONDS")
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--inspect", type=Path, help="Existing JSON report to inspect")
    return parser


def main():
    parser = _parser()
    args = parser.parse_args()
    if args.action == "metasploit-search":
        cve = args.cve or args.identifier
        if not cve:
            parser.error("--action metasploit-search requires --cve")
        from app.integrations.metasploit import MetasploitRPCClient, MetasploitDiscovery
        url = os.environ.get("METASPLOIT_RPC_URL", "http://127.0.0.1:55553/api/")
        username = os.environ.get("METASPLOIT_RPC_USERNAME")
        password = os.environ.get("METASPLOIT_RPC_PASSWORD")
        if not username or not password:
            parser.error("Set METASPLOIT_RPC_USERNAME and METASPLOIT_RPC_PASSWORD")
        client = MetasploitRPCClient(url, username, password)
        try:
            candidates = MetasploitDiscovery(client).search_cve(cve)
            print(json.dumps([item.model_dump(mode="json") for item in candidates], ensure_ascii=False, indent=2))
        finally:
            client.close()
        return

    if args.action == "metasploit-assess":
        if not args.identifier:
            parser.error("--action metasploit-assess requires a reproduction-spec identifier")
        catalog = TargetCatalog(args.specs)
        spec = catalog.get(args.identifier)
        target = catalog.to_target_spec(spec)
        cve = args.cve or target.vulnerability_id
        if not cve:
            parser.error("Target has no CVE identifier; provide --cve")
        if not 1 <= args.candidate_limit <= 100:
            parser.error("--candidate-limit must be between 1 and 100")
        from app.integrations.metasploit import MetasploitRPCClient, MetasploitDiscovery
        from app.integrations.metasploit.compatibility import assess_compatibility
        url = os.environ.get("METASPLOIT_RPC_URL", "http://127.0.0.1:55553/api/")
        username = os.environ.get("METASPLOIT_RPC_USERNAME")
        password = os.environ.get("METASPLOIT_RPC_PASSWORD")
        if not username or not password:
            parser.error("Set METASPLOIT_RPC_USERNAME and METASPLOIT_RPC_PASSWORD")
        client = MetasploitRPCClient(url, username, password)
        try:
            discovery = MetasploitDiscovery(client)
            candidates = discovery.search_cve(cve, limit=args.candidate_limit)
            results = []
            for candidate in candidates:
                try:
                    metadata = discovery.inspect(candidate)
                    assessment = assess_compatibility(candidate, metadata, target, spec)
                    results.append({
                        "candidate": candidate.model_dump(mode="json"),
                        "metadata": metadata.model_dump(mode="json"),
                        "assessment": assessment.model_dump(mode="json"),
                    })
                except Exception as exc:
                    results.append({
                        "candidate": candidate.model_dump(mode="json"),
                        "inspection_error": f"{type(exc).__name__}: {exc}",
                    })
            print(json.dumps({
                "cve": cve,
                "target_id": target.target_id,
                "candidate_count": len(candidates),
                "results": results,
            }, ensure_ascii=False, indent=2))
        finally:
            client.close()
        return



    if args.action == "docker-target-resolve":
        if not args.identifier or not args.project or not args.metasploit_network or not args.metasploit_container:
            parser.error("--action docker-target-resolve requires spec identifier, --project, --metasploit-network, and --metasploit-container")
        from app.environments.docker.manager import DockerLab
        spec = TargetCatalog(args.specs).get(args.identifier)
        compose_path = args.workspace / args.project / "compose.json"
        if not compose_path.is_file():
            parser.error(f"Prepared lab does not exist: {compose_path}")
        lab = DockerLab(compose_path, args.project)
        endpoint = lab.resolve_target_endpoint(
            spec.service, spec.port,
            network_name=args.metasploit_network,
            metasploit_container=args.metasploit_container,
        )
        print(json.dumps({
            "target_id": spec.id,
            "service": endpoint["service"],
            "target_host": endpoint["host"],
            "target_port": endpoint["port"],
            "published_host_port": endpoint["published_host_port"],
            "docker_network": endpoint["network"],
            "metasploit_container": endpoint["metasploit_container"],
            "metasploit_network_ip": endpoint["metasploit_network_ip"],
        }, ensure_ascii=False, indent=2))
        return

    if args.action == "metasploit-check":
        required = {
            "--project": args.project,
            "--module-type": args.module_type,
            "--module-name": args.module_name,
            "--metasploit-network": args.metasploit_network,
            "--metasploit-container": args.metasploit_container,
            "--approval-file": args.approval_file,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            parser.error("--action metasploit-check requires " + ", ".join(missing))
        if not args.identifier:
            parser.error("--action metasploit-check requires a reproduction-spec identifier")
        catalog = TargetCatalog(args.specs)
        spec = catalog.get(args.identifier)
        target = catalog.to_target_spec(spec)
        from app.environments.docker.manager import DockerLab
        from app.integrations.metasploit import MetasploitRPCClient, MetasploitDiscovery, prepare_module_options
        from app.integrations.metasploit.execution import MetasploitCheckAdapter, MetasploitCheckApproval, options_fingerprint
        url = os.environ.get("METASPLOIT_RPC_URL", "http://127.0.0.1:55553/api/")
        username = os.environ.get("METASPLOIT_RPC_USERNAME")
        password = os.environ.get("METASPLOIT_RPC_PASSWORD")
        if not username or not password:
            parser.error("Set METASPLOIT_RPC_USERNAME and METASPLOIT_RPC_PASSWORD")
        project_dir = args.workspace / args.project
        compose_path = project_dir / "compose.json"
        if not compose_path.is_file():
            parser.error(f"Prepared lab does not exist: {compose_path}; run the reviewed Docker lab first")
        lab = DockerLab(compose_path, args.project)
        endpoint = lab.resolve_target_endpoint(
            spec.service, spec.port, network_name=args.metasploit_network,
            metasploit_container=args.metasploit_container,
        )
        client = MetasploitRPCClient(url, username, password)
        try:
            discovery = MetasploitDiscovery(client)
            cve = args.cve or target.vulnerability_id or ""
            candidates = discovery.search_cve(cve, limit=100)
            candidate = next((item for item in candidates
                if item.module_type == args.module_type and item.module_name == args.module_name), None)
            if candidate is None:
                parser.error("The exact requested module was not found in the CVE search results")
            metadata = discovery.inspect(candidate)
            overrides = json.loads(args.module_options_file.read_text(encoding="utf-8")) if args.module_options_file else {}
            if not isinstance(overrides, dict):
                parser.error("--module-options-file must contain a JSON object")
            prepared = prepare_module_options(
                candidate, metadata, target_host=endpoint["host"],
                target_port=endpoint["port"], overrides=overrides,
            )
            if not prepared.ready:
                print(json.dumps({
                    "status": "blocked", "reason": "Required Metasploit options are missing",
                    "missing_required": prepared.missing_required,
                    "candidate_id": candidate.candidate_id, "target_id": target.target_id,
                    "execution_performed": False,
                }, ensure_ascii=False, indent=2))
                raise SystemExit(2)
            approval = MetasploitCheckApproval.model_validate(
                json.loads(args.approval_file.read_text(encoding="utf-8"))
            )
            result = MetasploitCheckAdapter(client).check(
                candidate, prepared, target_id=target.target_id, approval=approval,
            )
            print(json.dumps({
                "status": result["job_status"], "check_code": result["check_code"],
                "message": result["message"], "candidate_id": result["candidate_id"],
                "target_id": result["target_id"], "target_endpoint": endpoint,
                "policy_id": result["policy_id"],
                "options_sha256": options_fingerprint(prepared.options),
                "exploit_executed": False, "result": result,
            }, ensure_ascii=False, indent=2))
        finally:
            client.close()
        return

    if args.action == "metasploit-prepare":
        if not args.identifier:
            parser.error("--action metasploit-prepare requires a reproduction-spec identifier")
        if not args.target_host:
            parser.error("--action metasploit-prepare requires --target-host")
        if not 1 <= args.candidate_limit <= 100:
            parser.error("--candidate-limit must be between 1 and 100")
        catalog = TargetCatalog(args.specs)
        spec = catalog.get(args.identifier)
        target = catalog.to_target_spec(spec)
        cve = args.cve or target.vulnerability_id
        if not cve:
            parser.error("Target has no CVE identifier; provide --cve")
        from app.integrations.metasploit import (
            MetasploitRPCClient, MetasploitDiscovery, prepare_module_options,
        )
        from app.integrations.metasploit.execution import options_fingerprint
        url = os.environ.get("METASPLOIT_RPC_URL", "http://127.0.0.1:55553/api/")
        username = os.environ.get("METASPLOIT_RPC_USERNAME")
        password = os.environ.get("METASPLOIT_RPC_PASSWORD")
        if not username or not password:
            parser.error("Set METASPLOIT_RPC_USERNAME and METASPLOIT_RPC_PASSWORD")
        client = MetasploitRPCClient(url, username, password)
        try:
            discovery = MetasploitDiscovery(client)
            candidates = discovery.search_cve(cve, limit=args.candidate_limit)
            prepared = []
            overrides = json.loads(args.module_options_file.read_text(encoding="utf-8")) if args.module_options_file else {}
            if not isinstance(overrides, dict):
                parser.error("--module-options-file must contain a JSON object")
            for candidate in candidates:
                metadata = discovery.inspect(candidate)
                option_result = prepare_module_options(
                    candidate, metadata,
                    target_host=args.target_host,
                    target_port=args.target_port if args.target_port is not None else spec.port,
                    overrides=overrides,
                )
                prepared.append({
                    "candidate": candidate.model_dump(mode="json"),
                    "prepared_options": option_result.model_dump(mode="json"),
                    "options_sha256": options_fingerprint(option_result.options),
                    "approval_template": {
                        "policy_id": "REVIEW_REQUIRED",
                        "candidate_id": candidate.candidate_id,
                        "target_id": target.target_id,
                        "target_host": option_result.target_host,
                        "target_port": option_result.target_port,
                        "options_sha256": options_fingerprint(option_result.options),
                        "max_wait_seconds": 60,
                    } if option_result.ready else None,
                })
            print(json.dumps({
                "cve": cve,
                "target_id": target.target_id,
                "selection": "first Metasploit search result; not an exploitability claim",
                "results": prepared,
                "execution_performed": False,
            }, ensure_ascii=False, indent=2))
        finally:
            client.close()
        return
    if args.action == "inspect":
        path = args.inspect or (Path(args.identifier) if args.identifier else None)
        if path is None:
            parser.error("--action inspect requires a report path")
        print(json.dumps(json.loads(path.read_text(encoding="utf-8")), ensure_ascii=False, indent=2))
        return
    if args.action == "target-search":
        if not args.query:
            parser.error("--action target-search requires --query")
        targets = VulhubTargetLoader(args.targets).search(args.query)
        print(json.dumps([item.model_dump(mode="json") for item in targets], ensure_ascii=False, indent=2))
        return
    if args.action == "target-inspect":
        if not args.environment:
            parser.error("--action target-inspect requires --environment")
        target = VulhubTargetLoader(args.targets).load(args.environment)
        print(json.dumps(target.model_dump(mode="json"), ensure_ascii=False, indent=2))
        return
    if args.action == "request-validate":
        if not args.request_file:
            parser.error("--action request-validate requires --request-file")
        request = ReproductionRequest.model_validate(json.loads(args.request_file.read_text(encoding="utf-8")))
        print(json.dumps(request.model_dump(mode="json"), ensure_ascii=False, indent=2))
        return
    if args.action == "policy-preview":
        if not args.identifier:
            parser.error("--action policy-preview requires a reproduction-spec identifier")
        catalog = TargetCatalog(args.specs)
        spec = catalog.get(args.identifier)
        target = catalog.to_target_spec(spec)
        if any(source.sha256 is None for source in target.sources):
            parser.error("Policy preview requires local, content-hashed sources; pin remote sources before approval")
        actions = {"pull", "up", "status", "health", "logs", "verify", "down"}
        if spec.reproduction:
            actions.add("http")
        if spec.verification_requests:
            actions.add("verify_http")
        if spec.file_evidence:
            actions.add("read_file")
        if spec.version_probes:
            actions.add("version")
        if spec.initialization:
            actions.update({"stage_artifacts", "initialize"})
        if spec.scripts:
            actions.update({"stage_artifacts", "script"})
        if target.environment.build_required:
            actions.add("build")
        retryable_actions = {"pull", "status", "health", "logs", "down"}
        if any(probe.retry_safe for probe in spec.reproduction):
            retryable_actions.add("http")
        if args.keep:
            actions.add("keep")
        template = {
            "policy_id": f"reviewed-{spec.id}",
            "approved_target_hashes": {target.target_id: target.fingerprint()},
            "approved_reproduction_hashes": {spec.id: spec.fingerprint()},
            "allowed_actions": sorted(actions),
            "retryable_actions": sorted(retryable_actions),
            "allowed_services": target.environment.services,
            "allowed_ports": sorted({p for ports in target.environment.published_ports.values() for p in ports}),
            "network_scope": "loopback_only",
            "allowed_hosts": ["127.0.0.1", "localhost"],
            "max_timeout_seconds": 60,
            "max_retries_per_step": 1,
            "max_recovery_actions": 1,
            "allow_image_build": False,
            "allow_target_scripts": False,
            "allow_keep_environment": bool(args.keep),
        }
        print(json.dumps({
            "target_spec": target.model_dump(mode="json"),
            "target_fingerprint": target.fingerprint(),
            "reproduction_fingerprint": spec.fingerprint(),
            "policy_template": template,
        }, ensure_ascii=False, indent=2))
        return
    if args.action == "engine":
        result = DockerEngine().registry().call("ensure_docker_engine", {
            "start": not args.check_only, "timeout": args.engine_timeout})
        print(json.dumps(result.evidence, ensure_ascii=False, indent=2))
        if not result.evidence["ready"]:
            raise SystemExit(1)
        return
    if not args.identifier:
        parser.error("provide a reviewed reproduction-spec identifier")
    if args.action in {"plan", "run"} and not args.policy_file:
        parser.error(f"--action {args.action} requires --policy-file; generate a reviewed template with --action policy-preview")
    try:
        model = configured_model()
        if args.action == "research":
            result = Researcher(args.specs, model).research(args.identifier)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return
        policy = ExecutionPolicy.model_validate(json.loads(args.policy_file.read_text(encoding="utf-8"))) if args.policy_file else None
        if args.action == "plan":
            catalog = TargetCatalog(args.specs)
            spec = catalog.get(args.identifier)
            target = catalog.to_target_spec(spec)
            bundle = Researcher(args.specs, model).research(args.identifier)
            plan = StructuredPlanner(model).generate(
                bundle, target=target, spec=spec, policy=policy,
                retries=args.retries, timeout=args.timeout, keep=args.keep)
            print(json.dumps(plan.model_dump(mode="json"), ensure_ascii=False, indent=2))
            return
        project = args.project or f"lab-{uuid4().hex[:12]}"
        report_path = args.report or Path("reports") / f"{project}.json"
        pipeline = Pipeline(
            args.specs, args.workspace, project, llm=model,
            retries=args.retries, timeout=args.timeout, keep=args.keep,
            docker_engine=DockerEngine(), engine_timeout=args.engine_timeout,
            execution_policy=policy,
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
