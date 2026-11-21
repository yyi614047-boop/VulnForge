"""Command-line entry point for the staged LangGraph vulnerability Pipeline."""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from app.domain.requests import ReproductionRequest
from app.discovery.metasploit import MetasploitDiscovery
from app.domain.policies import ExecutionPolicy
from app.targets.vulhub.catalog import TargetCatalog
from app.targets.vulhub import VulhubTargetLoader
from app.runtime.models import configured_model
from app.workflows.reproduction.graph import Pipeline
from app.agents.planner import StructuredPlanner
from app.agents.researcher import Researcher
from app.environments.docker.engine import DockerEngine
from app.execution.metasploit_rpc import MetasploitRpcAdapter, MetasploitRpcClient


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("identifier", nargs="?", help="Reviewed reproduction specification identifier")
    parser.add_argument("--batch", type=Path, help="Text file containing one reviewed target identifier per line")
    parser.add_argument("--action", choices=["engine", "research", "plan", "run", "inspect", "target-search", "target-inspect", "request-validate", "policy-preview", "metasploit-search", "metasploit-inspect", "metasploit-rpc-version"], default="run")
    parser.add_argument("--targets", type=Path, default=Path("targets/vulhub"),
                        help="Root of the retained Vulhub target corpus")
    parser.add_argument("--query", help="Search query for target-search")
    parser.add_argument("--cve", help="CVE identifier for Metasploit discovery/inspection")
    parser.add_argument("--module", help="Metasploit module path for metasploit-inspect")
    parser.add_argument("--msfconsole", default="msfconsole", help="Path to the msfconsole executable")
    parser.add_argument("--msf-timeout", type=int, default=180, choices=range(1, 901), metavar="SECONDS")
    parser.add_argument("--discover-metasploit", action="store_true", help="Include read-only Metasploit candidates during research/planning")
    parser.add_argument("--enable-metasploit-execution", action="store_true", help="Enable policy-gated Metasploit Check/Execute through an attested internal Docker lab network")
    parser.add_argument("--msf-check", "--enable-metasploit-verification", dest="enable_metasploit_verification", action="store_true",
                        help="Run a policy-gated Metasploit Check after reproduction without executing an exploit")
    parser.add_argument("--no-msf-check", action="store_true", help="Disable default check-only Metasploit verification")
    parser.add_argument("--environment", help="Relative target directory for target-inspect")
    parser.add_argument("--request-file", type=Path, help="JSON ReproductionRequest for request-validate")
    parser.add_argument("--policy", "--policy-file", dest="policy_file", type=Path, default=Path("policies/local.json"), help="Reviewed JSON ExecutionPolicy (default: policies/local.json)")
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
    if args.batch:
        if args.identifier or args.action != "run" or args.enable_metasploit_execution:
            parser.error("--batch accepts only a list of reviewed identifiers for check-only runs")
        if not args.batch.is_file():
            parser.error(f"Batch file not found: {args.batch}")
        identifiers = []
        for raw in args.batch.read_text(encoding="utf-8").splitlines():
            identifier = raw.strip()
            if not identifier or identifier.startswith("#"):
                continue
            if not __import__("re").fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", identifier):
                parser.error(f"Invalid batch identifier: {identifier!r}")
            if identifier in identifiers:
                parser.error(f"Duplicate batch identifier: {identifier}")
            identifiers.append(identifier)
        if not identifiers:
            parser.error("Batch file contains no target identifiers")
        if not args.policy_file.is_file():
            parser.error(f"Reviewed policy not found: {args.policy_file}")
        results = []
        for identifier in identifiers:
            command = [sys.executable, "-m", "app.cli", identifier, "--policy", str(args.policy_file)]
            if args.no_msf_check:
                command.append("--no-msf-check")
            print(f"Running {identifier}...", flush=True)
            completed = subprocess.run(command, check=False)
            results.append({"identifier": identifier, "exit_code": completed.returncode})
        print(json.dumps({"batch": results, "passed": sum(x["exit_code"] == 0 for x in results),
                          "failed": sum(x["exit_code"] != 0 for x in results)}, ensure_ascii=False, indent=2))
        if any(x["exit_code"] != 0 for x in results):
            raise SystemExit(1)
        return
    if args.no_msf_check and args.enable_metasploit_verification:
        parser.error("--msf-check and --no-msf-check are mutually exclusive")
    if args.action == "run" and not args.no_msf_check and not args.enable_metasploit_execution:
        args.enable_metasploit_verification = True
    if args.enable_metasploit_verification:
        args.discover_metasploit = True
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
    if args.action == "metasploit-rpc-version":
        try:
            version = MetasploitRpcClient.from_env().call("core.version")
            print(json.dumps({"rpc": "connected", "version": version}, ensure_ascii=False, indent=2))
        except (OSError, RuntimeError, ValueError) as exc:
            parser.exit(2, f"Metasploit RPC smoke test failed: {exc}\\n")
        return
    if args.action in {"metasploit-search", "metasploit-inspect"}:
        if not args.cve:
            parser.error(f"--action {args.action} requires --cve")
        if args.action == "metasploit-inspect" and not args.module:
            parser.error("--action metasploit-inspect requires --module")
        try:
            discovery = MetasploitDiscovery(executable=args.msfconsole, timeout=args.msf_timeout)
            if args.action == "metasploit-search":
                result = {"cve": args.cve.upper(), "modules": discovery.discover(args.cve)}
            else:
                result = discovery.inspect(args.cve, args.module).model_dump(mode="json")
            print(json.dumps(result, ensure_ascii=False, indent=2))
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            parser.exit(2, f"Metasploit discovery failed: {exc}\\n")
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
            "approved_lab_networks": {},
            "approved_poc_candidates": {},
            "allow_metasploit_check": False,
            "allow_metasploit_execute": False,
            "allow_unknown_poc_compatibility": False,
            "allow_metasploit_payloads": False,
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
    if args.enable_metasploit_execution and args.action != "run":
        parser.error("--enable-metasploit-execution is only valid with --action run")
    if args.enable_metasploit_execution and not args.discover_metasploit:
        parser.error("--enable-metasploit-execution requires --discover-metasploit")
    if args.enable_metasploit_verification and args.enable_metasploit_execution:
        parser.error("Choose check-only verification or exploit execution, not both")
    if args.enable_metasploit_verification and args.action != "run":
        parser.error("--enable-metasploit-verification is only valid with --action run")
    if args.action in {"plan", "run"} and not args.policy_file.is_file():
        parser.error(f"Reviewed policy not found: {args.policy_file}. Generate a template with --action policy-preview, then review and save it.")
    try:
        model = configured_model()
        if args.action == "research":
            discovery = MetasploitDiscovery(executable=args.msfconsole, timeout=args.msf_timeout) if args.discover_metasploit else None
            result = Researcher(args.specs, model, poc_discovery=discovery).research(args.identifier)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return
        policy = ExecutionPolicy.model_validate(json.loads(args.policy_file.read_text(encoding="utf-8"))) if args.policy_file else None
        if args.action == "plan":
            catalog = TargetCatalog(args.specs)
            spec = catalog.get(args.identifier)
            target = catalog.to_target_spec(spec)
            discovery = MetasploitDiscovery(executable=args.msfconsole, timeout=args.msf_timeout) if args.discover_metasploit else None
            bundle = Researcher(args.specs, model, poc_discovery=discovery).research(args.identifier)
            plan = StructuredPlanner(model).generate(
                bundle, target=target, spec=spec, policy=policy,
                retries=args.retries, timeout=args.timeout, keep=args.keep)
            print(json.dumps(plan.model_dump(mode="json"), ensure_ascii=False, indent=2))
            return
        project = args.project or f"lab-{uuid4().hex[:12]}"
        report_path = args.report or Path("reports") / f"{project}.json"
        metasploit_enabled = args.enable_metasploit_execution or args.enable_metasploit_verification
        metasploit_adapter = MetasploitRpcAdapter(MetasploitRpcClient.from_env()) if metasploit_enabled else None
        pipeline = Pipeline(
            args.specs, args.workspace, project, llm=model,
            retries=args.retries, timeout=args.timeout, keep=args.keep,
            docker_engine=DockerEngine(), engine_timeout=args.engine_timeout,
            execution_policy=policy,
            poc_discovery=MetasploitDiscovery(executable=args.msfconsole, timeout=args.msf_timeout) if args.discover_metasploit else None,
            metasploit_adapter=metasploit_adapter,
            metasploit_check_only=args.enable_metasploit_verification,
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
