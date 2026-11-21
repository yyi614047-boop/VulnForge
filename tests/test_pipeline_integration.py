import json
from pathlib import Path

import yaml

from app.domain.policies import ExecutionPolicy
from app.domain.reproduction import Probe, ReproductionSpec
from app.targets.vulhub.catalog import TargetCatalog
from app.tools.registry import ToolOutput
from app.workflows.reproduction.graph import Pipeline


class FakeDockerLab:
    def __init__(self):
        self.actions = []

    def run(self, params):
        self.actions.append(params.action)
        evidence = {"all_running": True} if params.action == "status" else {}
        return ToolOutput(output=f"fake-{params.action}", evidence=evidence)


def make_fixture(root: Path):
    (root / "README.md").write_text("# Local test target\n", encoding="utf-8")
    (root / "compose.yml").write_text(yaml.safe_dump({
        "services": {"web": {"image": "nginx:1.25", "ports": ["127.0.0.1:8080:80"]}}
    }), encoding="utf-8")
    spec = ReproductionSpec(
        id="CVE-2024-12345",
        title="Local test target",
        product="demo",
        affected_versions=["1.0"],
        dependencies=["docker"],
        prerequisites=["local test fixture"],
        sources=["README.md"],
        environment="compose.yml",
        service="web",
        port=8080,
        health=Probe(id="health", path="/health"),
        reproduction=[Probe(id="reproduce", path="/poc", body_contains="vulnerable")],
        verification_requests=[Probe(id="verify", path="/verify", body_contains="confirmed")],
    )
    (root / "CVE-2024-12345.yaml").write_text(
        yaml.safe_dump(spec.model_dump(mode="json"), sort_keys=False), encoding="utf-8"
    )
    return spec


def test_pipeline_executes_domain_plan_with_policy_and_independent_verifier(tmp_path):
    specs = tmp_path / "specs"
    specs.mkdir()
    spec = make_fixture(specs)
    catalog = TargetCatalog(specs)
    target = catalog.to_target_spec(spec)
    policy = ExecutionPolicy(
        policy_id="local-test-policy",
        approved_target_hashes={target.target_id: target.fingerprint()},
        approved_reproduction_hashes={spec.id: spec.fingerprint()},
        allowed_actions={"pull", "up", "status", "health", "http", "verify_http", "logs", "verify", "down"},
        retryable_actions={"pull", "status", "health", "logs", "down"},
        allowed_services={"web"},
        allowed_ports={8080},
        max_recovery_actions=0,
    )
    lab = FakeDockerLab()
    observations = []

    def lab_factory(source, workspace, project):
        return lab

    def requester(port, probe, timeout=10):
        observations.append(probe.id)
        body = "vulnerable confirmed"
        return {
            "probe_id": probe.id,
            "url": f"http://127.0.0.1:{port}{probe.path}",
            "method": probe.method,
            "status": probe.expected_status,
            "body": body,
            "truncated": False,
        }

    report_path = tmp_path / "reports" / "run.json"
    pipeline = Pipeline(
        specs, tmp_path / "workspace", "lab-test-project",
        llm=None, retries=1, timeout=30,
        execution_policy=policy,
        executor_options={"lab_factory": lab_factory, "requester": requester, "sleeper": lambda _: None},
    )

    report = pipeline.run(spec.id, report_path)

    assert report["status"] == "success", report
    assert report["cleanup"] == "completed"
    assert report["authorization"]["policy_id"] == policy.policy_id
    assert report["verification"]["status"] == "success"
    assert {row["status"] for row in report["steps"]} == {"succeeded"}
    assert "pull" in lab.actions and "up" in lab.actions and "down" in lab.actions
    assert observations == ["health", "reproduce", "verify"]
    saved = json.loads(report_path.read_text(encoding="utf-8"))
    assert saved["plan"]["target_id"] == spec.id
    assert saved["plan"]["input_fingerprints"]["reproduction"] == spec.fingerprint()


def test_pipeline_fails_closed_without_policy_before_environment_side_effects(tmp_path):
    specs = tmp_path / "specs"
    specs.mkdir()
    spec = make_fixture(specs)
    lab_calls = []

    def lab_factory(source, workspace, project):
        lab_calls.append(project)
        return FakeDockerLab()

    pipeline = Pipeline(
        specs, tmp_path / "workspace", "lab-denied-project",
        llm=None, executor_options={"lab_factory": lab_factory},
    )
    report = pipeline.run(spec.id, tmp_path / "denied.json")

    assert report["status"] == "policy_denied"
    assert "ExecutionPolicy" in report["error"]
    assert lab_calls == []


class FakePoCDiscovery:
    def __init__(self, candidate):
        self.candidate = candidate
        self.queries = []

    def search_and_inspect(self, cve, *, limit=20):
        self.queries.append((cve, limit))
        return [self.candidate]


def test_pipeline_binds_optional_poc_discovery_into_research_and_plan(tmp_path):
    from app.domain.poc import PoCCandidate
    import hashlib

    specs = tmp_path / "specs"
    specs.mkdir()
    spec = make_fixture(specs)
    catalog = TargetCatalog(specs)
    target = catalog.to_target_spec(spec)
    policy = ExecutionPolicy(
        policy_id="local-poc-policy",
        approved_target_hashes={target.target_id: target.fingerprint()},
        approved_reproduction_hashes={spec.id: spec.fingerprint()},
        allowed_actions={"pull", "up", "status", "health", "http", "verify_http", "logs", "verify", "down"},
        retryable_actions={"pull", "status", "health", "logs", "down"},
        allowed_services={"web"},
        allowed_ports={8080},
        max_recovery_actions=0,
    )
    candidate = PoCCandidate(
        candidate_id="metasploit:exploit/linux/http/demo",
        source="metasploit",
        cve_ids=[spec.id],
        module_type="exploit",
        module_path="exploit/linux/http/demo",
        name="Demo module",
        metadata_sha256="c" * 64,
        metadata_excerpt="module info",
        inspected=True,
    )
    discovery = FakePoCDiscovery(candidate)
    lab = FakeDockerLab()

    def requester(port, probe, timeout=10):
        return {
            "probe_id": probe.id, "url": f"http://127.0.0.1:{port}{probe.path}",
            "method": probe.method, "status": probe.expected_status,
            "body": "vulnerable confirmed", "truncated": False,
        }

    report = Pipeline(
        specs, tmp_path / "workspace", "lab-poc-discovery",
        llm=None, execution_policy=policy, poc_discovery=discovery,
        executor_options={
            "lab_factory": lambda source, workspace, project: lab,
            "requester": requester, "sleeper": lambda _: None,
        },
    ).run(spec.id, tmp_path / "reports" / "poc.json")

    assert report["status"] == "success", report
    assert discovery.queries == [(spec.id, 10)]
    assert report["research"]["poc_discovery_status"] == "completed"
    assert report["research"]["poc_candidates"][0]["candidate_id"] == candidate.candidate_id
    expected_hash = hashlib.sha256(
        __import__("json").dumps(report["research"]["poc_candidates"], sort_keys=True).encode("utf-8")
    ).hexdigest()
    assert report["plan"]["input_fingerprints"]["poc_candidates"] == expected_hash
    assert report["plan"]["selected_poc_candidate_id"] is None
    assert "manual review" in report["plan"]["poc_selection_rationale"]


def test_pipeline_writes_redacted_trace_with_stage_events(tmp_path):
    from app.runtime.tracing import TraceRecorder, traced_call
    import json
    path = tmp_path / "test.trace.jsonl"
    with TraceRecorder(path, "test-run"):
        traced_call("model", "planner", {"api_key": "sk-verysecret"}, lambda: {"password": "sensitive"})
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert [event["event"] for event in events] == ["model.start", "model.end"]
    assert "verysecret" not in path.read_text()
    assert "sensitive" not in path.read_text()
