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

    assert report["status"] == "success"
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
