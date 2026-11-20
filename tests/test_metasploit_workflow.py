import pytest

from app.domain.poc import PoCCandidate, PoCOption
from app.domain.plans import ExecutionPlan
from app.domain.policies import ExecutionPolicy
from app.domain.reproduction import Probe, ReproductionSpec
from app.domain.targets import EnvironmentSpec, TargetSource, TargetSpec
from app.workflows.reproduction.metasploit import MetasploitCandidateRunner


class Outcome:
    def __init__(self, status, result_code):
        self.status, self.result_code = status, result_code

    def model_dump(self, mode="json"):
        return {"status": self.status, "result_code": self.result_code}


class FakeAdapter:
    def __init__(self, check_code="vulnerable"):
        self.check_code = check_code
        self.calls = []

    def check(self, spec, candidate, target, policy, *, timeout):
        self.calls.append(("check", timeout))
        return Outcome("completed", self.check_code)

    def execute(self, spec, candidate, target, policy, check, *, timeout):
        self.calls.append(("execute", timeout))
        return Outcome("completed", "completed")


def fixture(check_code="vulnerable"):
    target_id = "demo:CVE-2020-1234"
    target = TargetSpec(
        target_id=target_id, title="Demo lab", product="DemoServer",
        vulnerability_id="CVE-2020-1234", affected_versions=["1.0"],
        sources=[TargetSource(source_id="readme", path="README.md", sha256="a" * 64)],
        environment=EnvironmentSpec(compose_file="compose.yml", services=["web"], published_ports={"web": [8080]}),
    )
    reproduction = ReproductionSpec(
        id=target_id, title="Demo lab", product="DemoServer", affected_versions=["1.0"],
        dependencies=["docker"], prerequisites=["local lab"], sources=["README.md"],
        environment="demo", service="web", port=8080, health=Probe(id="health", path="/"),
        reproduction=[Probe(id="reproduce", path="/", body_contains="demo")],
    )
    candidate = PoCCandidate(
        candidate_id="metasploit:exploit/linux/http/demo", source="metasploit",
        cve_ids=["CVE-2020-1234"], discovery_query_cve="CVE-2020-1234",
        module_type="exploit", module_path="exploit/linux/http/demo", inspected=True,
        metadata_sha256="b" * 64,
        options=[PoCOption(name="RHOSTS", required=True), PoCOption(name="RPORT", required=True)],
    )
    policy = ExecutionPolicy(
        policy_id="approved-local-msf", approved_target_hashes={target_id: target.fingerprint()},
        approved_reproduction_hashes={target_id: reproduction.fingerprint()},
        approved_poc_candidates={candidate.candidate_id: candidate.metadata_sha256},
        allowed_actions={"pull", "up", "status", "health", "logs", "verify", "down"},
        allowed_services={"web"}, allowed_ports={8080}, network_scope="loopback_only",
        allowed_hosts={"127.0.0.1", "localhost"}, allow_metasploit_check=True,
        allow_metasploit_execute=True, allow_unknown_poc_compatibility=True,
    )
    bundle = {"poc_candidates": [candidate.model_dump(mode="json")], "poc_candidates_hash": "c" * 64}
    plan = ExecutionPlan(
        plan_id="plan-demo", target_id=target_id, policy_id=policy.policy_id,
        rationale="approved lab run", selected_poc_candidate_id=candidate.candidate_id,
        poc_selection_rationale="metadata matches reviewed CVE",
        input_fingerprints={"reproduction": reproduction.fingerprint(), "compose": "d" * 64,
                            "assets": "e" * 64, "poc_candidates": bundle["poc_candidates_hash"]},
        steps=[{"step_id": "deploy", "phase": "deploy", "action": "up", "target_id": target_id,
                "timeout_seconds": 30, "rationale": "start local lab"}],
    )
    return plan, bundle, target, reproduction, policy, FakeAdapter(check_code)


def test_runner_checks_then_executes_only_after_vulnerable_check():
    plan, bundle, target, reproduction, policy, adapter = fixture()
    result = MetasploitCandidateRunner(adapter).run(
        plan=plan, bundle=bundle, target=target, reproduction=reproduction, policy=policy,
    )
    assert result["status"] == "executed"
    assert result["verification"] == "pending_independent_assertions"
    assert [call[0] for call in adapter.calls] == ["check", "execute"]


def test_runner_never_executes_when_check_is_safe():
    plan, bundle, target, reproduction, policy, adapter = fixture("safe")
    result = MetasploitCandidateRunner(adapter).run(
        plan=plan, bundle=bundle, target=target, reproduction=reproduction, policy=policy,
    )
    assert result["status"] == "not_reproduced"
    assert result["execution"] is None
    assert [call[0] for call in adapter.calls] == ["check"]


def test_runner_rejects_candidate_bundle_tampering_before_rpc():
    plan, bundle, target, reproduction, policy, adapter = fixture()
    bundle["poc_candidates_hash"] = "f" * 64
    with pytest.raises(PermissionError, match="changed after planning"):
        MetasploitCandidateRunner(adapter).run(
            plan=plan, bundle=bundle, target=target, reproduction=reproduction, policy=policy,
        )
    assert adapter.calls == []

def test_pipeline_report_must_not_verify_after_inconclusive_metasploit(monkeypatch):
    # The workflow node guard is covered by the graph-level integration fixture;
    # this assertion protects the runner's non-success classification.
    plan, bundle, target, reproduction, policy, adapter = fixture("unknown")
    result = MetasploitCandidateRunner(adapter).run(
        plan=plan, bundle=bundle, target=target, reproduction=reproduction, policy=policy,
    )
    assert result["status"] == "inconclusive"
    assert result["execution"] is None
