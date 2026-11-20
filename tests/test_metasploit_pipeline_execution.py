from threading import Event
from types import SimpleNamespace

from app.domain.poc import PoCCandidate, PoCOption
from app.domain.poc_execution import MetasploitCheckOutcome, MetasploitExecutionOutcome
from app.domain.policies import ExecutionPolicy
from app.domain.targets import EnvironmentSpec, TargetSource, TargetSpec
from app.execution.executor import StepExecutor


def fixture(*, ports=(8080,), allow_check=True, allow_execute=True):
    target = TargetSpec(
        target_id="demo:CVE-2020-1234",
        title="Demo lab",
        product="DemoServer",
        vulnerability_id="CVE-2020-1234",
        affected_versions=["1.0"],
        sources=[TargetSource(source_id="readme", path="README.md", sha256="a" * 64)],
        environment=EnvironmentSpec(
            compose_file="compose.yml", services=["web"],
            published_ports={"web": list(ports)},
        ),
    )
    candidate = PoCCandidate(
        candidate_id="metasploit:exploit/linux/http/demo",
        source="metasploit",
        cve_ids=["CVE-2020-1234"],
        discovery_query_cve="CVE-2020-1234",
        module_type="exploit",
        module_path="exploit/linux/http/demo",
        options=[
            PoCOption(name="RHOSTS", required=True),
            PoCOption(name="RPORT", required=True),
            PoCOption(name="TARGETURI", required=True, current_value="/"),
        ],
        check_supported=True,
        metadata_sha256="b" * 64,
        inspected=True,
    )
    policy = ExecutionPolicy(
        policy_id="approved",
        approved_target_hashes={target.target_id: target.fingerprint()},
        approved_poc_candidates={candidate.candidate_id: candidate.metadata_sha256},
        allowed_actions={"pull", "up", "status", "health", "logs", "verify", "down"},
        allowed_services={"web"},
        allowed_ports=set(ports),
        allowed_hosts={"127.0.0.1", "localhost"},
        allow_metasploit_check=allow_check,
        allow_metasploit_execute=allow_execute,
        allow_unknown_poc_compatibility=True,
    )
    return target, candidate, policy


class FakeAdapter:
    def __init__(self, code="vulnerable"):
        self.code = code
        self.checked = 0
        self.executed = 0

    def check(self, spec, candidate, target, policy, timeout):
        self.checked += 1
        return MetasploitCheckOutcome(
            candidate_id=candidate.candidate_id,
            module_metadata_sha256=candidate.metadata_sha256,
            target_id=target.target_id,
            target_fingerprint=target.fingerprint(),
            job_uuid="check-uuid",
            status="completed",
            result_code=self.code,
            result={"code": self.code},
        )

    def execute(self, spec, candidate, target, policy, check_outcome, timeout):
        self.executed += 1
        return MetasploitExecutionOutcome(
            candidate_id=candidate.candidate_id,
            target_id=target.target_id,
            job_uuid="exec-uuid",
            status="completed",
            result={"status": "completed"},
        )


def make_executor(target, candidate, policy, adapter, *, port=None):
    executor = object.__new__(StepExecutor)
    executor.domain_plan = SimpleNamespace(selected_poc_candidate_id=candidate.candidate_id)
    executor.bundle = {"poc_candidates": [candidate.model_dump(mode="json")]}
    executor.target_spec = target
    executor.execution_policy = policy
    executor.metasploit_adapter = adapter
    executor.metasploit_target_port = port
    executor.metasploit_options = {}
    executor.started = True
    executor.cancel = Event()
    executor.report = {"status": "pending"}
    executor.save = lambda: None
    return executor


def test_step_executor_runs_check_then_existing_exploit_when_vulnerable():
    target, candidate, policy = fixture()
    adapter = FakeAdapter()
    executor = make_executor(target, candidate, policy, adapter)
    record = executor.run_metasploit()
    assert record["status"] == "executed"
    assert record["check"]["result_code"] == "vulnerable"
    assert record["execution"]["job_uuid"] == "exec-uuid"
    assert adapter.checked == 1
    assert adapter.executed == 1


def test_step_executor_never_executes_when_check_is_not_vulnerable():
    target, candidate, policy = fixture()
    adapter = FakeAdapter(code="safe")
    executor = make_executor(target, candidate, policy, adapter)
    record = executor.run_metasploit()
    assert record["status"] == "check_safe"
    assert adapter.checked == 1
    assert adapter.executed == 0


def test_step_executor_supports_check_only_policy():
    target, candidate, policy = fixture(allow_execute=False)
    adapter = FakeAdapter()
    executor = make_executor(target, candidate, policy, adapter)
    record = executor.run_metasploit()
    assert record["status"] == "check_vulnerable_execution_disabled"
    assert adapter.checked == 1
    assert adapter.executed == 0


def test_step_executor_requires_explicit_port_when_lab_exposes_multiple_ports():
    target, candidate, policy = fixture(ports=(8080, 8443))
    adapter = FakeAdapter()
    executor = make_executor(target, candidate, policy, adapter)
    record = executor.run_metasploit()
    assert record["status"] == "configuration_required"
    assert record["available_ports"] == [8080, 8443]
    assert adapter.checked == 0


def test_step_executor_records_policy_block_without_rpc_call():
    target, candidate, policy = fixture(allow_check=False)
    adapter = FakeAdapter()
    executor = make_executor(target, candidate, policy, adapter)
    record = executor.run_metasploit()
    assert record["status"] == "policy_blocked"
    assert adapter.checked == 0
