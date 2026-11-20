import pytest

from app.integrations.metasploit.execution import (
    MetasploitCheckAdapter,
    MetasploitCheckApproval,
    options_fingerprint,
)
from app.integrations.metasploit.models import ModuleMetadata, PoCCandidate
from app.integrations.metasploit.options import prepare_module_options


class FakeRPC:
    def __init__(self):
        self.calls = []
        self.polls = 0

    def module_check(self, module_type, module_name, options):
        self.calls.append((module_type, module_name, options))
        return {"uuid": "abcd1234"}

    def module_results(self, uuid):
        self.polls += 1
        if self.polls == 1:
            return {"status": "running"}
        return {
            "status": "completed",
            "result": {"code": "Vulnerable", "message": "Check evidence found", "details": {"service": "demo"}},
        }


def fixture(host="172.20.0.2"):
    candidate = PoCCandidate(
        candidate_id="metasploit:exploit:multi/http/demo",
        module_type="exploit",
        module_name="multi/http/demo",
        fullname="exploit/multi/http/demo",
    )
    metadata = ModuleMetadata(
        module_type="exploit",
        module_name="multi/http/demo",
        options={
            "RHOSTS": {"required": True},
            "RPORT": {"required": True},
            "TARGETURI": {"required": True, "default": "/"},
        },
    )
    prepared = prepare_module_options(
        candidate, metadata, target_host=host, target_port=8080,
    )
    approval = MetasploitCheckApproval(
        policy_id="reviewed-local-lab",
        candidate_id=candidate.candidate_id,
        target_id="CVE-2021-44228-log4j",
        target_host=host,
        target_port=8080,
        options_sha256=options_fingerprint(prepared.options),
        max_wait_seconds=5,
    )
    return candidate, prepared, approval


def test_check_polls_and_returns_check_code_without_exploiting():
    rpc = FakeRPC()
    candidate, prepared, approval = fixture()
    adapter = MetasploitCheckAdapter(rpc, poll_interval=0.05, sleeper=lambda _: None)
    result = adapter.check(
        candidate, prepared, target_id=approval.target_id, approval=approval,
    )
    assert result["check_code"] == "vulnerable"
    assert result["exploit_executed"] is False
    assert rpc.calls[0][2]["RHOSTS"] == "172.20.0.2"


def test_rejects_changed_options_before_rpc():
    rpc = FakeRPC()
    candidate, prepared, approval = fixture()
    prepared.options["TARGETURI"] = "/changed"
    with pytest.raises(PermissionError, match="changed after explicit approval"):
        MetasploitCheckAdapter(rpc).check(
            candidate, prepared, target_id=approval.target_id, approval=approval,
        )
    assert rpc.calls == []


def test_rejects_public_or_loopback_targets():
    rpc = FakeRPC()
    candidate, prepared, approval = fixture("8.8.8.8")
    with pytest.raises(PermissionError, match="private"):
        MetasploitCheckAdapter(rpc).check(
            candidate, prepared, target_id=approval.target_id, approval=approval,
        )
    assert rpc.calls == []


def test_rejects_module_type_without_check_support():
    rpc = FakeRPC()
    candidate, prepared, approval = fixture()
    candidate.module_type = "post"
    with pytest.raises(PermissionError, match="exploit and auxiliary"):
        MetasploitCheckAdapter(rpc).check(
            candidate, prepared, target_id=approval.target_id, approval=approval,
        )
    assert rpc.calls == []
