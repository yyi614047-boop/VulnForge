from app.domain.poc import PoCCandidate, PoCOption
from app.domain.poc_execution import LabNetworkAttestation, build_poc_execution_spec
from app.domain.policies import ExecutionPolicy
from app.domain.targets import EnvironmentSpec, TargetSource, TargetSpec
from app.execution.metasploit_rpc import (
    MetasploitRpcAdapter,
    MetasploitRpcClient,
    MessagePackHttpTransport,
    MetasploitRpcError,
)


class FakeRpcTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def call(self, method, *params):
        self.calls.append((method, params))
        expected_method, response = self.responses.pop(0)
        assert method == expected_method
        return response


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def call(self, method, *params):
        self.calls.append((method, params))
        expected_method, response = self.responses.pop(0)
        assert method == expected_method
        return response


def fixture():
    target = TargetSpec(
        target_id="demo:CVE-2020-1234",
        title="Demo lab",
        product="DemoServer",
        vulnerability_id="CVE-2020-1234",
        affected_versions=["1.0"],
        sources=[TargetSource(source_id="readme", path="README.md", sha256="a" * 64)],
        environment=EnvironmentSpec(
            compose_file="compose.yml", services=["web"], published_ports={"web": [8080]}
        ),
    )
    candidate = PoCCandidate(
        candidate_id="metasploit:exploit/linux/http/demo",
        source="metasploit",
        cve_ids=["CVE-2020-1234"],
        discovery_query_cve="CVE-2020-1234",
        module_type="exploit",
        module_path="exploit/linux/http/demo",
        name="Demo",
        options=[
            PoCOption(name="RHOSTS", required=True),
            PoCOption(name="RPORT", required=True),
            PoCOption(name="TARGETURI", required=True, current_value="/"),
        ],
        check_supported=True,
        metadata_sha256="b" * 64,
        inspected=True,
    )
    spec, _ = build_poc_execution_spec(candidate, target, target_port=8080)
    policy = ExecutionPolicy(
        policy_id="approved-local-msf",
        approved_target_hashes={target.target_id: target.fingerprint()},
        approved_poc_candidates={candidate.candidate_id: candidate.metadata_sha256},
        allowed_actions={"pull", "up", "status", "health", "logs", "verify", "down"},
        allowed_services={"web"},
        allowed_ports={8080},
        network_scope="loopback_only",
        allowed_hosts={"127.0.0.1", "localhost"},
        allow_metasploit_check=True,
        allow_metasploit_execute=True,
        allow_unknown_poc_compatibility=True,
    )
    return target, candidate, spec, policy


def test_rpc_client_authenticates_once_and_attaches_token():
    transport = FakeRpcTransport([
        ("auth.login", {"result": "success", "token": "secret-token"}),
        ("core.version", {"version": "6.4.0"}),
        ("core.version", {"version": "6.4.0"}),
    ])
    client = MetasploitRpcClient(transport, username="user", password="pass")
    assert client.call("core.version") == {"version": "6.4.0"}
    assert client.call("core.version") == {"version": "6.4.0"}
    assert transport.calls == [
        ("auth.login", ("user", "pass")),
        ("core.version", ("secret-token",)),
        ("core.version", ("secret-token",)),
    ]


def test_rpc_client_rejects_unapproved_rpc_method():
    transport = FakeRpcTransport([("auth.login", {"result": "failure"})])
    client = MetasploitRpcClient(transport, username="user", password="pass")
    try:
        client.call("console.execute", "arbitrary")
        assert False, "unapproved RPC method should be rejected"
    except ValueError as exc:
        assert "not exposed" in str(exc).lower()


def test_rpc_transport_restricts_server_to_loopback():
    import pytest
    with pytest.raises(ValueError, match="loopback"):
        MessagePackHttpTransport(host="192.0.2.1")
    with pytest.raises(ValueError, match="loopback"):
        MessagePackHttpTransport(host="msf.internal")


def test_check_and_execute_require_exact_policy_and_vulnerable_check():
    target, candidate, spec, policy = fixture()
    client = FakeClient([
        ("module.check", {"job_id": 1, "uuid": "check-uuid"}),
        ("module.results", {"status": "completed", "result": {
            "code": "vulnerable", "message": "Target is vulnerable"
        }}),
        ("session.list", {}),
        ("module.execute", {"job_id": 2, "uuid": "exec-uuid"}),
        ("module.results", {"status": "completed", "result": {"message": "module finished"}}),
        ("session.list", {}),
    ])
    adapter = MetasploitRpcAdapter(client, poll_interval=0.1)
    check = adapter.check(spec, candidate, target, policy, timeout=2)
    assert check.result_code == "vulnerable"
    result = adapter.execute(spec, candidate, target, policy, check, timeout=2)
    assert result.status == "completed"
    assert result.job_uuid == "exec-uuid"
    assert [call[0] for call in client.calls] == [
        "module.check", "module.results", "session.list",
        "module.execute", "module.results", "session.list",
    ]
    assert client.calls[0][1][0:2] == ("exploit", "linux/http/demo")
    assert client.calls[3][1][0:2] == ("exploit", "linux/http/demo")


def test_execute_is_blocked_without_a_vulnerable_check_from_same_adapter():
    import pytest
    target, candidate, spec, policy = fixture()
    client = FakeClient([])
    adapter = MetasploitRpcAdapter(client)
    forged = {
        "candidate_id": candidate.candidate_id,
        "module_metadata_sha256": candidate.metadata_sha256,
        "target_id": target.target_id,
        "target_fingerprint": target.fingerprint(),
        "job_uuid": "fake",
        "status": "completed",
        "result_code": "vulnerable",
        "result": {"code": "vulnerable"},
    }
    from app.domain.poc_execution import MetasploitCheckOutcome
    with pytest.raises(PermissionError, match="same adapter"):
        adapter.execute(spec, candidate, target, policy, MetasploitCheckOutcome.model_validate(forged))
    assert client.calls == []


def test_unapproved_candidate_is_rejected_before_rpc():
    import pytest
    target, candidate, spec, policy = fixture()
    policy = policy.model_copy(update={"approved_poc_candidates": {}})
    client = FakeClient([])
    adapter = MetasploitRpcAdapter(client)
    with pytest.raises(PermissionError, match="not explicitly approved"):
        adapter.check(spec, candidate, target, policy)
    assert client.calls == []


def test_execute_requires_explicit_unknown_compatibility_approval():
    import pytest
    target, candidate, spec, policy = fixture()
    policy = policy.model_copy(update={"allow_unknown_poc_compatibility": False})
    client = FakeClient([])
    adapter = MetasploitRpcAdapter(client)
    with pytest.raises(PermissionError, match="Unknown product/version"):
        adapter._validate_binding(spec, candidate, target, policy, "execute")
    assert client.calls == []


def test_callback_host_and_payload_options_are_policy_gated():
    import pytest
    target, candidate, spec, policy = fixture()
    candidate = candidate.model_copy(update={
        "options": candidate.options + [
            PoCOption(name="PAYLOAD", required=False),
            PoCOption(name="LHOST", required=False),
        ]
    })
    spec = spec.model_copy(update={"options": {
        **spec.options, "PAYLOAD": "linux/x64/shell_reverse_tcp", "LHOST": "0.0.0.0"
    }})
    client = FakeClient([])
    adapter = MetasploitRpcAdapter(client)
    with pytest.raises(PermissionError, match="LHOST"):
        adapter._validate_binding(spec, candidate, target, policy, "check")
    assert client.calls == []


def test_execute_stops_only_new_sessions_matching_this_target_and_module():
    target, candidate, spec, policy = fixture()
    client = FakeClient([
        ("module.check", {"job_id": 1, "uuid": "check-clean"}),
        ("module.results", {"status": "completed", "result": {"code": "vulnerable"}}),
        ("session.list", {}),
        ("module.execute", {"job_id": 2, "uuid": "exec-clean"}),
        ("module.results", {"status": "completed", "result": {"message": "done"}}),
        ("session.list", {
            "9": {"target_host": "127.0.0.1", "via_exploit": "exploit/linux/http/demo"},
            "10": {"target_host": "192.0.2.8", "via_exploit": "exploit/linux/http/demo"},
        }),
        ("session.stop", True),
    ])
    adapter = MetasploitRpcAdapter(client, poll_interval=0.1)
    check = adapter.check(spec, candidate, target, policy, timeout=2)
    result = adapter.execute(spec, candidate, target, policy, check, timeout=2)
    assert result.cleaned_session_ids == [9]
    assert client.calls[-1] == ("session.stop", (9,))


def test_check_unsupported_is_reported_as_a_candidate_result():
    target, candidate, spec, policy = fixture()
    client = FakeClient([])
    def call(method, *params):
        assert method == "module.check"
        raise MetasploitRpcError("The target module does not implement a check method")
    client.call = call
    outcome = MetasploitRpcAdapter(client).check(spec, candidate, target, policy)
    assert outcome.status == "failed"
    assert outcome.result_code == "unsupported"

def test_rpc_accepts_private_target_only_with_matching_internal_network_attestation():
    target, candidate, _, policy = fixture()
    attestation = LabNetworkAttestation(
        project="lab-demo", service="web", compose_sha256="c" * 64,
        target_container_id="d" * 64, target_host="172.20.0.2", target_port=80,
        published_host_port=8080, network_name="lab-shared", network_id="e" * 64,
        network_internal=True, target_networks=["lab-shared"],
        metasploit_container_id="f" * 64, metasploit_host="172.20.0.3",
        metasploit_networks=["lab-shared"],
    )
    spec, _ = build_poc_execution_spec(
        candidate, target, target_port=8080, target_attestation=attestation,
    )
    policy = policy.model_copy(update={"approved_lab_networks": {target.target_id: "lab-shared"}})
    MetasploitRpcAdapter(FakeClient([]))._validate_binding(spec, candidate, target, policy, "check")


def test_rpc_rejects_private_target_without_explicit_network_approval():
    import pytest
    target, candidate, _, policy = fixture()
    attestation = LabNetworkAttestation(
        project="lab-demo", service="web", compose_sha256="c" * 64,
        target_container_id="d" * 64, target_host="172.20.0.2", target_port=80,
        published_host_port=8080, network_name="lab-shared", network_id="e" * 64,
        network_internal=True, target_networks=["lab-shared"],
        metasploit_container_id="f" * 64, metasploit_host="172.20.0.3",
        metasploit_networks=["lab-shared"],
    )
    spec, _ = build_poc_execution_spec(candidate, target, target_port=8080, target_attestation=attestation)
    with pytest.raises(PermissionError, match="not explicitly approved"):
        MetasploitRpcAdapter(FakeClient([]))._validate_binding(spec, candidate, target, policy, "check")
