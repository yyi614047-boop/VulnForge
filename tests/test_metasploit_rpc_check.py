import pytest

from app.integrations.metasploit.client import MetasploitRPCClient


class StubClient(MetasploitRPCClient):
    def __init__(self):
        self.calls = []

    def _call(self, method, *args):
        self.calls.append((method, args))
        if method == "module.check":
            return {"uuid": "abcd1234"}
        if method == "module.results":
            return {"status": "completed", "result": {"code": "Safe"}}


def test_module_check_and_result_calls_are_narrow_and_typed():
    client = StubClient()
    submitted = client.module_check(
        "exploit", "multi/http/example", {"RHOSTS": "172.20.0.2", "RPORT": 8080},
    )
    result = client.module_results(submitted["uuid"])
    assert result["result"]["code"] == "Safe"
    assert client.calls == [
        ("module.check", ("exploit", "multi/http/example", {"RHOSTS": "172.20.0.2", "RPORT": 8080})),
        ("module.results", ("abcd1234",)),
    ]


def test_module_check_rejects_unsupported_module_types():
    client = StubClient()
    with pytest.raises(ValueError, match="exploit and auxiliary"):
        client.module_check("post", "linux/gather/env", {})


def test_module_check_rejects_nested_options():
    client = StubClient()
    with pytest.raises(ValueError, match="flat scalar"):
        client.module_check("exploit", "multi/http/example", {"RHOSTS": {"host": "x"}})


def test_module_results_rejects_invalid_job_id():
    client = StubClient()
    with pytest.raises(ValueError, match="UUID"):
        client.module_results("../not-a-job")
