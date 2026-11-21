from pathlib import Path

from app.workflows.reproduction.graph import Pipeline


class DummyExecutor:
    def __init__(self):
        self.report = {"status": "pending"}
        self.phases = []

    def execute_phase(self, phase):
        self.phases.append(phase)


class NeverCallMetasploit:
    def __init__(self):
        self.calls = 0

    def check(self, *args, **kwargs):
        self.calls += 1
        raise AssertionError("Metasploit must not run before successful deployment")


def test_failed_deployment_blocks_metasploit_reproduction_and_verification(tmp_path: Path):
    adapter = NeverCallMetasploit()
    pipeline = Pipeline(tmp_path, tmp_path / "workspace", "stage-gate-test", metasploit_adapter=adapter)
    pipeline.active = True
    pipeline.executor = DummyExecutor()
    failed_state = {"status": "environment_error", "deployment_ready": False}

    assert pipeline.metasploit(failed_state) == {}
    assert pipeline.reproduce(failed_state) == {}
    assert pipeline.verification(failed_state) == {}
    assert adapter.calls == 0
    assert pipeline.executor.phases == []


def test_independent_http_verification_collects_evidence_after_inconclusive_metasploit(tmp_path: Path):
    pipeline = Pipeline(tmp_path, tmp_path / "workspace", "stage-gate-verify")
    pipeline.active = True
    pipeline.executor = DummyExecutor()
    pipeline.executor.report["status"] = "inconclusive"

    result = pipeline.verification({"deployment_ready": True, "status": "inconclusive"})

    assert result == {"status": "inconclusive"}
    assert pipeline.executor.phases == ["verify"]
    assert pipeline.executor.report["status"] == "inconclusive"



def test_graph_runs_reproduction_before_metasploit_and_independent_verifier(tmp_path: Path):
    pipeline = Pipeline(
        tmp_path, tmp_path / "workspace", "stage-order-test",
        metasploit_check_only=True,
    )
    edges = {(edge.source, edge.target) for edge in pipeline.graph().get_graph().edges}
    assert ("deployer", "reproducer") in edges
    assert ("reproducer", "metasploit") in edges
    assert ("metasploit", "verifier") in edges
