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


def test_successful_deployment_allows_independent_verification_even_after_metasploit_outcome(tmp_path: Path):
    pipeline = Pipeline(tmp_path, tmp_path / "workspace", "stage-gate-verify")
    pipeline.active = True
    pipeline.executor = DummyExecutor()

    result = pipeline.verification({"deployment_ready": True, "status": "not_reproduced"})

    assert result == {"status": "pending"}
    assert pipeline.executor.phases == ["verify"]
