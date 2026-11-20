from app.workflows.reproduction.graph import Pipeline


class DockerEngineSpy:
    def __init__(self):
        self.called = False

    def ensure(self, _params):
        self.called = True
        raise AssertionError("Docker must not start before policy validation")


def test_pipeline_fails_closed_without_execution_policy(tmp_path):
    engine = DockerEngineSpy()
    pipeline = Pipeline(tmp_path, tmp_path / "workspace", "test-run", docker_engine=engine)

    result = pipeline.deploy({"status": "planned", "domain_plan": {}})

    assert result["status"] == "policy_denied"
    assert not engine.called
