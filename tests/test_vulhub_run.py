import json
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from app.lab.vulhub_run import AgentDecision, EffectCheck, SourcePlan, VulhubRun
from app.tools.registry import ToolOutput


class Model:
    def __init__(self, plan, *, verification=None):
        self.plan = plan
        self.verification = verification or EffectCheck(
            status="success", reason="Observed documented output", evidence_quotes=["proof-output"])
        self.prompts = []
        self.decisions = []
        self.decision_count = 0
        self.structured_output_options = []

    def with_structured_output(self, schema, **kwargs):
        self.structured_output_options.append(kwargs)
        owner = self

        class Structured:
            def invoke(self, prompt):
                owner.prompts.append((schema, prompt))
                if schema is SourcePlan:
                    return owner.plan
                if schema is AgentDecision:
                    index = owner.decision_count
                    owner.decision_count += 1
                    if owner.decisions:
                        return owner.decisions[index]
                    if index < len(owner.plan.operations):
                        return AgentDecision(action="execute", operation=owner.plan.operations[index], reason="Follow source")
                    return AgentDecision(action="finish", reason="Submit observed results")
                return owner.verification

        return Structured()


class Engine:
    def ensure(self, params):
        return ToolOutput("ready", {"ready": True})


@pytest.fixture
def experiment(tmp_path):
    knowledge = tmp_path / "knowledge"
    source = knowledge / "product" / "CVE-2020-1234"
    source.mkdir(parents=True)
    (source / "docker-compose.yml").write_text(
        "version: '2'\nservices:\n  web:\n    image: example:1\n    ports: ['8080:80']\n", encoding="utf-8")
    (source / "README.md").write_text("# CVE-2020-1234\nDocumented local POST example.\n", encoding="utf-8")
    card = {"summary": {"prerequisite": "EVALUATION_ONLY_SECRET", "documented_effect": "Produces proof-output",
                        "expected_file_paths": [], "method": "POST", "request_shape": {
                            "media_type": "application/json", "required_cookie_names": [],
                            "json_fields": {"sample": "string"}}}}
    (knowledge / "product-CVE-2020-1234.yaml").write_text(yaml.safe_dump(card), encoding="utf-8")
    plan = SourcePlan.model_validate({"rationale": "Follow source", "operations": [{
        "id": "reproduce", "kind": "http", "phase": "reproduce", "service": "web",
        "container_port": 80, "method": "POST", "path": "/sample",
        "headers": {"Content-Type": "application/json"}, "body": '{"sample":"value"}',
        "citation": "product/CVE-2020-1234/README.md", "quote": "Documented local POST example.",
        "reason": "Documented request"}]})
    model = Model(plan)
    commands = []

    def runner(argv, **kwargs):
        commands.append(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    workflow = VulhubRun(knowledge, tmp_path / "workspace", "lab-test", model,
                         runner=runner, docker_engine=Engine(), auto_port=False)
    workflow.http = lambda operation: {"status": 200, "body": "proof-output", "truncated": False}
    return workflow, model, commands, tmp_path / "report.json", source


def test_source_run_evaluates_after_execution_and_cleans_up(experiment):
    workflow, model, commands, report_path, original = experiment
    report = workflow.run("CVE-2020-1234", report_path)
    assert report["status"] == "success"
    assert report["cleanup"] == "completed"
    assert all(options["method"] == "json_mode" for options in model.structured_output_options)
    assert '"operations"' in model.prompts[0][1]
    assert all("EVALUATION_ONLY_SECRET" not in prompt for schema, prompt in model.prompts if schema is not EffectCheck)
    assert "EVALUATION_ONLY_SECRET" in model.prompts[-1][1]
    assert model.prompts[-1][0] is EffectCheck
    assert "--wait" in commands[0]
    assert "down" in commands[-1]
    assert json.loads(report_path.read_text(encoding="utf-8"))["status"] == "success"
    assert yaml.safe_load((original / "docker-compose.yml").read_text())["services"]["web"]["ports"] == ["8080:80"]
    assert yaml.safe_load(workflow.compose.read_text())["services"]["web"]["ports"] == ["127.0.0.1:8080:80/tcp"]


def test_failed_operation_still_checks_and_cleans_up(experiment):
    workflow, model, commands, report_path, _ = experiment

    def fail(operation):
        raise OSError("connection failed")

    workflow.http = fail
    report = workflow.run("CVE-2020-1234", report_path)
    assert report["status"] == "inconclusive"
    assert report["cleanup"] == "completed"
    assert report["verification"]["status"] == "inconclusive"
    assert "down" in commands[-1]


def test_missing_information_does_not_start_docker(experiment):
    workflow, model, commands, report_path, _ = experiment
    model.plan = SourcePlan(rationale="Needs manual input", missing_information=["Credential missing"])
    report = workflow.run("CVE-2020-1234", report_path)
    assert report["status"] == "information_missing"
    assert not commands


def test_verifier_cannot_cite_request_as_success(experiment):
    workflow, model, _, report_path, _ = experiment
    model.verification = EffectCheck(status="success", reason="Wrong evidence", evidence_quotes=["value"])
    report = workflow.run("CVE-2020-1234", report_path)
    assert report["status"] == "inconclusive"


def test_report_is_not_overwritten(experiment):
    workflow, model, commands, report_path, _ = experiment
    report_path.write_text("preserve", encoding="utf-8")
    with pytest.raises(FileExistsError):
        workflow.run("CVE-2020-1234", report_path)
    assert report_path.read_text() == "preserve"
    assert not model.prompts
    assert not commands


def test_no_evaluation_card_returns_inconclusive(experiment):
    workflow, model, _, report_path, _ = experiment
    (workflow.knowledge / "product-CVE-2020-1234.yaml").unlink()
    report = workflow.run("CVE-2020-1234", report_path)
    assert report["status"] == "inconclusive"
    assert not any(schema is EffectCheck for schema, _ in model.prompts)


@pytest.mark.parametrize("arguments", [
    ["CVE-2020-1234"], ["run", "CVE-2020-1234"], ["CVE-2020-1234", "--action", "run"]])
def test_cli_run_entries_use_source_workflow(monkeypatch, arguments, tmp_path):
    import sys
    from app.lab import cli

    calls = []

    class Workflow:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, identifier, report_path, **kwargs):
            calls.append(identifier)
            return {"status": "success", "cleanup": "completed"}

    monkeypatch.setattr(cli, "source_model", lambda: object())
    monkeypatch.setattr(cli, "VulhubRun", Workflow)
    monkeypatch.setattr(sys, "argv", ["cli", *arguments, "--report", str(tmp_path / "report.json")])
    cli.main()
    assert calls == ["CVE-2020-1234"]


def test_partial_deployment_failure_is_cleaned_up(experiment):
    workflow, _, commands, report_path, _ = experiment
    original = workflow.runner

    def fail_deploy(argv, **kwargs):
        result = original(argv, **kwargs)
        if "up" in argv:
            result.returncode = 1
        return result

    workflow.runner = fail_deploy
    report = workflow.run("CVE-2020-1234", report_path)
    assert report["status"] == "environment_error"
    assert report["cleanup"] == "completed"
    assert "down" in commands[-1]


def test_source_model_reads_existing_llm_settings(monkeypatch, tmp_path):
    import langchain_openai
    from app.lab.vulhub_run import source_model

    for name in ["OPENAI_API_KEY", "OPENAI_BASE_URL", "PLANNER_MODEL", "LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"]:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        'LLM_API_KEY="test-key"\nLLM_BASE_URL=https://example.invalid/v1\nLLM_MODEL=test-model\n', encoding="utf-8")
    monkeypatch.setattr(langchain_openai, "ChatOpenAI", lambda **kwargs: kwargs)
    configuration = source_model()
    assert configuration["model"] == "test-model"
    assert configuration["api_key"] == "test-key"
    monkeypatch.setenv("PLANNER_MODEL", "process-model")
    assert source_model()["model"] == "process-model"


@pytest.mark.parametrize("key", ["test-\u4e2d\u6587", "test key", "test\tkey", "test\x7fkey"])
def test_source_model_rejects_invalid_api_key(monkeypatch, tmp_path, key):
    from app.lab.vulhub_run import source_model

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("LLM_API_KEY", key)
    monkeypatch.setenv("PLANNER_MODEL", "test-model")
    with pytest.raises(ValueError, match="Invalid API key configuration") as error:
        source_model()
    assert key not in str(error.value)


def test_source_mutation_is_rejected_before_docker(experiment):
    workflow, _, commands, _, source = experiment
    bundle = workflow.plan("CVE-2020-1234")
    (source / "README.md").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="changed after planning"):
        workflow.prepare(bundle)
    assert not commands


def test_langgraph_feedback_loop_recovers_and_traces_http(experiment):
    workflow, model, _, report_path, _ = experiment
    operation = model.plan.operations[0]
    model.decisions = [
        AgentDecision(action="execute", operation=operation, reason="First attempt"),
        AgentDecision(action="execute", operation=operation, reason="Recover after observing failure"),
        AgentDecision(action="finish", reason="Submit actual response"),
    ]
    attempts = []

    def open_response(request, timeout):
        attempts.append(request)
        if len(attempts) == 1:
            raise OSError("first-request-failed")
        response = BytesIO(b"proof-output")
        response.code = 200
        return response

    workflow.http = VulhubRun.http.__get__(workflow)
    workflow.opener = SimpleNamespace(open=open_response)
    report = workflow.run("CVE-2020-1234", report_path)
    assert report["status"] == "success"
    assert report["engine_type"] == "langgraph"
    assert report["agent_status"] == "submitted"
    assert [row["status"] for row in report["observations"]] == ["failed", "completed"]
    agent_prompts = [prompt for schema, prompt in model.prompts if schema is AgentDecision]
    assert "first-request-failed" in agent_prompts[1]
    events = [json.loads(line) for line in Path(report["trace"]).read_text(encoding="utf-8").splitlines()]
    assert events[0]["event"] == "run.start"
    assert events[-1]["event"] == "run.end"
    assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))
    assert len({event["run_id"] for event in events}) == 1
    assert any(event["event"] == "tool.error" and event["name"] == "http" for event in events)
    http_result = next(event for event in events if event["event"] == "tool.end" and event["name"] == "http")
    assert http_result["output"]["body"] == "proof-output"
    card_read = next(event for event in events if event["event"] == "tool.start" and event["name"] == "read_evaluation_card")
    assert card_read["sequence"] > http_result["sequence"]
    assert all("EVALUATION_ONLY_SECRET" not in json.dumps(event) for event in events
               if event["sequence"] < card_read["sequence"])


def test_decision_budget_stops_loop_and_still_cleans_up(experiment):
    workflow, model, commands, report_path, _ = experiment
    workflow.max_steps = 1
    model.decisions = [AgentDecision(action="logs", reason="Inspect environment")]
    report = workflow.run("CVE-2020-1234", report_path)
    assert report["agent_status"] == "max_steps_reached"
    assert report["status"] == "max_steps_reached"
    assert report["cleanup"] == "completed"
    assert "down" in commands[-1]


def test_model_error_is_persisted_in_trace(experiment):
    workflow, model, commands, report_path, _ = experiment

    class BrokenModel:
        def with_structured_output(self, schema, **kwargs):
            return self

        def invoke(self, prompt):
            raise RuntimeError("model-provider-failed")

    workflow.model = BrokenModel()
    report = workflow.run("CVE-2020-1234", report_path)
    assert report["status"] == "execution_error"
    assert not commands
    events = [json.loads(line) for line in Path(report["trace"]).read_text(encoding="utf-8").splitlines()]
    error = next(event for event in events if event["event"] == "model.error")
    assert error["error"]["message"] == "model-provider-failed"
    assert events[-1]["event"] == "run.end"


def test_sequential_engine_uses_the_same_agent_loop(experiment):
    workflow, model, _, report_path, _ = experiment
    report = workflow.run("CVE-2020-1234", report_path, engine="sequential")
    assert report["status"] == "success"
    assert model.decision_count == 2


def test_trace_keeps_raw_model_response_and_usage(experiment):
    workflow, model, _, report_path, _ = experiment

    class RawModel(Model):
        def with_structured_output(self, schema, **kwargs):
            parsed = super().with_structured_output(schema, **kwargs)
            assert kwargs["include_raw"] is True

            class Raw:
                def invoke(self, prompt):
                    return {"parsed": parsed.invoke(prompt), "parsing_error": None,
                            "raw": {"content": "provider response", "usage_metadata": {"input_tokens": 100}}}

            return Raw()

    workflow.model = RawModel(model.plan)
    report = workflow.run("CVE-2020-1234", report_path)
    assert report["status"] == "success"
    events = [json.loads(line) for line in Path(report["trace"]).read_text(encoding="utf-8").splitlines()]
    model_results = [event for event in events if event["event"] == "model.end"]
    assert all(event["output"]["raw"]["usage_metadata"]["input_tokens"] == 100 for event in model_results)


def test_read_source_cannot_access_root_evaluation_cards(experiment):
    workflow, _, _, _, _ = experiment
    bundle = workflow.plan("CVE-2020-1234")
    workflow.prepare(bundle)
    with pytest.raises(ValueError, match="inside the environment"):
        workflow.read_source("../../../knowledge/product-CVE-2020-1234.yaml")
