from pathlib import Path

from app.lab.vulhub_run import Operation, SourcePlan, VulhubRun


class FakeMetasploit:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def verify(self, cve, *, host, port):
        self.calls.append((cve, host, port))
        return self.result


def make_operation():
    return Operation(
        id="reproduce", kind="http", phase="reproduce", service="web",
        container_port=80, method="POST", path="/vuln",
        headers={"Content-Type": "application/json"}, body='{"x":"y"}',
        citation="product/CVE-2020-1234/README.md",
        quote="Send this documented request.", reason="Reproduce the documented issue",
    )


def make_workflow(tmp_path, metasploit=None):
    return VulhubRun(
        tmp_path / "knowledge", tmp_path / ".labs", "lab-test", llm=None,
        runner=lambda *args, **kwargs: None, metasploit=metasploit,
    )


def make_bundle(operation):
    return {
        "sources": {"files": [{"source": operation.citation, "text": operation.quote}]},
        "compose": {"services": {"web": {}}},
        "plan": SourcePlan(rationale="Translate the Vulhub Markdown procedure",
                           operations=[operation]).model_dump(),
    }


def test_execute_plan_runs_markdown_operations_in_order_without_llm(tmp_path):
    workflow = make_workflow(tmp_path)
    operation = make_operation()
    bundle = make_bundle(operation)
    workflow.execute_operation = lambda op: {"status": 200, "body": "local lab response"}
    report = {}
    result = workflow.execute_plan(bundle, report, tmp_path / "report.json")
    assert result == "completed"
    assert report["execution_mode"] == "langgraph_plan_act_observe"
    assert report["observations"][0]["source_quote"] == operation.quote
    assert report["observations"][0]["evidence"]["status"] == 200


def test_execute_plan_stops_on_first_failed_documented_step(tmp_path):
    workflow = make_workflow(tmp_path)
    operation = make_operation()
    bundle = make_bundle(operation)

    def fail(_):
        raise OSError("local service unavailable")

    workflow.execute_operation = fail
    report = {}
    assert workflow.execute_plan(bundle, report, tmp_path / "report.json") == "execution_failed"
    assert report["observations"][0]["status"] == "failed"


def test_execute_plan_rejects_changed_markdown_quote(tmp_path):
    workflow = make_workflow(tmp_path)
    operation = make_operation()
    bundle = make_bundle(operation)
    bundle["sources"]["files"][0]["text"] = "different source text"
    report = {}
    assert workflow.execute_plan(bundle, report, tmp_path / "report.json") == "execution_failed"
    assert "no longer matches" in report["observations"][0]["error"]


def test_verifier_uses_metasploit_native_check_and_no_evaluation_card(tmp_path):
    metasploit = FakeMetasploit({"cve": "CVE-2020-1234", "status": "vulnerable", "modules": []})
    workflow = make_workflow(tmp_path, metasploit)
    operation = make_operation()
    workflow.ports[("web", 80)] = 18080
    result = workflow.check("CVE-2020-1234", make_bundle(operation), [])
    assert result["status"] == "success"
    assert result["verification_method"] == "metasploit_native_check"
    assert metasploit.calls == [("CVE-2020-1234", "127.0.0.1", 18080)]
    assert not (tmp_path / "knowledge" / "evaluation-cards").exists()


def test_missing_metasploit_module_is_unsupported_not_success(tmp_path):
    metasploit = FakeMetasploit({"cve": "CVE-2020-1234", "status": "unsupported", "modules": []})
    workflow = make_workflow(tmp_path, metasploit)
    operation = make_operation()
    workflow.ports[("web", 80)] = 18080
    result = workflow.check("CVE-2020-1234", make_bundle(operation), [])
    assert result["status"] == "unsupported"


def test_detected_is_not_misreported_as_reproduction_success(tmp_path):
    metasploit = FakeMetasploit({"cve": "CVE-2020-1234", "status": "detected", "modules": []})
    workflow = make_workflow(tmp_path, metasploit)
    operation = make_operation()
    workflow.ports[("web", 80)] = 18080
    result = workflow.check("CVE-2020-1234", make_bundle(operation), [])
    assert result["status"] == "inconclusive"


def test_no_documented_http_target_is_inconclusive(tmp_path):
    metasploit = FakeMetasploit({"status": "vulnerable"})
    workflow = make_workflow(tmp_path, metasploit)
    bundle = {"plan": {"operations": []}}
    result = workflow.check("CVE-2020-1234", bundle, [])
    assert result["status"] == "inconclusive"
    assert not metasploit.calls
