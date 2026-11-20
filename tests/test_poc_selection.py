from app.agents import planner as planner_module
from app.agents.planner import StructuredPlanner
from app.domain.poc import PoCCandidate, PoCSelectionProposal
from app.domain.targets import EnvironmentSpec, TargetSource, TargetSpec


class FakeStructuredLLM:
    def with_structured_output(self, schema):
        return object()


def target():
    return TargetSpec(
        target_id="demo:CVE-2024-12345",
        title="Demo vulnerable service",
        product="demo",
        vulnerability_id="CVE-2024-12345",
        affected_versions=["1.0"],
        sources=[TargetSource(source_id="readme", path="README.md", sha256="a" * 64)],
        environment=EnvironmentSpec(
            compose_file="compose.yml", services=["web"], published_ports={"web": [8080]}
        ),
    )


def candidate(*, module_type="exploit", cve="CVE-2024-12345", source="metasploit"):
    return PoCCandidate(
        candidate_id="metasploit:exploit/linux/http/example",
        source=source,
        cve_ids=[cve],
        module_type=module_type,
        module_path="exploit/linux/http/example" if module_type == "exploit" else "auxiliary/scanner/http/example",
        name="Example module",
        description="Example metadata",
        metadata_sha256="b" * 64,
        metadata_excerpt="raw info output",
        inspected=True,
    )


def test_planner_selects_only_a_discovered_exploit_bound_to_target_cve(monkeypatch):
    planner = StructuredPlanner(FakeStructuredLLM())
    item = candidate()
    monkeypatch.setattr(
        planner_module, "invoke_agent",
        lambda *args: PoCSelectionProposal(
            selected_candidate_id=item.candidate_id,
            rationale="The inspected module explicitly references the target CVE.",
        ),
    )
    result = planner._select_poc_candidate(
        {"poc_candidates": [item.model_dump(mode="json")]}, target()
    )
    assert result["selected_candidate_id"] == item.candidate_id
    assert "compatibility" in result["rationale"]
    assert "authorization" in result["rationale"]


def test_planner_does_not_select_auxiliary_scanner_as_exploit(monkeypatch):
    planner = StructuredPlanner(FakeStructuredLLM())
    item = candidate(module_type="auxiliary")
    called = []
    monkeypatch.setattr(planner_module, "invoke_agent", lambda *args: called.append(True))
    result = planner._select_poc_candidate(
        {"poc_candidates": [item.model_dump(mode="json")]}, target()
    )
    assert result["selected_candidate_id"] is None
    assert called == []


def test_planner_does_not_select_candidate_for_another_cve(monkeypatch):
    planner = StructuredPlanner(FakeStructuredLLM())
    item = candidate(cve="CVE-2020-9999")
    monkeypatch.setattr(planner_module, "invoke_agent", lambda *args: pytest.fail("must not call model"))
    result = planner._select_poc_candidate(
        {"poc_candidates": [item.model_dump(mode="json")]}, target()
    )
    assert result["selected_candidate_id"] is None


def test_planner_rejects_model_proposal_not_in_eligible_candidates(monkeypatch):
    planner = StructuredPlanner(FakeStructuredLLM())
    item = candidate()
    monkeypatch.setattr(
        planner_module, "invoke_agent",
        lambda *args: PoCSelectionProposal(
            selected_candidate_id="metasploit:exploit/not-in-candidate-list",
            rationale="Trust me",
        ),
    )
    result = planner._select_poc_candidate(
        {"poc_candidates": [item.model_dump(mode="json")]}, target()
    )
    assert result["selected_candidate_id"] is None
    assert "rejected" in result["rationale"].lower()


def test_without_model_candidates_are_available_for_manual_review():
    planner = StructuredPlanner(llm=None)
    item = candidate()
    result = planner._select_poc_candidate(
        {"poc_candidates": [item.model_dump(mode="json")]}, target()
    )
    assert result["selected_candidate_id"] is None
    assert "manual review" in result["rationale"]


def test_uninspected_candidate_is_not_eligible(monkeypatch):
    planner = StructuredPlanner(FakeStructuredLLM())
    item = candidate().model_copy(update={"inspected": False})
    monkeypatch.setattr(planner_module, "invoke_agent", lambda *args: pytest.fail("must not call model"))
    result = planner._select_poc_candidate(
        {"poc_candidates": [item.model_dump(mode="json")]}, target()
    )
    assert result["selected_candidate_id"] is None


import pytest
