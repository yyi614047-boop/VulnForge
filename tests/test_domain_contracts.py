import pytest
from pydantic import ValidationError

from app.domain import ExecutionPlan, ExecutionPolicy, ExecutionStep, ReproductionRequest, TargetSpec
from app.domain.targets import EnvironmentSpec, TargetSource


def target(*, scripts=None, port=8080):
    return TargetSpec(
        target_id="demo:CVE-2024-12345", title="Demo vulnerable service", product="demo",
        vulnerability_id="CVE-2024-12345",
        sources=[TargetSource(source_id="readme", path="demo/CVE-2024-12345/README.md")],
        environment=EnvironmentSpec(compose_file="demo/CVE-2024-12345/docker-compose.yml",
                                    services=["web"], published_ports={"web": [port]}),
        reproduction_entrypoints=scripts or [],
    )


def policy(approved_target=None, **overrides):
    selected = approved_target or target()
    values = dict(
        policy_id="local-reviewed-lab", approved_target_hashes={selected.target_id: selected.fingerprint()},
        allowed_actions={"up", "http", "verify_http", "down"}, allowed_services={"web"},
        allowed_ports={8080}, max_timeout_seconds=60, max_retries_per_step=1,
    )
    values.update(overrides)
    return ExecutionPolicy(**values)


def test_request_requires_some_target_intent():
    with pytest.raises(ValidationError):
        ReproductionRequest(request_id="req-1")
    assert ReproductionRequest(request_id="req-2", cve_id="CVE-2024-12345").cve_id == "CVE-2024-12345"


def test_request_rejects_path_traversal_and_bad_cve():
    with pytest.raises(ValidationError):
        ReproductionRequest(request_id="req-3", target_spec_path="../outside.yaml")
    with pytest.raises(ValidationError):
        ReproductionRequest(request_id="req-4", cve_id="CVE-2024-x")


def test_target_sources_reject_ambiguous_or_escaping_paths():
    with pytest.raises(ValidationError):
        TargetSource(source_id="bad", path="../outside.md")
    with pytest.raises(ValidationError):
        TargetSource(source_id="ambiguous", path="local.md", url="https://example.com/doc")
    with pytest.raises(ValidationError):
        TargetSource(source_id="insecure", url="http://example.com/doc")


def test_policy_uses_explicit_content_hash_approval_not_target_claims():
    candidate = target()
    policy(approved_target=candidate).authorize_target(candidate)
    altered = target(port=8081)
    with pytest.raises(PermissionError, match="not approved|fingerprint"):
        policy(approved_target=candidate).authorize_target(altered)


def test_policy_rejects_unapproved_service_port_and_script():
    approved = target()
    with pytest.raises(PermissionError, match="service"):
        policy(approved, allowed_services={"db"}).authorize_target(approved)
    with pytest.raises(PermissionError, match="port"):
        policy(approved, allowed_ports={9000}).authorize_target(approved)
    scripted = target(scripts=["demo/poc.py"])
    with pytest.raises(PermissionError, match="fingerprint|scripts"):
        policy(approved).authorize_target(scripted)


def test_policy_enforces_action_timeout_and_retry_budget():
    p = policy()
    p.authorize_action("up", timeout_seconds=30, retries=1)
    with pytest.raises(PermissionError):
        p.authorize_action("build", timeout_seconds=30)
    with pytest.raises(PermissionError):
        p.authorize_action("up", timeout_seconds=61)
    with pytest.raises(PermissionError):
        p.authorize_action("up", timeout_seconds=30, retries=2)


def test_execution_plan_requires_known_topologically_ordered_dependencies():
    selected = target()
    common = dict(target_id=selected.target_id, timeout_seconds=30)
    plan = ExecutionPlan(
        plan_id="plan-1", target_id=selected.target_id, policy_id="local-reviewed-lab",
        rationale="Deploy, observe, then clean up.",
        steps=[
            ExecutionStep(step_id="start", phase="deploy", action="up", rationale="Start service", **common),
            ExecutionStep(step_id="probe", phase="reproduce", action="http", depends_on=["start"], rationale="Observe target", **common),
            ExecutionStep(step_id="stop", phase="cleanup", action="down", depends_on=["probe"], rationale="Release resources", **common),
        ],
    )
    plan.validate_policy(policy(selected), selected)
    with pytest.raises(PermissionError):
        plan.validate_policy(policy(selected, policy_id="different-policy"), selected)
    with pytest.raises(ValidationError):
        ExecutionPlan(
            plan_id="plan-2", target_id=selected.target_id, policy_id="local-reviewed-lab",
            rationale="Invalid dependency.",
            steps=[ExecutionStep(step_id="probe", phase="reproduce", action="http", target_id=selected.target_id,
                                 depends_on=["missing"], timeout_seconds=30, rationale="Probe")],
        )


def test_reproduction_spec_fingerprint_is_bound_by_execution_policy():
    from app.domain.reproduction import Probe, ReproductionSpec

    selected = target()
    spec = ReproductionSpec(
        id=selected.target_id, title="Demo reproduction", product="demo",
        affected_versions=["1.0"], dependencies=["docker"], prerequisites=["local lab"],
        sources=["README.md"], environment="compose.yml", service="web", port=8080,
        health=Probe(id="health", path="/health"),
        reproduction=[Probe(id="repro", path="/poc", body_contains="vulnerable")],
    )
    p = policy(selected, approved_reproduction_hashes={spec.id: spec.fingerprint()})
    p.authorize_target(selected, spec)
    changed = spec.model_copy(update={"title": "Changed reproduction"})
    with pytest.raises(PermissionError, match="specification"):
        p.authorize_target(selected, changed)
