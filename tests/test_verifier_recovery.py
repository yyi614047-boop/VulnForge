import pytest

from app.domain.plans import ExecutionPlan, ExecutionStep
from app.domain.policies import ExecutionPolicy
from app.domain.results import Evidence
from app.domain.targets import EnvironmentSpec, TargetSource, TargetSpec, VerificationAssertion
from app.execution.recovery import RecoveryGate, RecoveryProposal
from app.execution.verifier import EvidenceVerifier


def reviewed_target():
    return TargetSpec(
        target_id="demo:CVE-2024-12345", title="Demo target", product="demo",
        vulnerability_id="CVE-2024-12345",
        sources=[TargetSource(source_id="readme", path="demo/README.md", sha256="a" * 64)],
        environment=EnvironmentSpec(compose_file="demo/docker-compose.yml", services=["web"], published_ports={"web": [8080]}),
        verification_assertions=[VerificationAssertion(assertion_id="vuln-response", evidence_kind="http",
            source="/vulnerable", operator="contains", expected_value="vulnerable")],
    )


def reviewed_policy(target):
    return ExecutionPolicy(
        policy_id="policy-1", approved_target_hashes={target.target_id: target.fingerprint()},
        allowed_actions={"up", "http", "down"}, retryable_actions={"http"},
        allowed_services={"web"}, allowed_ports={8080}, max_timeout_seconds=60,
        max_retries_per_step=1, max_recovery_actions=1,
    )


def plan(target):
    return ExecutionPlan(plan_id="plan-1", target_id=target.target_id, policy_id="policy-1",
        rationale="Run one bounded HTTP probe.", steps=[ExecutionStep(step_id="probe", phase="reproduce",
            action="http", target_id=target.target_id, timeout_seconds=30, retries=1,
            rationale="Collect the target response.")])


def test_verifier_requires_policy_approved_target_and_evidence():
    target = reviewed_target()
    policy = reviewed_policy(target)
    result = EvidenceVerifier().verify(target, [Evidence(evidence_id="ev-1", kind="http",
        source="/vulnerable", observed_value="200 vulnerable response")], policy)
    assert result.status == "success"
    assert result.checks[0].status == "matched"


def test_verifier_distinguishes_missing_evidence_from_failed_assertion():
    target = reviewed_target()
    policy = reviewed_policy(target)
    verifier = EvidenceVerifier()
    missing = verifier.verify(target, [], policy)
    mismatch = verifier.verify(target, [Evidence(evidence_id="ev-2", kind="http",
        source="/vulnerable", observed_value="404 not found")], policy)
    assert missing.status == "inconclusive"
    assert mismatch.status == "not_reproduced"


def test_recovery_gate_allows_only_budgeted_retry_of_exact_failed_step():
    target = reviewed_target()
    policy = reviewed_policy(target)
    current = plan(target)
    gate = RecoveryGate()
    approved = gate.authorize(RecoveryProposal(action="retry", reason="Transient reset."),
        target=target, policy=policy, current_plan=current, failed_step_id="probe", retries_used=0)
    assert approved.approved and approved.plan == current
    with pytest.raises(PermissionError, match="budget"):
        gate.authorize(RecoveryProposal(action="retry", reason="Try again."), target=target,
            policy=policy, current_plan=current, failed_step_id="probe", retries_used=1)
    with pytest.raises(PermissionError, match="exact failed step"):
        gate.authorize(RecoveryProposal(action="retry", reason="Other step.", step_id="other"),
            target=target, policy=policy, current_plan=current, failed_step_id="probe")


def test_recovery_gate_requires_full_validator_for_replan_and_allows_abort():
    target = reviewed_target()
    policy = reviewed_policy(target)
    current = plan(target)
    gate = RecoveryGate()
    aborted = gate.authorize(RecoveryProposal(action="abort", reason="Evidence is insufficient."),
        target=target, policy=policy, current_plan=current)
    assert aborted.approved and aborted.action == "abort"
    proposal = RecoveryProposal(action="replan", reason="Use a safer probe.", replacement_plan=current)
    with pytest.raises(PermissionError, match="deterministic validator"):
        gate.authorize(proposal, target=target, policy=policy, current_plan=current, recovery_actions_used=0)
    approved = gate.authorize(proposal, target=target, policy=policy, current_plan=current,
        recovery_actions_used=0, validate_candidate=lambda candidate: None)
    assert approved.approved and approved.plan == current
