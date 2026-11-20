"""Translate the planner's structured output into the shared domain plan."""
from app.agents.planner import DeploymentPlan
from app.domain.plans import ExecutionPlan, ExecutionStep
from app.domain.policies import ExecutionPolicy
from app.domain.targets import TargetSpec
from app.domain.reproduction import ReproductionSpec


def to_execution_plan(plan, target: TargetSpec, reproduction_spec: ReproductionSpec,
                      policy: ExecutionPolicy) -> ExecutionPlan:
    legacy = DeploymentPlan.model_validate(plan.model_dump() if hasattr(plan, "model_dump") else plan)
    steps = []
    for step in legacy.steps:
        parameters = {"probe_id": step.probe_id} if step.probe_id else {}
        steps.append(ExecutionStep(
            step_id=step.id,
            phase=step.phase,
            action=step.action,
            target_id=target.target_id,
            parameters=parameters,
            depends_on=step.depends_on,
            timeout_seconds=step.timeout_seconds,
            retries=step.max_retries,
            rationale=step.reason,
            evidence_refs=step.citations,
        ))
    domain_plan = ExecutionPlan(
        plan_id=f"{legacy.card_id}-{legacy.card_hash[:12]}",
        target_id=target.target_id,
        policy_id=policy.policy_id,
        rationale=legacy.rationale,
        steps=steps,
    )
    domain_plan.validate_policy(policy, target, reproduction_spec)
    return domain_plan
