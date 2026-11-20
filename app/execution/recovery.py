"""Policy-gated recovery proposals; model suggestions never directly cause side effects."""
from typing import Callable, Literal
from pydantic import Field
from app.domain.plans import ExecutionPlan, ExecutionStep
from app.domain.policies import ExecutionPolicy
from app.domain.targets import DomainModel, TargetSpec


class RecoveryProposal(DomainModel):
    action: Literal["retry", "replan", "switch_tool", "abort"]
    reason: str = Field(min_length=1, max_length=4000)
    step_id: str | None = None
    replacement_plan: ExecutionPlan | None = None
    replacement_step: ExecutionStep | None = None


class RecoveryAuthorization(DomainModel):
    action: Literal["retry", "replan", "switch_tool", "abort"]
    approved: bool
    reason: str
    plan: ExecutionPlan | None = None


class RecoveryGate:
    """Enforce retry budgets and require the full deterministic validator for plan changes."""

    def authorize(self, proposal: RecoveryProposal, *, target: TargetSpec, policy: ExecutionPolicy,
                  current_plan: ExecutionPlan, failed_step_id: str | None = None,
                  retries_used: int = 0, recovery_actions_used: int = 0,
                  validate_candidate: Callable[[ExecutionPlan], None] | None = None) -> RecoveryAuthorization:
        policy.authorize_target(target)
        if proposal.action == "abort":
            return RecoveryAuthorization(action="abort", approved=True, reason=proposal.reason)
        if proposal.action == "retry":
            step_id = proposal.step_id or failed_step_id
            step = next((item for item in current_plan.steps if item.step_id == step_id), None)
            if step is None or step_id != failed_step_id:
                raise PermissionError("Retry must refer to the exact failed step")
            if step.action not in policy.retryable_actions:
                raise PermissionError("The failed action is not retryable under policy")
            if retries_used >= min(step.retries, policy.max_retries_per_step):
                raise PermissionError("Retry budget is exhausted")
            if proposal.replacement_plan or proposal.replacement_step:
                raise PermissionError("Retry cannot modify the execution plan or step")
            return RecoveryAuthorization(action="retry", approved=True, reason=proposal.reason, plan=current_plan)
        if recovery_actions_used >= policy.max_recovery_actions:
            raise PermissionError("Recovery action budget is exhausted")
        if validate_candidate is None:
            raise PermissionError("Plan changes require the same deterministic validator used before execution")
        if proposal.action == "replan":
            if proposal.replacement_plan is None or proposal.replacement_step is not None:
                raise PermissionError("Replan requires exactly one replacement plan")
            candidate = proposal.replacement_plan
        else:
            if proposal.replacement_step is None or proposal.replacement_plan is not None:
                raise PermissionError("Tool switching requires exactly one replacement step")
            original = next((item for item in current_plan.steps if item.step_id == proposal.replacement_step.step_id), None)
            replacement = proposal.replacement_step
            if original is None or replacement.target_id != original.target_id or replacement.phase != original.phase or replacement.depends_on != original.depends_on or replacement.parameters != original.parameters:
                raise PermissionError("Tool switching may change only the action for the same step and arguments")
            if replacement.action == original.action:
                raise PermissionError("Replacement tool must differ from the failed action")
            steps = [replacement if item.step_id == original.step_id else item for item in current_plan.steps]
            candidate = current_plan.model_copy(update={"steps": steps})
            candidate = ExecutionPlan.model_validate(candidate.model_dump())
        candidate.validate_policy(policy, target)
        validate_candidate(candidate)
        return RecoveryAuthorization(action=proposal.action, approved=True, reason=proposal.reason, plan=candidate)
