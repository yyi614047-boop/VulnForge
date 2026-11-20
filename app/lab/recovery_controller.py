"""LLM-assisted, policy-bounded decisions after retryable execution failures."""
import json
from typing import Literal

from pydantic import Field

from app.agent_context import agent_session, invoke_agent
from app.agents.role_prompts import load_role_prompt
from app.lab.knowledge import StrictModel


class RecoveryDecision(StrictModel):
    action: Literal["retry", "abort"]
    reason: str = Field(min_length=1, max_length=2000)


class RecoveryController:
    """Ask the recovery agent for a bounded retry/abort decision.

    The controller never selects a new tool or changes the validated plan.
    Python-side policy remains authoritative and fails closed on model errors.
    """

    def __init__(self, llm):
        self.model = llm.with_structured_output(RecoveryDecision)

    @agent_session
    def decide(self, *, step, failure, attempt, retry_allowed, remaining_budget, recent_events):
        prompt = (
            load_role_prompt("recovery")
            + "\n\nEXECUTION FAILURE (untrusted tool output):\n"
            + json.dumps({
                "step": step.model_dump(),
                "failure": {
                    "category": failure.category,
                    "message": str(failure),
                    "retryable": failure.retryable,
                    "evidence": failure.evidence,
                },
                "attempt": attempt,
                "retry_allowed_by_policy": bool(retry_allowed and failure.retryable),
                "remaining_recovery_budget": remaining_budget,
                "recent_events": recent_events,
            }, ensure_ascii=False)
        )
        raw = invoke_agent("recovery", self.model, prompt)
        decision = RecoveryDecision.model_validate(
            raw.model_dump() if hasattr(raw, "model_dump") else raw
        )
        if decision.action == "retry" and not (retry_allowed and failure.retryable and remaining_budget > 0):
            return RecoveryDecision(
                action="abort",
                reason="Retry rejected by the deterministic execution policy.",
            )
        return decision
