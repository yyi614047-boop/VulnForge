"""Pure domain contracts shared by VulnForge agents, workflows, and tools."""

from app.domain.policies import ExecutionPolicy
from app.domain.plans import ExecutionPlan, ExecutionStep
from app.domain.requests import ReproductionRequest
from app.domain.results import AssertionResult, Evidence, ExecutionReport, StepResult, VerificationOutcome
from app.domain.targets import TargetSpec, VerificationAssertion

__all__ = [
    "AssertionResult", "Evidence", "ExecutionPlan", "ExecutionPolicy", "ExecutionReport",
    "ExecutionStep", "ReproductionRequest", "StepResult", "TargetSpec", "VerificationAssertion", "VerificationOutcome",
]
