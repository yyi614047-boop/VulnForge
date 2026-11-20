"""Pure domain contracts shared by VulnForge agents, workflows, and tools."""

from app.domain.policies import ExecutionPolicy
from app.domain.plans import ExecutionPlan, ExecutionStep
from app.domain.requests import ReproductionRequest
from app.domain.reproduction import ReproductionSpec, Probe, Script, FileEvidence, VersionProbe
from app.domain.results import AssertionResult, Evidence, ExecutionReport, StepResult, VerificationOutcome
from app.domain.targets import TargetSpec, VerificationAssertion

__all__ = [
    "AssertionResult", "Evidence", "FileEvidence", "Probe", "ReproductionSpec", "Script", "VersionProbe", "ExecutionPlan", "ExecutionPolicy", "ExecutionReport",
    "ExecutionStep", "ReproductionRequest", "StepResult", "TargetSpec", "VerificationAssertion", "VerificationOutcome",
]
