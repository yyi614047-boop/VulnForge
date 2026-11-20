"""Typed execution plans and dependency invariants, independent of LangGraph."""
from typing import Literal

from pydantic import Field, model_validator

from app.domain.reproduction import ReproductionSpec
from app.domain.targets import DomainModel, TargetSpec

ExecutionPhase = Literal["deploy", "reproduce", "verify", "cleanup"]
ExecutionAction = Literal[
    "stage_artifacts", "pull", "build", "up", "status", "version", "initialize",
    "health", "script", "http", "verify_http", "read_file", "logs", "verify", "down", "keep",
]


class ExecutionStep(DomainModel):
    step_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    phase: ExecutionPhase
    action: ExecutionAction
    target_id: str = Field(min_length=1, max_length=200)
    parameters: dict = Field(default_factory=dict, max_length=50)
    depends_on: list[str] = Field(default_factory=list, max_length=100)
    timeout_seconds: int = Field(default=60, ge=1, le=300)
    retries: int = Field(default=0, ge=0, le=3)
    rationale: str = Field(min_length=1, max_length=2000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)


class ExecutionPlan(DomainModel):
    schema_version: Literal[1] = 1
    plan_id: str = Field(min_length=1, max_length=128)
    target_id: str = Field(min_length=1, max_length=200)
    policy_id: str = Field(min_length=1, max_length=128)
    rationale: str = Field(min_length=1, max_length=4000)
    input_fingerprints: dict[str, str] = Field(min_length=3, max_length=10)
    steps: list[ExecutionStep] = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def validate_graph(self):
        ids = [step.step_id for step in self.steps]
        if len(ids) != len(set(ids)):
            raise ValueError("Execution step IDs must be unique")
        known, visited = set(ids), set()
        phase_order = {"deploy": 0, "reproduce": 1, "verify": 2, "cleanup": 3}
        last_phase = 0
        for step in self.steps:
            if step.target_id != self.target_id:
                raise ValueError("Every step must be bound to the plan target")
            if not set(step.depends_on) <= known or step.step_id in step.depends_on:
                raise ValueError("Step dependencies must reference other known steps")
            if not set(step.depends_on) <= visited:
                raise ValueError("Steps must be topologically ordered")
            if phase_order[step.phase] < last_phase:
                raise ValueError("Execution phases must follow deploy/reproduce/verify/cleanup order")
            last_phase = phase_order[step.phase]
            visited.add(step.step_id)
        return self

    def validate_policy(self, policy, target: TargetSpec, reproduction_spec: ReproductionSpec | None = None):
        if self.policy_id != policy.policy_id:
            raise PermissionError("Plan policy binding does not match the active policy")
        if self.target_id != target.target_id:
            raise PermissionError("Plan target binding does not match the selected target")
        policy.authorize_target(target, reproduction_spec)
        for step in self.steps:
            policy.authorize_action(step.action, timeout_seconds=step.timeout_seconds, retries=step.retries)
