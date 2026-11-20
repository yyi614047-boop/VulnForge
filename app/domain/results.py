"""Auditable execution and evidence records shared across runtime layers."""
from datetime import datetime, timezone
from typing import Literal
from pydantic import Field
from app.domain.targets import DomainModel


class Evidence(DomainModel):
    evidence_id: str = Field(min_length=1, max_length=128)
    kind: Literal["source", "http", "file", "log", "container", "model_decision", "policy"]
    source: str = Field(min_length=1, max_length=2048)
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    content_ref: str | None = Field(default=None, max_length=2048)
    summary: str = Field(default="", max_length=4000)
    trusted: bool = False


class StepResult(DomainModel):
    step_id: str = Field(min_length=1, max_length=64)
    status: Literal["pending", "running", "success", "failed", "skipped", "inconclusive"]
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: float | None = Field(default=None, ge=0)
    error_category: str | None = None
    output_ref: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class ExecutionReport(DomainModel):
    schema_version: Literal[1] = 1
    run_id: str = Field(min_length=1, max_length=128)
    request_id: str = Field(min_length=1, max_length=128)
    target_id: str = Field(min_length=1, max_length=200)
    policy_id: str = Field(min_length=1, max_length=128)
    status: Literal["pending", "running", "success", "not_reproduced", "inconclusive", "failed", "cancelled"]
    plan_ref: str | None = None
    steps: list[StepResult] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    verification_status: Literal["pending", "success", "not_reproduced", "inconclusive", "failed"] = "pending"
    cleanup_status: Literal["pending", "completed", "failed", "not_needed"] = "pending"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
