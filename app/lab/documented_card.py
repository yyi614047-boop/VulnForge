"""Write self-contained documentary summaries, separate from executable cards."""
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, model_validator

from app.lab.knowledge import StrictModel


class RequestShape(StrictModel):
    media_type: str
    required_cookie_names: list[str]
    json_fields: dict[str, Literal["string", "integer", "boolean", "array", "object", "null", "number"]]


class DocumentedStep(StrictModel):
    id: str = Field(min_length=1)
    type: Literal["web", "ui", "other"]
    description: str = Field(min_length=1)
    method: str | None = None
    request_shape: RequestShape | None = None


class DocumentedCheck(StrictModel):
    verifies: str
    type: str = Field(min_length=1)
    expected: str = Field(min_length=1)


class DocumentedCard(StrictModel):
    id: str
    source: str
    prerequisites: list[str] = Field(default_factory=list)
    steps: list[DocumentedStep] = Field(min_length=1)
    checks: list[DocumentedCheck] = Field(min_length=1)
    verification_status: Literal["documented"] = "documented"

    @model_validator(mode="after")
    def check_step_links(self):
        ids = {step.id for step in self.steps}
        if len(ids) != len(self.steps) or any(check.verifies not in ids for check in self.checks):
            raise ValueError("Expected unique step IDs and valid check references")
        return self

    def write(self, destination: Path):
        destination.write_text(yaml.safe_dump(self.model_dump(exclude_none=True),
                                              allow_unicode=True, sort_keys=False), encoding="utf-8")
