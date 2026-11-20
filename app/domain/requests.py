"""Validated user intent; deliberately contains no I/O or orchestration."""
from pathlib import PurePosixPath, PureWindowsPath
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator


class ReproductionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    request_id: str = Field(min_length=1, max_length=128)
    cve_id: str | None = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,}$")
    repository_url: HttpUrl | None = None
    description: str | None = Field(default=None, min_length=10, max_length=8000)
    target_id: str | None = Field(default=None, min_length=1, max_length=200)
    target_spec_path: str | None = Field(default=None, min_length=1, max_length=512)

    @model_validator(mode="after")
    def require_target_intent(self):
        if not any((self.cve_id, self.repository_url, self.description, self.target_id, self.target_spec_path)):
            raise ValueError("Provide a CVE, repository URL, vulnerability description, target ID, or target spec")
        if self.target_spec_path and (PurePosixPath(self.target_spec_path).is_absolute() or PureWindowsPath(self.target_spec_path).is_absolute() or ".." in PurePosixPath(self.target_spec_path.replace(chr(92), "/")).parts):
            raise ValueError("Target spec path must be relative and cannot traverse directories")
        return self
