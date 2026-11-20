"""Small normalized models for Metasploit module discovery."""
from typing import Literal
from pydantic import Field
from app.domain.targets import DomainModel

ModuleType = Literal["exploit", "auxiliary", "post"]


class PoCCandidate(DomainModel):
    candidate_id: str = Field(min_length=1, max_length=256)
    source: Literal["metasploit"] = "metasploit"
    module_type: ModuleType
    module_name: str = Field(min_length=1, max_length=512)
    fullname: str = Field(min_length=1, max_length=600)
    rank: str | int | None = None
    cve_ids: list[str] = Field(default_factory=list, max_length=100)


class ModuleMetadata(DomainModel):
    module_type: ModuleType
    module_name: str
    name: str = ""
    description: str = ""
    rank: str | int | None = None
    references: list[dict] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    options: dict[str, dict] = Field(default_factory=dict)
