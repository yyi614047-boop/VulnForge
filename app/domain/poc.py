"""Typed, provenance-aware descriptions of existing PoC candidates."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class PoCOption(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z][A-Za-z0-9_]*$")
    required: bool
    current_value: str | None = Field(default=None, max_length=2000)
    description: str = Field(default="", max_length=4000)


class PoCCandidate(BaseModel):
    """A discovered existing PoC; discovery never grants execution permission."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    candidate_id: str = Field(min_length=1, max_length=256)
    source: Literal["metasploit", "github", "exploit_db", "upstream"]
    # CVEs parsed from the module metadata itself; never copy the search query here.
    cve_ids: list[str] = Field(default_factory=list, max_length=50)
    discovery_query_cve: str | None = Field(default=None, pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    module_type: Literal["exploit", "auxiliary"] | None = None
    module_path: str = Field(min_length=1, max_length=512)
    name: str | None = Field(default=None, max_length=500)
    description: str = Field(default="", max_length=12000)
    rank: str | None = Field(default=None, max_length=100)
    disclosure_date: str | None = Field(default=None, max_length=40)
    references: list[str] = Field(default_factory=list, max_length=100)
    targets: list[str] = Field(default_factory=list, max_length=100)
    options: list[PoCOption] = Field(default_factory=list, max_length=200)
    check_supported: bool | None = None
    metadata_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    metadata_excerpt: str = Field(default="", max_length=32000)
    inspected: bool = False


class PoCSelectionProposal(BaseModel):
    """LLM proposal only; application code must validate candidate membership."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    selected_candidate_id: str | None = Field(default=None, max_length=256)
    rationale: str = Field(min_length=1, max_length=4000)
