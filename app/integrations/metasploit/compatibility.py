"""Evidence-based compatibility assessment for a Metasploit candidate and a reviewed target."""
import re
from typing import Literal

from pydantic import Field

from app.domain.reproduction import ReproductionSpec
from app.domain.targets import DomainModel, TargetSpec
from app.integrations.metasploit.models import ModuleMetadata, PoCCandidate


class CompatibilityAssessment(DomainModel):
    candidate_id: str
    target_id: str
    status: Literal["compatible", "partial", "incompatible", "unknown"]
    matched_signals: list[str] = Field(default_factory=list)
    unknown_signals: list[str] = Field(default_factory=list)
    mismatches: list[str] = Field(default_factory=list)
    explanation: str
    next_step: str


def _normal_cve(value: str) -> str | None:
    match = re.search(r"CVE-\d{4}-\d{4,}", value, re.IGNORECASE)
    return match.group(0).upper() if match else None


def _version_mentioned(version: str, text: str) -> bool:
    version = version.strip()
    return bool(version and re.search(r"(?<![0-9A-Za-z.])" + re.escape(version) + r"(?![0-9A-Za-z.])", text))


def assess_compatibility(
    candidate: PoCCandidate,
    metadata: ModuleMetadata,
    target: TargetSpec,
    reproduction: ReproductionSpec | None = None,
) -> CompatibilityAssessment:
    """Compare only explicit signals; missing metadata stays unknown, not a false mismatch."""
    target_cve = _normal_cve(target.vulnerability_id or (reproduction.id if reproduction else ""))
    reference_cves = {
        _normal_cve(str(ref.get("ref", "")))
        for ref in metadata.references
        if str(ref.get("type", "")).upper() == "CVE" or _normal_cve(str(ref.get("ref", "")))
    }
    reference_cves.discard(None)
    matched, unknown, mismatches = [], [], []

    if target_cve and target_cve in reference_cves:
        matched.append(f"module references {target_cve}")
    elif reference_cves and target_cve:
        mismatches.append(f"module CVE references do not include {target_cve}")
    else:
        unknown.append("module metadata does not confirm the target CVE")

    product = (reproduction.product if reproduction else target.product).casefold().strip()
    module_identity = f"{metadata.name} {candidate.fullname}".casefold()
    product_tokens = [token for token in re.split(r"[^a-z0-9]+", product) if len(token) >= 3]
    if product_tokens and any(token in module_identity for token in product_tokens):
        matched.append("product name appears in module identity")
    else:
        unknown.append("product compatibility is not explicit in module identity")

    versions = reproduction.affected_versions if reproduction else target.affected_versions
    version_text = f"{metadata.name} {metadata.description}"
    if versions:
        if any(_version_mentioned(version, version_text) for version in versions):
            matched.append("an affected version is mentioned in module metadata")
        else:
            unknown.append("module metadata does not establish affected-version compatibility")
    else:
        unknown.append("target affected versions are not specified")

    options = {key.upper(): value for key, value in metadata.options.items()}
    if "RHOSTS" in options or "RHOST" in options:
        matched.append("module exposes a remote-host option")
    else:
        unknown.append("module remote-host option was not identified")

    target_port = reproduction.port if reproduction else None
    if target_port and ("RPORT" in options or "RPORTS" in options):
        matched.append(f"module exposes a configurable port for target port {target_port}")
    elif target_port:
        unknown.append("module port option was not identified")
    else:
        unknown.append("target service port is not available for comparison")

    if mismatches:
        status = "incompatible"
        next_step = "Skip this candidate or manually review its CVE references."
    elif target_cve and target_cve in reference_cves and product_tokens and any(
        token in module_identity for token in product_tokens
    ) and versions and any(_version_mentioned(version, version_text) for version in versions):
        status = "compatible"
        next_step = "Review required options, then consider a separately authorized module check."
    elif matched:
        status = "partial"
        next_step = "Review the unknown signals before deciding whether to run a module check."
    else:
        status = "unknown"
        next_step = "Gather stronger target or module metadata before selecting this candidate."

    explanation = {
        "compatible": "Explicit CVE, product, and version evidence align.",
        "partial": "Some signals align, but available metadata is insufficient to confirm compatibility.",
        "incompatible": "Explicit module metadata conflicts with the target CVE.",
        "unknown": "There is not enough explicit evidence to assess compatibility.",
    }[status]
    return CompatibilityAssessment(
        candidate_id=candidate.candidate_id,
        target_id=target.target_id,
        status=status,
        matched_signals=matched,
        unknown_signals=unknown,
        mismatches=mismatches,
        explanation=explanation,
        next_step=next_step,
    )
