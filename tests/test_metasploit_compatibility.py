from app.domain.reproduction import ReproductionSpec
from app.domain.targets import EnvironmentSpec, TargetSource, TargetSpec
from app.integrations.metasploit.compatibility import assess_compatibility
from app.integrations.metasploit.models import ModuleMetadata, PoCCandidate


def target():
    return TargetSpec(
        target_id="log4j:CVE-2021-44228",
        title="Log4j vulnerable lab",
        product="log4j",
        vulnerability_id="CVE-2021-44228",
        affected_versions=["2.14.1"],
        sources=[TargetSource(source_id="compose", path="docker-compose.yml")],
        environment=EnvironmentSpec(
            compose_file="docker-compose.yml",
            services=["app"],
            published_ports={"app": [8080]},
        ),
    )


def candidate():
    return PoCCandidate(
        candidate_id="metasploit:exploit:multi/http/log4shell_header_injection",
        module_type="exploit",
        module_name="multi/http/log4shell_header_injection",
        fullname="exploit/multi/http/log4shell_header_injection",
        cve_ids=["CVE-2021-44228"],
    )


def reproduction():
    return ReproductionSpec(
        id="CVE-2021-44228-log4j",
        title="Log4j reproduction",
        product="log4j",
        affected_versions=["2.14.1"],
        dependencies=["docker"],
        prerequisites=["target is isolated"],
        sources=["README.md"],
        environment="docker-compose.yml",
        service="app",
        port=8080,
        health={"id": "health", "path": "/", "expected_status": 200},
        reproduction=[{"id": "repro", "path": "/", "body_contains": "ok"}],
    )


def metadata(refs=None, description="Supports Log4j 2.14.1"):
    return ModuleMetadata(
        module_type="exploit",
        module_name=candidate().module_name,
        name="Log4j Header Injection",
        description=description,
        references=refs or [{"type": "CVE", "ref": "2021-44228"}],
        options={"RHOSTS": {"required": True}, "RPORT": {"required": True}},
    )


def test_assessment_marks_explicit_match_compatible():
    result = assess_compatibility(candidate(), metadata(), target(), reproduction())
    assert result.status == "compatible"
    assert any("CVE-2021-44228" in item for item in result.matched_signals)


def test_assessment_marks_missing_version_evidence_partial():
    result = assess_compatibility(candidate(), metadata(description="Remote header injection"), target(), reproduction())
    assert result.status == "partial"
    assert any("version" in item for item in result.unknown_signals)


def test_assessment_marks_conflicting_cve_incompatible():
    result = assess_compatibility(
        candidate(),
        metadata(refs=[{"type": "CVE", "ref": "CVE-2020-9999"}]),
        target(),
        reproduction(),
    )
    assert result.status == "incompatible"
    assert result.mismatches


def test_assessment_does_not_treat_search_hit_as_proof():
    result = assess_compatibility(
        candidate(),
        metadata(refs=[], description="Unknown affected versions"),
        target(),
        reproduction(),
    )
    assert result.status == "partial"
    assert result.unknown_signals
