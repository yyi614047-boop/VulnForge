import pytest

from app.discovery.metasploit import parse_module_info
from app.domain.poc import PoCCandidate, PoCOption
from app.domain.poc_execution import (
    PoCExecutionSpec,
    assess_metasploit_compatibility,
    build_poc_execution_spec,
)
from app.domain.targets import EnvironmentSpec, TargetSource, TargetSpec


def make_target():
    return TargetSpec(
        target_id="demo:CVE-2020-1234",
        title="Demo lab",
        product="DemoServer",
        vulnerability_id="CVE-2020-1234",
        affected_versions=["1.0"],
        sources=[TargetSource(source_id="readme", path="README.md", sha256="a" * 64)],
        environment=EnvironmentSpec(
            compose_file="compose.yml",
            services=["web"],
            published_ports={"web": [8080]},
        ),
    )


def make_candidate():
    return PoCCandidate(
        candidate_id="metasploit:exploit/linux/http/demo",
        source="metasploit",
        cve_ids=["CVE-2020-1234"],
        discovery_query_cve="CVE-2020-1234",
        module_type="exploit",
        module_path="exploit/linux/http/demo",
        name="Demo exploit",
        targets=["Automatic"],
        options=[
            PoCOption(name="RHOSTS", required=True),
            PoCOption(name="RPORT", required=True, current_value="80"),
            PoCOption(name="TARGETURI", required=True, current_value="/"),
            PoCOption(name="SSL", required=False, current_value="false"),
        ],
        metadata_sha256="b" * 64,
        inspected=True,
    )


def test_search_query_is_not_promoted_to_module_cve_reference():
    candidate = parse_module_info(
        "exploit/linux/http/demo",
        "CVE-2020-1234",
        "Name: Demo exploit\nRank: Normal\nReferences:\n  URL: https://example.test/advisory",
    )
    assert candidate.discovery_query_cve == "CVE-2020-1234"
    assert candidate.cve_ids == []


def test_parser_uses_only_cves_present_in_module_metadata():
    candidate = parse_module_info(
        "exploit/linux/http/demo",
        "CVE-2020-1234",
        "Name: Demo exploit\nReferences:\n  CVE-2019-9999\n  CVE-2020-1234",
    )
    assert candidate.discovery_query_cve == "CVE-2020-1234"
    assert candidate.cve_ids == ["CVE-2019-9999", "CVE-2020-1234"]


def test_build_execution_spec_binds_module_to_loopback_target_and_port():
    spec, assessment = build_poc_execution_spec(
        make_candidate(), make_target(), target_port=8080
    )
    assert isinstance(spec, PoCExecutionSpec)
    assert spec.module_path == "exploit/linux/http/demo"
    assert spec.target_id == "demo:CVE-2020-1234"
    assert spec.target_fingerprint == make_target().fingerprint()
    assert spec.target_host == "127.0.0.1"
    assert spec.target_port == 8080
    assert spec.options == {"RHOSTS": "127.0.0.1", "RPORT": "8080", "TARGETURI": "/"}
    assert spec.approval_required is True
    assert spec.compatibility_status == "unknown"
    assert assessment.status == "unknown"
    assert assessment.unknowns


@pytest.mark.parametrize("host", ["192.0.2.10", "attacker.example", "0.0.0.0"])
def test_non_loopback_target_is_rejected(host):
    assessment = assess_metasploit_compatibility(
        make_candidate(), make_target(), target_host=host, target_port=8080
    )
    assert assessment.status == "incompatible"
    assert any("loopback" in item.lower() for item in assessment.blockers)


def test_port_must_be_declared_by_target_environment():
    assessment = assess_metasploit_compatibility(
        make_candidate(), make_target(), target_port=4444
    )
    assert assessment.status == "incompatible"
    assert any("port" in item.lower() for item in assessment.blockers)


def test_candidate_must_reference_target_cve_in_inspected_metadata():
    candidate = make_candidate().model_copy(update={"cve_ids": ["CVE-2019-9999"]})
    assessment = assess_metasploit_compatibility(candidate, make_target(), target_port=8080)
    assert assessment.status == "incompatible"
    assert any("CVE" in item for item in assessment.blockers)


def test_required_option_without_value_blocks_execution_spec():
    candidate = make_candidate().model_copy(update={
        "options": [PoCOption(name="RHOSTS", required=True),
                    PoCOption(name="RPORT", required=True),
                    PoCOption(name="TARGETURI", required=True)]
    })
    with pytest.raises(ValueError, match="Required module options"):
        build_poc_execution_spec(
            candidate, make_target(), target_port=8080, supplied_options={}
        )


def test_unknown_option_is_rejected():
    assessment = assess_metasploit_compatibility(
        make_candidate(), make_target(), target_port=8080,
        supplied_options={"NOT_A_REAL_OPTION": "value"},
    )
    assert assessment.status == "incompatible"
    assert any("Unknown module options" in item for item in assessment.blockers)


def test_network_destination_cannot_be_overridden_as_an_option():
    assessment = assess_metasploit_compatibility(
        make_candidate(), make_target(), target_port=8080,
        supplied_options={"RHOSTS": "203.0.113.9"},
    )
    assert assessment.status == "incompatible"
    assert any("RHOSTS" in item for item in assessment.blockers)


def test_execution_spec_rejects_non_exploit_module_path():
    with pytest.raises(Exception):
        PoCExecutionSpec(
            candidate_id="msf:module",
            module_path="auxiliary/scanner/http/example",
            module_metadata_sha256="b" * 64,
            target_id="demo:CVE-2020-1234",
            target_fingerprint="a" * 64,
            cve_id="CVE-2020-1234",
            target_host="127.0.0.1",
            target_port=8080,
        )
