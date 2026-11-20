import pytest

from app.integrations.metasploit.models import ModuleMetadata, PoCCandidate
from app.integrations.metasploit.options import prepare_module_options


def candidate():
    return PoCCandidate(
        candidate_id="metasploit:exploit:multi/http/demo",
        module_type="exploit",
        module_name="multi/http/demo",
        fullname="exploit/multi/http/demo",
    )


def metadata(options):
    return ModuleMetadata(
        module_type="exploit",
        module_name="multi/http/demo",
        options=options,
    )


def test_prepares_target_host_port_and_defaults():
    result = prepare_module_options(
        candidate(),
        metadata({
            "RHOSTS": {"required": True},
            "RPORT": {"required": True, "default": 80},
            "TARGETURI": {"required": True, "default": "/"},
            "SSL": {"required": False, "default": False},
        }),
        target_host="127.0.0.1",
        target_port=8080,
    )
    assert result.ready
    assert result.options == {
        "RHOSTS": "127.0.0.1",
        "RPORT": 8080,
        "TARGETURI": "/",
        "SSL": False,
    }
    assert result.missing_required == []


def test_reports_required_options_without_guessing():
    result = prepare_module_options(
        candidate(),
        metadata({
            "RHOSTS": {"required": True},
            "RPORT": {"required": True},
            "TARGETURI": {"required": True},
        }),
        target_host="127.0.0.1",
        target_port=8080,
    )
    assert not result.ready
    assert result.missing_required == ["TARGETURI"]


def test_rejects_target_binding_override():
    with pytest.raises(ValueError, match="Target-bound option"):
        prepare_module_options(
            candidate(),
            metadata({"RHOSTS": {"required": True}, "RPORT": {"required": True}, "TARGETURI": {}}),
            target_host="127.0.0.1",
            target_port=8080,
            overrides={"RHOSTS": "example.com"},
        )


def test_rejects_undeclared_override():
    with pytest.raises(ValueError, match="not a declared"):
        prepare_module_options(
            candidate(),
            metadata({"RHOSTS": {"required": True}, "RPORT": {"required": True}}),
            target_host="127.0.0.1",
            target_port=8080,
            overrides={"UNKNOWN": "x"},
        )


def test_rejects_invalid_host_and_port():
    with pytest.raises(ValueError):
        prepare_module_options(candidate(), metadata({}), target_host="bad host", target_port=8080)
    with pytest.raises(ValueError):
        prepare_module_options(candidate(), metadata({}), target_host="127.0.0.1", target_port=70000)
