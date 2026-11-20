from types import SimpleNamespace

import pytest

from app.discovery.metasploit import MetasploitDiscovery, parse_module_info, valid_module_path


def fake_runner(outputs):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        output = outputs.pop(0)
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    return run, calls


def test_discover_cve_modules_deduplicates_and_uses_no_shell():
    runner, calls = fake_runner([
        "Matching Modules\n================\n exploit/linux/http/example\n"
        " auxiliary/scanner/http/example\n exploit/linux/http/example\n"
    ])
    client = MetasploitDiscovery(runner=runner)
    assert client.discover("cve-2020-1234") == [
        "exploit/linux/http/example", "auxiliary/scanner/http/example"
    ]
    assert calls[0][0] == [
        "msfconsole", "-q", "-x", "search cve:CVE-2020-1234; exit"
    ]
    assert calls[0][1]["shell"] is False


def test_rejects_invalid_cve_before_process_execution():
    runner, calls = fake_runner([])
    client = MetasploitDiscovery(runner=runner)
    with pytest.raises(ValueError, match="CVE"):
        client.discover("CVE-2020-1234; exploit")
    assert calls == []


@pytest.mark.parametrize("module", [
    "exploit/../../etc/passwd", "auxiliary/../exploit/foo", "exploit/foo; exit",
    "payload/linux/x64/shell",
])
def test_rejects_invalid_module_paths(module):
    assert not valid_module_path(module)


def test_inspect_parses_module_metadata_and_required_options():
    output = """
Name: Example HTTP Exploit
Module: exploit/linux/http/example
Rank: Excellent
Disclosure Date: 2020-01-01
Description:
  A demonstration module for a test CVE.
Basic Options:
  Name       Current Setting  Required  Description
  ----       ---------------  --------  -----------
  RHOSTS                      yes       The target host(s)
  RPORT      8080              yes       The target port
  SSL        false             no        Negotiate SSL/TLS
Targets:
  0   Automatic
  1   Linux x86
References:
  CVE-2020-1234
"""
    candidate = parse_module_info("exploit/linux/http/example", "CVE-2020-1234", output)
    assert candidate.source == "metasploit"
    assert candidate.module_type == "exploit"
    assert candidate.name == "Example HTTP Exploit"
    assert candidate.rank == "Excellent"
    assert candidate.cve_ids == ["CVE-2020-1234"]
    assert candidate.targets == ["Automatic", "Linux x86"]
    assert [option.name for option in candidate.options] == ["RHOSTS", "RPORT", "SSL"]
    assert [option.required for option in candidate.options] == [True, True, False]
    assert candidate.inspected is True
    assert len(candidate.metadata_sha256) == 64


def test_inspect_validates_module_before_process_execution():
    runner, calls = fake_runner([])
    client = MetasploitDiscovery(runner=runner)
    with pytest.raises(ValueError, match="module"):
        client.inspect("CVE-2020-1234", "exploit/../../bad")
    assert calls == []


def test_inspect_invokes_info_command_without_shell():
    runner, calls = fake_runner(["Name: Example\nRank: Normal\n"])
    client = MetasploitDiscovery(runner=runner)
    candidate = client.inspect("CVE-2020-1234", "exploit/linux/http/example")
    assert candidate.module_path == "exploit/linux/http/example"
    assert calls[0][0][-1] == "info exploit/linux/http/example; exit"
    assert calls[0][1]["shell"] is False


def test_nonzero_exit_is_reported():
    def run(argv, **kwargs):
        return SimpleNamespace(returncode=2, stdout="", stderr="database unavailable")

    with pytest.raises(RuntimeError, match="database unavailable"):
        MetasploitDiscovery(runner=run).discover("CVE-2020-1234")


def test_candidate_metadata_hash_changes_with_inspected_output():
    one = parse_module_info("exploit/linux/http/example", "CVE-2020-1234", "Name: A")
    two = parse_module_info("exploit/linux/http/example", "CVE-2020-1234", "Name: B")
    assert one.metadata_sha256 != two.metadata_sha256


def test_cve_mentioned_in_description_is_not_a_module_reference():
    candidate = parse_module_info(
        "exploit/linux/http/demo",
        "CVE-2020-1234",
        "Name: Demo\nDescription:\n  This advisory discusses CVE-2020-1234.\nReferences:\n  URL: https://example.test/",
    )
    assert candidate.discovery_query_cve == "CVE-2020-1234"
    assert candidate.cve_ids == []
