from app.integrations.metasploit.discovery import MetasploitDiscovery
from app.integrations.metasploit.models import PoCCandidate


class FakeRPC:
    def search_modules(self, query):
        assert query == "cve:CVE-2021-44228"
        return [
            {"type": "exploit", "fullname": "exploit/multi/http/log4shell_header_injection", "rank": "Excellent"},
            {"type": "auxiliary", "fullname": "auxiliary/scanner/http/log4shell"},
            {"type": "payload", "fullname": "payload/java/shell_reverse_tcp"},
        ]

    def module_info(self, kind, name):
        return {"name": "Example", "description": "Demo", "rank": "Excellent",
                "references": [{"type": "CVE", "ref": "2021-44228"}], "targets": ["Linux"]}

    def module_options(self, kind, name):
        return {"RHOSTS": {"required": True, "type": "address"}, "RPORT": {"required": True, "default": 8080}}


def test_search_cve_returns_normalized_candidates():
    candidates = MetasploitDiscovery(FakeRPC()).search_cve("cve-2021-44228")
    assert len(candidates) == 2
    assert candidates[0].candidate_id == "metasploit:exploit:multi/http/log4shell_header_injection"
    assert candidates[0].cve_ids == ["CVE-2021-44228"]


def test_search_rejects_invalid_cve():
    import pytest
    with pytest.raises(ValueError):
        MetasploitDiscovery(FakeRPC()).search_cve("not-a-cve")


def test_inspect_returns_metadata_and_options():
    discovery = MetasploitDiscovery(FakeRPC())
    candidate = PoCCandidate(candidate_id="msf:test", module_type="exploit",
        module_name="multi/http/demo", fullname="exploit/multi/http/demo")
    result = discovery.inspect(candidate)
    assert result.options["RHOSTS"]["required"] is True
    assert result.references[0]["ref"] == "2021-44228"
