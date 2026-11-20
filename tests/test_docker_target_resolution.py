import json

import pytest

from app.environments.docker.manager import DockerLab


class Result:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr


class FakeRunner:
    def __init__(self, *, target_network="lab-shared", msf_network="lab-shared"):
        self.target_network = target_network
        self.msf_network = msf_network

    def __call__(self, argv, **kwargs):
        if argv[:3] == ["docker", "compose", "--project-name"]:
            return Result("target-container-id\n")
        if argv[:2] == ["docker", "inspect"] and argv[2] == "target-container-id":
            row = {
                "State": {"Running": True},
                "NetworkSettings": {
                    "Ports": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"}]},
                    "Networks": {self.target_network: {"IPAddress": "172.20.0.2"}},
                },
            }
            return Result(json.dumps([row]))
        if argv[:2] == ["docker", "inspect"] and argv[2] == "msf":
            row = {
                "State": {"Running": True},
                "NetworkSettings": {
                    "Networks": {self.msf_network: {"IPAddress": "172.20.0.3"}},
                },
            }
            return Result(json.dumps([row]))
        raise AssertionError(f"Unexpected command: {argv}")


def make_lab(tmp_path, runner):
    compose = tmp_path / "compose.json"
    compose.write_text(json.dumps({
        "services": {
            "app": {
                "image": "example/app:1",
                "ports": ["127.0.0.1:18080:8080/tcp"],
            }
        }
    }), encoding="utf-8")
    return DockerLab(compose, "lab-demo", runner=runner)


def test_resolves_private_endpoint_only_on_explicit_shared_network(tmp_path):
    lab = make_lab(tmp_path, FakeRunner())
    endpoint = lab.resolve_target_endpoint(
        "app", 18080, network_name="lab-shared", metasploit_container="msf",
    )
    assert endpoint["host"] == "172.20.0.2"
    assert endpoint["port"] == 8080
    assert endpoint["metasploit_network_ip"] == "172.20.0.3"


def test_rejects_network_not_shared_with_metasploit(tmp_path):
    lab = make_lab(tmp_path, FakeRunner(msf_network="management"))
    with pytest.raises(ValueError, match="not attached"):
        lab.resolve_target_endpoint(
            "app", 18080, network_name="lab-shared", metasploit_container="msf",
        )


def test_rejects_non_loopback_published_port(tmp_path):
    lab = make_lab(tmp_path, FakeRunner())
    with pytest.raises(ValueError, match="published on loopback"):
        lab.resolve_target_endpoint(
            "app", 8080, network_name="lab-shared", metasploit_container="msf",
        )
