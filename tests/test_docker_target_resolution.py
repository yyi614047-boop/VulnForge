import json

import pytest

from app.environments.docker.manager import DockerLab, load_compose


class Result:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr


class FakeRunner:
    def __init__(self, *, target_network="lab-shared", msf_network="lab-shared",
                 internal=True, target_extra_network=False, msf_extra_network=False):
        self.target_network = target_network
        self.msf_network = msf_network
        self.internal = internal
        self.target_extra_network = target_extra_network
        self.msf_extra_network = msf_extra_network

    def __call__(self, argv, **kwargs):
        if argv[:4] == ["docker", "network", "inspect", "lab-shared"]:
            return Result(json.dumps([{
                "Name": "lab-shared", "Id": "a" * 64, "Internal": self.internal,
            }]))
        if argv[:3] == ["docker", "compose", "--project-name"]:
            return Result("target-container-id\n")
        if argv[:2] == ["docker", "inspect"] and argv[2] == "target-container-id":
            networks = {
                self.target_network: {"NetworkID": "a" * 64, "IPAddress": "172.20.0.2"},
            }
            if self.target_extra_network:
                networks["bridge"] = {"NetworkID": "b" * 64, "IPAddress": "172.17.0.2"}
            row = {
                "Id": "c" * 64,
                "State": {"Running": True},
                "NetworkSettings": {
                    "Ports": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"}]},
                    "Networks": networks,
                },
            }
            return Result(json.dumps([row]))
        if argv[:2] == ["docker", "inspect"] and argv[2] == "msf":
            networks = {
                self.msf_network: {"NetworkID": "a" * 64, "IPAddress": "172.20.0.3"},
            }
            if self.msf_extra_network:
                networks["bridge"] = {"NetworkID": "b" * 64, "IPAddress": "172.17.0.3"}
            row = {
                "Id": "d" * 64,
                "State": {"Running": True},
                "NetworkSettings": {"Networks": networks},
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
                "networks": ["isolated"],
            }
        },
        "networks": {
            "isolated": {"internal": True, "name": "lab-shared"},
        },
    }), encoding="utf-8")
    return DockerLab(compose, "lab-demo", runner=runner)


def test_resolves_private_endpoint_only_on_explicit_internal_network(tmp_path):
    lab = make_lab(tmp_path, FakeRunner())
    endpoint = lab.resolve_target_endpoint(
        "app", 18080, network_name="lab-shared", metasploit_container="msf",
    )
    assert endpoint["host"] == "172.20.0.2"
    assert endpoint["port"] == 8080
    assert endpoint["metasploit_host"] == "172.20.0.3"
    assert endpoint["network_internal"] is True
    assert endpoint["network_id"] == "a" * 64
    assert endpoint["target_networks"] == ["lab-shared"]
    assert endpoint["metasploit_networks"] == ["lab-shared"]


def test_rejects_network_not_shared_with_metasploit(tmp_path):
    lab = make_lab(tmp_path, FakeRunner(msf_network="management"))
    with pytest.raises(ValueError, match="only to the approved internal network"):
        lab.resolve_target_endpoint(
            "app", 18080, network_name="lab-shared", metasploit_container="msf",
        )


def test_rejects_non_internal_docker_network(tmp_path):
    lab = make_lab(tmp_path, FakeRunner(internal=False))
    with pytest.raises(ValueError, match="not the approved internal network"):
        lab.resolve_target_endpoint(
            "app", 18080, network_name="lab-shared", metasploit_container="msf",
        )


@pytest.mark.parametrize("extra", ["target", "metasploit"])
def test_rejects_extra_network_that_could_bypass_egress_isolation(tmp_path, extra):
    lab = make_lab(tmp_path, FakeRunner(
        target_extra_network=extra == "target",
        msf_extra_network=extra == "metasploit",
    ))
    with pytest.raises(ValueError, match="attached only"):
        lab.resolve_target_endpoint(
            "app", 18080, network_name="lab-shared", metasploit_container="msf",
        )


def test_rejects_non_loopback_published_port(tmp_path):
    lab = make_lab(tmp_path, FakeRunner())
    with pytest.raises(ValueError, match="published on loopback"):
        lab.resolve_target_endpoint(
            "app", 8080, network_name="lab-shared", metasploit_container="msf",
        )

def test_compose_loader_rejects_non_internal_network_definition(tmp_path):
    compose = tmp_path / "compose.yml"
    compose.write_text(json.dumps({
        "services": {"app": {"image": "example/app:1", "networks": ["lab"]}},
        "networks": {"lab": {"internal": False}},
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="explicitly internal"):
        load_compose(compose)
