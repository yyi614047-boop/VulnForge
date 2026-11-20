"""Opt-in integration test for real Docker internal-network egress isolation."""

import json
import os
import subprocess
import time
from uuid import uuid4

import pytest

from app.environments.docker.manager import DockerLab, DockerLabParams


pytestmark = pytest.mark.skipif(
    os.getenv("VULNFORGE_DOCKER_INTEGRATION") != "1",
    reason="set VULNFORGE_DOCKER_INTEGRATION=1 to run the Docker daemon integration test",
)


def docker(*args, timeout=30):
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False,
    )


def test_internal_network_allows_lab_peer_and_blocks_external_egress():
    suffix = uuid4().hex[:10]
    network = f"vf-it-{suffix}"
    target = f"vf-target-{suffix}"
    msf = f"vf-msf-{suffix}"
    image = os.getenv("VULNFORGE_DOCKER_TEST_IMAGE", "busybox:1.36.1")

    if docker("info", timeout=30).returncode:
        pytest.skip("Docker daemon is unavailable")
    if docker("image", "inspect", image).returncode:
        pulled = docker("pull", image, timeout=180)
        if pulled.returncode:
            pytest.skip(f"Cannot obtain integration image: {pulled.stderr[-500:]}")

    created = docker("network", "create", "--internal", network)
    assert created.returncode == 0, created.stderr
    try:
        target_run = docker(
            "run", "-d", "--name", target, "--network", network, "--network-alias", "target",
            image, "sh", "-c",
            "mkdir -p /www && echo isolated-ok >/www/index.html && httpd -f -p 8080 -h /www",
        )
        assert target_run.returncode == 0, target_run.stderr
        msf_run = docker("run", "-d", "--name", msf, "--network", network, image, "sleep", "60")
        assert msf_run.returncode == 0, msf_run.stderr

        peer = None
        for _ in range(20):
            peer = docker("exec", msf, "wget", "-T", "2", "-qO-", "http://target:8080", timeout=5)
            if peer.returncode == 0:
                break
            time.sleep(0.25)
        assert peer is not None and peer.returncode == 0, peer.stderr if peer else "no peer probe result"
        assert "isolated-ok" in peer.stdout

        external = docker("exec", msf, "wget", "-T", "3", "-qO-", "http://1.1.1.1", timeout=8)
        assert external.returncode != 0, "internal lab network unexpectedly allowed external egress"

        network_info = json.loads(docker("network", "inspect", network).stdout)[0]
        assert network_info["Internal"] is True
        containers = json.loads(docker("inspect", target, msf).stdout)
        for container in containers:
            attached = container["NetworkSettings"]["Networks"]
            assert set(attached) == {network}
    finally:
        docker("rm", "-f", target, msf)
        docker("network", "rm", network)

def test_docker_lab_resolves_target_only_from_live_internal_network(tmp_path):
    suffix = uuid4().hex[:10]
    project = f"lab-it-{suffix}"
    network = f"vf-lab-{suffix}"
    msf = f"vf-msf-{suffix}"
    image = os.getenv("VULNFORGE_DOCKER_TEST_IMAGE", "busybox:1.36.1")

    if docker("info", timeout=10).returncode:
        pytest.skip("Docker daemon is unavailable")
    if docker("image", "inspect", image).returncode:
        pulled = docker("pull", image, timeout=180)
        if pulled.returncode:
            pytest.skip(f"Cannot obtain integration image: {pulled.stderr[-500:]}")

    compose = tmp_path / "compose.json"
    config = {
        "services": {
            "web": {
                "image": image,
                "ports": ["127.0.0.1:18080:8080/tcp"],
                "networks": ["isolated"],
                "command": [
                    "sh", "-c",
                    "mkdir -p /www && echo target-ok >/www/index.html && httpd -f -p 8080 -h /www",
                ],
            },
        },
        "networks": {
            "isolated": {"internal": True, "name": network},
        },
    }
    compose.write_text(json.dumps(config), encoding="utf-8")
    lab = DockerLab(compose, project)
    try:
        result = lab.run(DockerLabParams(action="up", timeout=60))
        assert result.evidence["exit_code"] == 0
        msf_run = docker("run", "-d", "--name", msf, "--network", network, image, "sleep", "60")
        assert msf_run.returncode == 0, msf_run.stderr

        endpoint = lab.resolve_target_endpoint(
            "web", 18080, network_name=network, metasploit_container=msf,
        )
        assert endpoint["target_host"].startswith("172.")
        assert endpoint["target_host"] == endpoint["target_host"]
        assert endpoint["target_port"] == 8080
        assert endpoint["target_port"] == 8080
        assert endpoint["network_internal"] is True
        assert endpoint["target_networks"] == [network]
        assert endpoint["metasploit_networks"] == [network]
        assert endpoint["compose_sha256"] == __import__("hashlib").sha256(
            json.dumps(config, sort_keys=True).encode("utf-8")
        ).hexdigest()
    finally:
        docker("rm", "-f", msf)
        try:
            lab.run(DockerLabParams(action="down", timeout=30))
        except Exception:
            pass
