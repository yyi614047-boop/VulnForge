"""Opt-in integration test for real Docker internal-network egress isolation."""

import json
import os
import subprocess
import time
from uuid import uuid4

import pytest


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

    if docker("info", timeout=10).returncode:
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
