"""Opt-in live Metasploit RPC test using a harmless local-only auxiliary fixture.

Run with VULNFORGE_MSF_INTEGRATION=1. The fixture only checks a local HTTP marker
and POSTs to a local test HTTP server; it does not exploit a CVE or open a shell.
"""

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from urllib.request import urlopen
from uuid import uuid4

import pytest

from app.domain.poc import PoCCandidate, PoCOption
from app.domain.plans import ExecutionPlan
from app.domain.poc_execution import LabNetworkAttestation
from app.domain.policies import ExecutionPolicy
from app.domain.reproduction import Probe, ReproductionSpec
from app.domain.targets import EnvironmentSpec, TargetSource, TargetSpec
from app.environments.docker.manager import DockerLab, DockerLabParams
from app.execution.artifacts import digest
from app.execution.metasploit_rpc import (
    DockerExecMessagePackTransport, MetasploitRpcAdapter, MetasploitRpcClient,
)
from app.workflows.reproduction.metasploit import MetasploitCandidateRunner


pytestmark = pytest.mark.skipif(
    os.getenv("VULNFORGE_MSF_INTEGRATION") != "1",
    reason="set VULNFORGE_MSF_INTEGRATION=1 to run the live Metasploit RPC integration",
)


def docker(*args, timeout=30):
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False,
    )


MODULE = r"""
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'VulnForge harmless RPC integration fixture',
      'Description' => 'Checks and triggers a local test-only HTTP marker endpoint.',
      'License' => MSF_LICENSE,
      'Author' => ['VulnForge test suite'],
      'References' => [['CVE', 'CVE-2099-0001']],
      'Actions' => [['Scan']],
      'DefaultAction' => 'Scan'
    ))
    register_options([
      Opt::RHOSTS,
      Opt::RPORT(8080)
    ])
  end

  def check
    response = send_request_cgi('method' => 'GET', 'uri' => '/health')
    return CheckCode::Unknown('No HTTP response') unless response
    return CheckCode::Vulnerable('Fixture marker is present') if
      response.code == 200 && response.body.include?('VULNFORGE_FIXTURE_VULNERABLE')
    CheckCode::Safe('Fixture marker is absent')
  end

  def run
    response = send_request_cgi('method' => 'POST', 'uri' => '/trigger')
    fail_with(Failure::UnexpectedReply, 'Fixture trigger failed') unless response && response.code == 200
    print_good('Harmless local fixture trigger completed')
  end
end
"""


SERVER = r'''
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

class Handler(BaseHTTPRequestHandler):
    def reply(self, body):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            return self.reply("VULNFORGE_FIXTURE_VULNERABLE")
        if self.path == "/verify":
            marker = Path("/tmp/vulnforge-triggered").exists()
            return self.reply("VULNFORGE_EXECUTED" if marker else "NOT_EXECUTED")
        self.send_error(404)

    def do_POST(self):
        Path("/tmp/vulnforge-triggered").write_text("executed")
        return self.reply("triggered")

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


def test_real_rpc_check_execute_and_independent_http_verification(tmp_path):
    suffix = uuid4().hex[:8]
    project = f"lab-vf-{suffix}"
    network = f"vf-msf-{suffix}"
    msf_name = f"vf-msf-rpc-{suffix}"
    target_host_port = 18080 + int(suffix[:3], 16) % 1000
    msf_image = os.getenv("VULNFORGE_MSF_TEST_IMAGE", "metasploitframework/metasploit-framework:latest")
    target_image = "python:3.11-alpine"
    password = "vf-test-" + uuid4().hex

    if docker("info", timeout=30).returncode:
        pytest.skip("Docker daemon is unavailable")
    for image in (target_image, msf_image):
        if docker("image", "inspect", image).returncode:
            pulled = docker("pull", image, timeout=600)
            if pulled.returncode:
                pytest.skip(f"Cannot obtain integration image {image}: {pulled.stderr[-500:]}")

    module_root = tmp_path / "msf-modules"
    module_path = module_root / "auxiliary" / "scanner" / "http" / "vulnforge_fixture.rb"
    module_path.parent.mkdir(parents=True)
    module_path.write_text(MODULE, encoding="utf-8")

    compose_path = tmp_path / "compose.json"
    compose = {
        "services": {
            "web": {
                "image": target_image,
                "ports": [f"127.0.0.1:{target_host_port}:8080/tcp"],
                "networks": ["isolated"],
                "command": ["python", "-c", SERVER],
            }
        },
        "networks": {"isolated": {"internal": True, "name": network}},
    }
    compose_path.write_text(json.dumps(compose), encoding="utf-8")
    lab = DockerLab(compose_path, project)
    msf_started = False
    try:
        up = lab.run(DockerLabParams(action="up", timeout=180))
        assert up.evidence["exit_code"] == 0, up.output

        started = docker(
            "run", "-d", "--name", msf_name,
            "-v", f"{module_root}:/root/.msf4/modules:ro",
            "--entrypoint", "ruby", msf_image, "msfrpcd",
            "-U", "vulnforge", "-P", password, "-a", "127.0.0.1",
            "-p", "55553", "-S", "-n", "-f",
            timeout=180,
        )
        assert started.returncode == 0, started.stderr
        msf_started = True

        lab.prepare_metasploit_container(
            network, msf_name, container_rpc_port=55553,
        )
        endpoint = lab.resolve_target_endpoint(
            "web", target_host_port, network_name=network, metasploit_container=msf_name,
        )
        attestation = LabNetworkAttestation.model_validate(endpoint)

        local_probe = None
        for _ in range(120):
            local_probe = docker(
                "exec", msf_name, "python3", "-c",
                "import socket; s=socket.create_connection(('127.0.0.1',55553),timeout=2); s.close()",
                timeout=5,
            )
            if local_probe.returncode == 0:
                break
            time.sleep(1)
        if local_probe is None or local_probe.returncode:
            logs = docker("logs", msf_name, timeout=15)
            processes = docker("exec", msf_name, "ps", "-ef", timeout=10)
            raise AssertionError(
                f"Metasploit RPC never listened inside its own container; "
                f"processes={processes.stdout[-3000:]}; "
                f"logs={logs.stdout[-4000:]}{logs.stderr[-1000:]}"
            )

        client = MetasploitRpcClient(
            DockerExecMessagePackTransport(msf_name, port=55553, timeout=10),
            username="vulnforge", password=password,
        )
        auth_probe = client.transport.call("auth.login", "vulnforge", password)
        if not isinstance(auth_probe, dict) or auth_probe.get("result") != "success" or not auth_probe.get("token"):
            safe_detail = (
                auth_probe.get("error_message") or auth_probe.get("error_class")
                if isinstance(auth_probe, dict) else type(auth_probe).__name__
            )
            safe_keys = sorted(str(key) for key in auth_probe.keys()) if isinstance(auth_probe, dict) else []
            raise AssertionError(
                f"Raw Metasploit auth.login failed: {safe_detail}; response_keys={safe_keys}"
            )
        client.token = str(auth_probe["token"])

        version = None
        last_error = None
        for _ in range(30):
            try:
                version = client.call("core.version")
                break
            except Exception as exc:
                last_error = exc
                time.sleep(1)
        if not version:
            logs = docker("logs", msf_name, timeout=15)
            state = docker("inspect", "-f", "{{.State.Status}}", msf_name, timeout=10)
            processes = docker("exec", msf_name, "ps", "-ef", timeout=10)
            raise AssertionError(
                f"Metasploit RPC did not become ready: {last_error}; "
                f"container_state={state.stdout.strip()}; "
                f"processes={processes.stdout[-3000:]}; "
                f"logs={logs.stdout[-4000:]}{logs.stderr[-1000:]}"
            )

        options = {"RHOSTS": attestation.target_host, "RPORT": str(attestation.target_port)}

        def wait_for_rpc_job(ticket, timeout=30):
            assert isinstance(ticket, dict) and isinstance(ticket.get("uuid"), str), ticket
            job_id = int(ticket["job_id"])
            job_uuid = ticket["uuid"]
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                result = client.call("module.results", job_uuid)
                if result.get("status") == "completed":
                    return result
                if result.get("status") in {"errored", "failed"}:
                    raise AssertionError(f"Metasploit fixture job failed: {result}")
                time.sleep(0.2)
            client.call("job.stop", job_id)
            raise TimeoutError(f"Metasploit fixture job {job_uuid} did not complete")

        # An auxiliary scanner is the correct harmless fixture: unlike an exploit,
        # it can complete a check/run without creating a shell session.
        module_name = "scanner/http/vulnforge_fixture"
        check_ticket = client.call("module.check", "auxiliary", module_name, options)
        check_result = wait_for_rpc_job(check_ticket)
        check_code = (check_result.get("result") or {}).get("code")
        assert str(check_code).lower() == "vulnerable", check_result

        execute_ticket = client.call("module.execute", "auxiliary", module_name, options)
        execute_result = wait_for_rpc_job(execute_ticket)
        assert execute_result.get("status") == "completed", execute_result

        verified = urlopen(f"http://127.0.0.1:{target_host_port}/verify", timeout=5).read().decode()
        assert "VULNFORGE_EXECUTED" in verified

    finally:
        if msf_started:
            docker("rm", "-f", msf_name)
        try:
            lab.run(DockerLabParams(action="down", timeout=60))
        except Exception:
            pass
