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
from app.domain.plans import ExecutionPlan, ExecutionStep
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
class MetasploitModule < Msf::Exploit::Remote
  include Msf::Exploit::Remote::HttpClient
  Rank = ExcellentRanking

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'VulnForge harmless RPC integration fixture',
      'Description' => 'Checks and triggers a local test-only HTTP marker endpoint.',
      'License' => MSF_LICENSE,
      'Author' => ['VulnForge test suite'],
      'References' => [['CVE', 'CVE-2099-0001']],
      'Platform' => 'linux',
      'Arch' => ARCH_CMD,
      'Targets' => [['Automatic', {}]],
      'DefaultTarget' => 0,
      'Privileged' => false
    ))
    register_options([Opt::RHOSTS, Opt::RPORT(8080)])
  end

  def check
    response = send_request_cgi('method' => 'GET', 'uri' => '/health')
    return Msf::Exploit::CheckCode::Unknown('No HTTP response') unless response
    return Msf::Exploit::CheckCode::Vulnerable('Fixture marker is present') if
      response.code == 200 && response.body.include?('VULNFORGE_FIXTURE_VULNERABLE')
    Msf::Exploit::CheckCode::Safe('Fixture marker is absent')
  end

  def exploit
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
        version = client.call("core.version")
        assert version and "version" in version

        # Exercise the production adapter and candidate runner, not raw RPC:
        # policy binding, Check gating, Execute, and independent HTTP evidence.
        target_id = "demo:CVE-2099-0001"
        target = TargetSpec(
            target_id=target_id, title="Harmless local RPC fixture",
            product="VulnForge test service", vulnerability_id="CVE-2099-0001",
            affected_versions=["test"],
            sources=[TargetSource(source_id="compose", path="compose.json",
                                  sha256=hashlib.sha256(compose_path.read_bytes()).hexdigest())],
            environment=EnvironmentSpec(compose_file="compose.json", services=["web"],
                                        published_ports={"web": [target_host_port]}),
        )
        reproduction = ReproductionSpec(
            id=target_id, title="Harmless local HTTP marker fixture",
            product="VulnForge test service", affected_versions=["test"],
            dependencies=["Docker"], prerequisites=["ephemeral Docker internal network"],
            sources=["compose.json"], environment="compose.json", service="web",
            port=target_host_port,
            health=Probe(id="health", path="/health", body_contains="VULNFORGE_FIXTURE_VULNERABLE"),
            reproduction=[Probe(id="marker", path="/health", body_contains="VULNFORGE_FIXTURE_VULNERABLE")],
            verification_requests=[Probe(id="independent", path="/verify", body_contains="VULNFORGE_EXECUTED")],
            purpose="demo",
        )
        candidate = PoCCandidate(
            candidate_id="metasploit:exploit/multi/http/vulnforge_fixture",
            source="metasploit", cve_ids=["CVE-2099-0001"],
            discovery_query_cve="CVE-2099-0001", module_type="exploit",
            module_path="exploit/multi/http/vulnforge_fixture",
            name="VulnForge harmless RPC integration fixture",
            options=[PoCOption(name="RHOSTS", required=True), PoCOption(name="RPORT", required=True)],
            check_supported=True,
            metadata_sha256=hashlib.sha256(MODULE.encode("utf-8")).hexdigest(),
            inspected=True,
        )
        candidate_rows = [candidate.model_dump(mode="json")]
        candidates_hash = digest(json.dumps(candidate_rows, sort_keys=True))
        policy = ExecutionPolicy(
            policy_id="live-rpc-fixture",
            approved_target_hashes={target_id: target.fingerprint()},
            approved_reproduction_hashes={target_id: reproduction.fingerprint()},
            allowed_actions={"http"}, allowed_services={"web"},
            allowed_ports={target_host_port},
            approved_poc_candidates={candidate.candidate_id: candidate.metadata_sha256},
            approved_lab_networks={target_id: network},
            allow_metasploit_check=True, allow_metasploit_execute=True,
            allow_unknown_poc_compatibility=True,
        )
        bundle = {"poc_candidates": candidate_rows,
                  "poc_candidates_hash": candidates_hash,
                  "compose_hash": attestation.compose_sha256}
        plan = ExecutionPlan(
            plan_id="live-rpc-fixture-plan", target_id=target_id,
            policy_id=policy.policy_id,
            rationale="Exercise the production Metasploit candidate runner against a local-only fixture.",
            selected_poc_candidate_id=candidate.candidate_id,
            poc_selection_rationale="Test fixture selected explicitly.",
            input_fingerprints={"poc_candidates": candidates_hash,
                                "reproduction": reproduction.fingerprint(),
                                "compose": attestation.compose_sha256},
            steps=[ExecutionStep(step_id="fixture-http", phase="reproduce",
                                 action="http", target_id=target_id,
                                 rationale="Harmless local fixture")],
        )
        adapter = MetasploitRpcAdapter(client, poll_interval=0.2)
        result = MetasploitCandidateRunner(adapter).run(
            plan=plan, bundle=bundle, target=target, reproduction=reproduction,
            policy=policy, target_attestation=attestation,
        )
        assert result["status"] == "executed", result
        assert result["check"]["result_code"] == "vulnerable", result
        assert result["execution"]["status"] == "completed", result

        verified = urlopen(f"http://127.0.0.1:{target_host_port}/verify", timeout=5).read().decode()
        assert "VULNFORGE_EXECUTED" in verified, verified

    finally:
        if msf_started:
            docker("rm", "-f", msf_name)
        try:
            lab.run(DockerLabParams(action="down", timeout=60))
        except Exception:
            pass
