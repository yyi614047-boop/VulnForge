"""Explicitly approved, check-only Metasploit adapter."""
import hashlib
import ipaddress
import json
import time
from typing import Literal

from pydantic import Field

from app.domain.targets import DomainModel
from app.integrations.metasploit.models import PoCCandidate
from app.integrations.metasploit.options import PreparedModuleOptions


class MetasploitCheckApproval(DomainModel):
    """Out-of-band approval binding one module, target, port and exact option set."""
    policy_id: str = Field(min_length=1, max_length=128)
    candidate_id: str = Field(min_length=1, max_length=256)
    target_id: str = Field(min_length=1, max_length=200)
    target_host: str
    target_port: int = Field(ge=1, le=65535)
    options_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    max_wait_seconds: int = Field(default=60, ge=1, le=300)


def options_fingerprint(options: dict) -> str:
    payload = json.dumps(options, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class MetasploitCheckAdapter:
    """Runs module.check only; this adapter intentionally has no exploit operation."""

    def __init__(self, client, *, poll_interval: float = 0.5, clock=None, sleeper=None):
        if not 0.05 <= poll_interval <= 5:
            raise ValueError("poll_interval must be between 0.05 and 5 seconds")
        self.client = client
        self.poll_interval = poll_interval
        self.clock = clock or time.monotonic
        self.sleeper = sleeper or time.sleep

    @staticmethod
    def _validate_binding(candidate, prepared, target_id, approval):
        try:
            address = ipaddress.ip_address(prepared.target_host)
        except ValueError as exc:
            raise PermissionError("Metasploit check target must be an explicit IP address") from exc
        if address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local:
            raise PermissionError("Metasploit check is restricted to a private, non-loopback IPv4 lab target")
        if not prepared.ready:
            raise PermissionError("Required Metasploit module options are missing")
        if candidate.module_type not in {"exploit", "auxiliary"}:
            raise PermissionError("Only exploit and auxiliary module checks are supported")
        if candidate.candidate_id != prepared.candidate_id:
            raise PermissionError("Prepared options belong to another Metasploit candidate")
        if (approval.candidate_id != candidate.candidate_id
                or approval.target_id != target_id
                or approval.target_host != prepared.target_host
                or approval.target_port != prepared.target_port):
            raise PermissionError("Metasploit check approval does not match the selected candidate and target")
        if approval.options_sha256 != options_fingerprint(prepared.options):
            raise PermissionError("Prepared options changed after explicit approval")
        target_hosts = [prepared.options.get(key) for key in ("RHOSTS", "RHOST") if key in prepared.options]
        target_ports = [prepared.options.get(key) for key in ("RPORT", "RPORTS") if key in prepared.options]
        if not target_hosts or any(str(value) != prepared.target_host for value in target_hosts):
            raise PermissionError("Prepared module options are not bound to the approved target host")
        if not target_ports or any(str(value) != str(prepared.target_port) for value in target_ports):
            raise PermissionError("Prepared module options are not bound to the approved target port")

    def check(self, candidate: PoCCandidate, prepared: PreparedModuleOptions, *,
              target_id: str, approval: MetasploitCheckApproval) -> dict:
        """Submit an approved non-exploit check and poll its bounded result."""
        self._validate_binding(candidate, prepared, target_id, approval)
        submitted = self.client.module_check(
            candidate.module_type, candidate.module_name, dict(prepared.options)
        )
        job_uuid = submitted["uuid"]
        deadline = self.clock() + approval.max_wait_seconds
        while True:
            result = self.client.module_results(job_uuid)
            status = str(result.get("status", "")).lower()
            if status in {"completed", "errored", "failed"}:
                payload = result.get("result") if isinstance(result.get("result"), dict) else {}
                code = payload.get("code") or payload.get("status") or "unknown"
                return {
                    "candidate_id": candidate.candidate_id,
                    "target_id": target_id,
                    "target_host": prepared.target_host,
                    "target_port": prepared.target_port,
                    "policy_id": approval.policy_id,
                    "job_uuid": job_uuid,
                    "job_status": status,
                    "check_code": str(code).lower(),
                    "message": str(payload.get("message") or result.get("error") or "")[:2000],
                    "details": payload.get("details") if isinstance(payload.get("details"), dict) else {},
                    "exploit_executed": False,
                }
            if status not in {"running", "waiting", "queued", ""}:
                raise RuntimeError(f"Unexpected Metasploit check job status: {status}")
            remaining = deadline - self.clock()
            if remaining <= 0:
                return {
                    "candidate_id": candidate.candidate_id,
                    "target_id": target_id,
                    "target_host": prepared.target_host,
                    "target_port": prepared.target_port,
                    "policy_id": approval.policy_id,
                    "job_uuid": job_uuid,
                    "job_status": "timeout",
                    "check_code": "unknown",
                    "message": "Metasploit check did not finish within the approved time budget",
                    "details": {},
                    "exploit_executed": False,
                }
            self.sleeper(min(self.poll_interval, remaining))
