"""Policy-gated Metasploit MessagePack RPC adapter.

The adapter accepts only target-bound PoCExecutionSpec values and requires
an exact candidate metadata approval in ExecutionPolicy. It never exposes a
general-purpose RPC or console passthrough.
"""
from __future__ import annotations

import ipaddress
import os
import re
import ssl
import time
from typing import Callable
from urllib.error import URLError
from urllib.request import Request, urlopen

from app.domain.poc import PoCCandidate
from app.domain.poc_execution import (
    MetasploitCheckOutcome,
    MetasploitExecutionOutcome,
    PoCExecutionSpec,
)
from app.domain.policies import ExecutionPolicy
from app.domain.targets import TargetSpec


class MetasploitRpcError(RuntimeError):
    pass


class MessagePackHttpTransport:
    """Small HTTP MessagePack transport for the Metasploit Framework RPC API."""

    def __init__(self, *, host: str = "127.0.0.1", port: int = 55553,
                 ssl_enabled: bool = True, endpoint: str = "/api/",
                 timeout: int = 15, opener: Callable = urlopen):
        try:
            address = ipaddress.ip_address(host)
            loopback = address.is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback:
            raise ValueError("Metasploit RPC server must be bound to loopback in V1")
        if not 1 <= port <= 65535 or not 1 <= timeout <= 120:
            raise ValueError("Invalid Metasploit RPC port or timeout")
        if not endpoint.startswith("/") or ".." in endpoint.split("/"):
            raise ValueError("RPC endpoint must be an absolute, traversal-free path")
        self.host, self.port = host, port
        self.ssl_enabled, self.endpoint = ssl_enabled, endpoint
        self.timeout, self.opener = timeout, opener

    def call(self, method: str, *params):
        try:
            import msgpack
        except ImportError as exc:
            raise RuntimeError(
                "MessagePack support is optional; install with pip install -e '.[metasploit]'"
            ) from exc
        scheme = "https" if self.ssl_enabled else "http"
        body = msgpack.packb([method, *params], use_bin_type=True)
        request = Request(
            f"{scheme}://{self.host}:{self.port}{self.endpoint}",
            data=body,
            headers={"Content-Type": "binary/message-pack", "Accept": "binary/message-pack"},
            method="POST",
        )
        context = ssl.create_default_context() if self.ssl_enabled else None
        try:
            with self.opener(request, timeout=self.timeout, context=context) as response:
                payload = msgpack.unpackb(response.read(), raw=False, strict_map_key=False)
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            raise MetasploitRpcError(f"Metasploit RPC transport failed: {exc}") from exc
        if isinstance(payload, dict) and payload.get("error"):
            raise MetasploitRpcError(str(payload["error"]))
        return payload


class MetasploitRpcClient:
    """Authenticated RPC client; only named API methods are callable."""

    def __init__(self, transport, *, username: str, password: str):
        if not username or not password:
            raise ValueError("Metasploit RPC username and password are required")
        self.transport = transport
        self.username, self.password = username, password
        self.token: str | None = None

    @classmethod
    def from_env(cls, *, transport=None):
        if transport is None:
            transport = MessagePackHttpTransport(
                host=os.getenv("MSFRPC_HOST", "127.0.0.1"),
                port=int(os.getenv("MSFRPC_PORT", "55553")),
                ssl_enabled=os.getenv("MSFRPC_SSL", "true").lower() in {"1", "true", "yes"},
                endpoint=os.getenv("MSFRPC_URI", "/api/"),
            )
        return cls(
            transport,
            username=os.environ.get("MSFRPC_USER", ""),
            password=os.environ.get("MSFRPC_PASS", ""),
        )

    def call(self, method: str, *params):
        if not re.fullmatch(r"[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*", method):
            raise ValueError("Invalid Metasploit RPC method name")
        if method == "auth.login":
            raise ValueError("Authentication is managed internally")
        if self.token is None:
            auth = self.transport.call("auth.login", self.username, self.password)
            if not isinstance(auth, dict) or auth.get("result") != "success" or not auth.get("token"):
                raise MetasploitRpcError("Metasploit RPC authentication failed")
            self.token = str(auth["token"])
        response = self.transport.call(method, self.token, *params)
        if isinstance(response, dict) and response.get("error"):
            raise MetasploitRpcError(str(response["error"]))
        return response


class MetasploitRpcAdapter:
    """Run module.check and module.execute only for explicitly approved lab candidates."""

    def __init__(self, client: MetasploitRpcClient, *, poll_interval: float = 0.5):
        if not 0.1 <= poll_interval <= 5:
            raise ValueError("poll_interval must be between 0.1 and 5 seconds")
        self.client = client
        self.poll_interval = poll_interval
        self._validated_checks: dict[str, tuple[str, str, str]] = {}

    @staticmethod
    def _module_name(spec: PoCExecutionSpec) -> str:
        return spec.module_path.removeprefix("exploit/")

    @staticmethod
    def _validate_binding(spec: PoCExecutionSpec, candidate: PoCCandidate,
                          target: TargetSpec, policy: ExecutionPolicy, action: str):
        if spec.candidate_id != candidate.candidate_id:
            raise PermissionError("Execution spec candidate binding does not match the inspected candidate")
        if spec.module_path != candidate.module_path or spec.module_metadata_sha256 != candidate.metadata_sha256:
            raise PermissionError("Metasploit module metadata changed after candidate inspection")
        if not candidate.inspected or candidate.source != "metasploit" or candidate.module_type != "exploit":
            raise PermissionError("Only inspected Metasploit exploit modules may be submitted")
        if not target.vulnerability_id or spec.cve_id != target.vulnerability_id:
            raise PermissionError("Execution spec CVE does not match the selected target")
        if spec.cve_id.upper() not in {value.upper() for value in candidate.cve_ids}:
            raise PermissionError("The inspected module metadata does not reference the target CVE")
        if spec.target_id != target.target_id or spec.target_fingerprint != target.fingerprint():
            raise PermissionError("Execution spec target binding is stale or mismatched")
        policy.authorize_target(target)
        if spec.target_host not in policy.allowed_hosts:
            raise PermissionError("Target host is not explicitly allowed by the active policy")
        if spec.target_port not in policy.allowed_ports:
            raise PermissionError("Target port is not explicitly allowed by the active policy")
        declared_ports = {port for ports in target.environment.published_ports.values() for port in ports}
        if spec.target_port not in declared_ports:
            raise PermissionError("Target port is not declared by the selected lab environment")
        options = {item.name: item for item in candidate.options}
        if set(spec.options) - set(options):
            raise PermissionError("Execution spec contains options not declared by the inspected module")
        for item in candidate.options:
            if item.required and not (spec.options.get(item.name) or item.current_value):
                raise PermissionError(f"Required Metasploit option {item.name} is missing")
        for name in ("RHOSTS", "RHOST"):
            if name in options and spec.options.get(name) != spec.target_host:
                raise PermissionError(f"{name} must be bound to the approved target host")
        if "RPORT" in options and spec.options.get("RPORT") != str(spec.target_port):
            raise PermissionError("RPORT must be bound to the approved target port")
        for name in ("LHOST", "SRVHOST"):
            if name in spec.options and spec.options[name] not in policy.allowed_hosts:
                raise PermissionError(f"{name} must use an explicitly allowed loopback host")
        for name in ("LPORT", "SRVPORT"):
            if name in spec.options:
                try:
                    callback_port = int(spec.options[name])
                except ValueError as exc:
                    raise PermissionError(f"{name} must be a valid port") from exc
                if callback_port not in policy.allowed_ports:
                    raise PermissionError(f"{name} must use an explicitly allowed port")
        if "PAYLOAD" in spec.options and not policy.allow_metasploit_payloads:
            raise PermissionError("Metasploit payload selection is disabled by execution policy")
        policy.authorize_metasploit_candidate(
            candidate.candidate_id, candidate.metadata_sha256, action=action,
            compatibility_status=spec.compatibility_status,
        )

    def _wait_for_result(self, job_id: int, job_uuid: str, timeout: int) -> dict:
        if not 1 <= timeout <= 300:
            raise ValueError("Metasploit job timeout must be between 1 and 300 seconds")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.client.call("module.results", job_uuid)
            if not isinstance(result, dict):
                raise MetasploitRpcError("Metasploit returned a malformed module result")
            status = str(result.get("status", "")).lower()
            if status == "completed":
                return result
            if status in {"failed", "error"}:
                raise MetasploitRpcError(f"Metasploit module job {status}: {result}")
            time.sleep(self.poll_interval)
        try:
            self.client.call("job.stop", job_id)
        except Exception:
            pass
        raise TimeoutError(f"Metasploit module job {job_uuid} exceeded {timeout} seconds")

    def check(self, spec: PoCExecutionSpec, candidate: PoCCandidate,
              target: TargetSpec, policy: ExecutionPolicy, *, timeout: int = 60) -> MetasploitCheckOutcome:
        self._validate_binding(spec, candidate, target, policy, "check")
        if candidate.check_supported is not True:
            raise PermissionError("Module metadata does not explicitly confirm Check support")
        response = self.client.call("module.check", "exploit", self._module_name(spec), spec.options)
        job_id, job_uuid = self._ticket(response)
        completed = self._wait_for_result(job_id, job_uuid, timeout)
        result = completed.get("result") or {}
        code = str(result.get("code", "unknown")).lower() if isinstance(result, dict) else "unknown"
        known_codes = {"vulnerable", "safe", "detected", "appears", "unknown", "not_vulnerable", "unsupported"}
        if code not in known_codes:
            code = "unknown"
        outcome = MetasploitCheckOutcome(
            candidate_id=candidate.candidate_id,
            module_metadata_sha256=candidate.metadata_sha256,
            target_id=target.target_id,
            target_fingerprint=target.fingerprint(),
            job_uuid=job_uuid,
            status="completed",
            result_code=code,
            result=result if isinstance(result, dict) else {"value": str(result)},
        )
        if code == "vulnerable":
            self._validated_checks[job_uuid] = (
                candidate.candidate_id, target.target_id, candidate.metadata_sha256
            )
        return outcome

    def execute(self, spec: PoCExecutionSpec, candidate: PoCCandidate,
                target: TargetSpec, policy: ExecutionPolicy,
                check_outcome: MetasploitCheckOutcome, *, timeout: int = 120) -> MetasploitExecutionOutcome:
        self._validate_binding(spec, candidate, target, policy, "execute")
        binding = self._validated_checks.get(check_outcome.job_uuid)
        expected = (candidate.candidate_id, target.target_id, candidate.metadata_sha256)
        if (binding != expected or check_outcome.result_code != "vulnerable"
                or check_outcome.status != "completed"
                or check_outcome.target_fingerprint != target.fingerprint()
                or check_outcome.candidate_id != candidate.candidate_id
                or check_outcome.module_metadata_sha256 != candidate.metadata_sha256):
            raise PermissionError("Exploit execution requires a completed vulnerable Check from this adapter instance")
        before_sessions = self.client.call("session.list") or {}
        response = self.client.call("module.execute", "exploit", self._module_name(spec), spec.options)
        job_id, job_uuid = self._ticket(response)
        stopped = []
        try:
            completed = self._wait_for_result(job_id, job_uuid, timeout)
        finally:
            # Always attempt to stop only sessions created by this module for
            # this exact target during this invocation, including timeout paths.
            try:
                after_sessions = self.client.call("session.list") or {}
                stopped = self._stop_new_target_sessions(before_sessions, after_sessions, spec)
            except Exception:
                stopped = []
        result = completed.get("result") or {}
        return MetasploitExecutionOutcome(
            candidate_id=candidate.candidate_id,
            target_id=target.target_id,
            job_uuid=job_uuid,
            status="completed",
            result=result if isinstance(result, dict) else {"value": str(result)},
            cleaned_session_ids=stopped,
        )

    @staticmethod
    def _ticket(response) -> tuple[int, str]:
        if not isinstance(response, dict) or not isinstance(response.get("uuid"), str):
            raise MetasploitRpcError("Metasploit did not return a valid asynchronous job ticket")
        try:
            job_id = int(response["job_id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise MetasploitRpcError("Metasploit job ticket has no valid job_id") from exc
        return job_id, response["uuid"]

    def _stop_new_target_sessions(self, before: dict, after: dict,
                                  spec: PoCExecutionSpec) -> list[int]:
        stopped = []
        module_name = self._module_name(spec)
        for raw_id, session in after.items():
            if str(raw_id) in {str(key) for key in before} or not isinstance(session, dict):
                continue
            host = session.get("target_host") or session.get("session_host")
            via = str(session.get("via_exploit", "")).removeprefix("exploit/")
            if host != spec.target_host or via != module_name:
                continue
            try:
                session_id = int(raw_id)
                self.client.call("session.stop", session_id)
                stopped.append(session_id)
            except (TypeError, ValueError, MetasploitRpcError):
                continue
        return stopped
