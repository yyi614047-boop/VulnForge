"""Detect and start the local Docker engine with bounded readiness polling."""
import json
import os
import platform
import subprocess
import time
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from app.tools.registry import ToolOutput, ToolRegistry


class EngineParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start: bool = True
    timeout: int = Field(default=120, ge=1, le=300)


class DockerEngine:
    def __init__(self, *, runner=None, launcher=None, clock=None, sleeper=None, system=None):
        self.runner = runner or subprocess.run
        self.launcher = launcher or subprocess.Popen
        self.clock = clock or time.monotonic
        self.sleeper = sleeper or time.sleep
        self.system = system or platform.system()

    def registry(self):
        registry = ToolRegistry()
        registry.register("ensure_docker_engine", EngineParams, self.ensure)
        return registry

    def ensure(self, params: EngineParams):
        deadline = self.clock() + params.timeout
        evidence = {"ready": False, "start_attempted": False, "status": "unavailable"}

        def finish(status, error=None):
            evidence["status"] = status
            if error:
                evidence["error"] = str(error)[-4096:]
            return ToolOutput(json.dumps(evidence), evidence)

        def run(command):
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, params.timeout)
            return self.runner(command, capture_output=True, text=True, timeout=min(10, remaining))

        def probe():
            result = run(["docker", "info", "--format", "{{json .}}"])
            if result.returncode != 0:
                evidence["last_probe_error"] = (result.stderr or result.stdout)[-4096:]
                return False
            try:
                info = json.loads(result.stdout)
            except (ValueError, TypeError):
                info = None
            if not isinstance(info, dict) or not info.get("ServerVersion"):
                server_errors = info.get("ServerErrors") if isinstance(info, dict) else None
                evidence["last_probe_error"] = (result.stderr or
                    ("\n".join(map(str, server_errors)) if isinstance(server_errors, list) else "") or
                    "Docker returned no server version")[-4096:]
                return False
            evidence.update(ready=True, server_version=info["ServerVersion"])
            return True

        try:
            try:
                if probe():
                    return finish("ready")
            except subprocess.TimeoutExpired as exc:
                evidence["last_probe_error"] = str(exc)
            if not params.start:
                return finish("unavailable")
            # Never start a local daemon to repair an explicitly remote endpoint.
            endpoint = os.environ.get("DOCKER_HOST") if not os.environ.get("DOCKER_CONTEXT") else None
            if not endpoint:
                context = run(["docker", "context", "inspect"])
                if context.returncode:
                    return finish("context_error", context.stderr)
                endpoint = json.loads(context.stdout)[0]["Endpoints"]["docker"]["Host"]
            if not endpoint.startswith(("npipe://", "unix://")):
                return finish("remote_endpoint", "Selected Docker endpoint is remote; local startup cannot repair it")
            if self.system == "Windows":
                executable = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Docker/Docker/Docker Desktop.exe"
                if not executable.is_file():
                    return finish("not_installed", "Docker Desktop executable was not found")
                startup = subprocess.STARTUPINFO()
                startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startup.wShowWindow = 0
                evidence["start_attempted"] = True
                self.launcher([str(executable)], startupinfo=startup,
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif self.system == "Darwin":
                evidence["start_attempted"] = True
                result = run(["open", "-g", "-a", "Docker"])
                if result.returncode:
                    return finish("start_failed", result.stderr)
            elif self.system == "Linux":
                evidence["start_attempted"] = True
                result = run(["systemctl", "--no-ask-password", "start", "docker"])
                if result.returncode:
                    return finish("start_failed", result.stderr)
            else:
                return finish("unsupported_platform", self.system)
            while self.clock() < deadline:
                try:
                    if probe():
                        return finish("ready")
                except subprocess.TimeoutExpired as exc:
                    evidence["last_probe_error"] = str(exc)
                self.sleeper(min(2, max(0, deadline - self.clock())))
            return finish("timeout", "Docker did not become ready within the startup budget")
        except FileNotFoundError as exc:
            return finish("not_installed", exc)
        except PermissionError as exc:
            return finish("permission_denied", exc)
        except subprocess.TimeoutExpired as exc:
            return finish("timeout", exc)
        except (OSError, ValueError, KeyError, IndexError, TypeError) as exc:
            return finish("startup_error", exc)
