"""Document-backed Compose labs with fixed commands and structured observations.

Only a deliberately small Compose subset is accepted. Documents are data, never
shell scripts. Container readiness does not imply vulnerability reproduction.
"""

import ipaddress
import json
import re
import subprocess
import shutil
from uuid import uuid4
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from app.tools.registry import ToolExecutionError, ToolOutput, ToolRegistry, ToolTimeoutError
from app.tools.builtin.filesystem import local_path, file_hash


class DockerLabParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["pull", "build", "up", "status", "logs", "down"]
    timeout: int = Field(default=120, ge=1, le=900)
    tail: int = Field(default=100, ge=1, le=1000)
    since: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}T[0-9:.]+\+00:00$")


class ScriptRunParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service: str
    script: str
    args: list[str] = Field(default_factory=list)
    environment: dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(default=60, ge=1, le=300)


class EvidenceParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service: str
    path: str
    timeout: int = Field(default=30, ge=1, le=300)


class BuildParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timeout: int = Field(default=120, ge=1, le=900)


def load_compose(source: Path, *, base: Path | None = None) -> dict:
    """Read YAML/JSON or exactly one fenced compose/yaml block from Markdown."""
    text = source.read_text(encoding="utf-8")
    if source.suffix.lower() == ".md":
        blocks = re.findall(r"^```(?:yaml|yml|compose)\s*\n(.*?)^```\s*$", text,
                            re.MULTILINE | re.DOTALL)
        candidates = [yaml.safe_load(block) for block in blocks]
        candidates = [item for item in candidates if isinstance(item, dict) and "services" in item]
        if len(candidates) != 1:
            raise ValueError("Document must contain exactly one Compose code block")
        config = candidates[0]
    else:
        config = yaml.safe_load(text)
    if not isinstance(config, dict) or set(config) != {"services"}:
        raise ValueError("Only a top-level services mapping is supported")
    services = config["services"]
    if not isinstance(services, dict) or not services:
        raise ValueError("At least one service is required")
    base = base or source.parent
    allowed = {"image", "build", "volumes", "ports", "environment", "command", "entrypoint", "healthcheck", "depends_on"}
    for name, service in services.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", name):
            raise ValueError("Invalid service name")
        if not isinstance(service, dict) or set(service) - allowed:
            raise ValueError(f"Unsupported Compose fields in {name}")
        build = service.get("build")
        if build is not None:
            if isinstance(build, str):
                build = {"context": build}
            if not isinstance(build, dict) or set(build) - {"context", "dockerfile", "args", "target"}:
                raise ValueError("Only local build context, dockerfile, args and target are supported")
            context = local_path(base, build.get("context", "."), allow_root=True)
            dockerfile = local_path(context, build.get("dockerfile", "Dockerfile"))
            if not context.is_dir() or not dockerfile.is_file():
                raise ValueError("Local build context and Dockerfile must exist")
        for mount in service.get("volumes", []):
            if not isinstance(mount, dict) or set(mount) != {"type", "source", "target", "read_only"}:
                raise ValueError("Mounts require type/source/target/read_only")
            if mount["type"] != "bind" or mount["read_only"] is not True:
                raise ValueError("Only read-only project bind mounts are supported")
            if not local_path(base, mount["source"]).exists():
                raise ValueError("Mount source is missing")
            if not isinstance(mount["target"], str) or not mount["target"].startswith("/") or ".." in mount["target"].split("/"):
                raise ValueError("Mount target must be an absolute container path")
        image = service.get("image", "")
        if not image and build is not None:
            image = "local-build:1"
        if not isinstance(image, str) or not image or "$" in image:
            raise ValueError(f"Explicit image required for {name}")
        if "@sha256:" not in image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
            raise ValueError(f"Use a fixed image tag or digest for {name}")
        ports = service.get("ports", [])
        if not isinstance(ports, list) or any(
            not isinstance(port, str) or not re.fullmatch(r"127\.0\.0\.1:[0-9]+:[0-9]+(?:/tcp|/udp)?", port)
            for port in ports
        ):
            raise ValueError("Published ports must explicitly bind to 127.0.0.1")
    # Prevent Compose environment interpolation from silently changing reviewed data.
    if "$" in json.dumps(config):
        raise ValueError("Resolve Compose dollar expressions before importing the document")
    return config


def environment_assets(source: Path, config: dict | None = None, *, base: Path | None = None) -> dict[str, str]:
    base = (base or source.parent).resolve()
    config = config or load_compose(source, base=base)
    roots = []
    for service in config["services"].values():
        if "build" in service:
            build = service["build"]
            roots.append(local_path(base, build if isinstance(build, str) else build.get("context", "."), allow_root=True))
        roots.extend(local_path(base, m["source"]) for m in service.get("volumes", []))
    manifest, total = {}, 0
    for root in roots:
        for path in sorted(root.rglob("*") if root.is_dir() else [root]):
            path = local_path(base, path.relative_to(base).as_posix())
            if not path.is_file():
                continue
            relative = path.relative_to(base).as_posix()
            if relative in manifest:
                continue
            total += path.stat().st_size
            if total > 32 * 1024 * 1024 or len(manifest) >= 1000:
                raise ValueError("Environment inputs exceed 32 MiB / 1000 files")
            manifest[relative] = file_hash(path)
    return manifest


class DockerLab:
    def __init__(self, compose: Path, project: str, *, runner=None):
        if not re.fullmatch(r"lab-[a-z0-9][a-z0-9_-]{0,48}", project):
            raise ValueError("Project must start with lab- and contain lowercase letters/digits/_/-")
        self.compose = compose.resolve()
        self.project = project
        self.runner = runner or subprocess.run
        self.jobs = set()

    @property
    def input_root(self):
        candidate = self.compose.parent / "inputs"
        return candidate if candidate.is_dir() else self.compose.parent

    def configuration(self):
        return load_compose(self.compose, base=self.input_root)

    @classmethod
    def prepare(cls, source: Path, workspace: Path, project: str):
        config = load_compose(source)
        manifest = environment_assets(source, config)
        lab = cls(workspace / project / "compose.json", project)
        lab.compose.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(config, indent=2)
        if lab.compose.exists() and lab.compose.read_text(encoding="utf-8") != serialized:
            raise ValueError("Project already has another configuration; use a new project name")
        for name, expected in manifest.items():
            destination = local_path(lab.compose.parent / "inputs", name)
            if destination.exists() and file_hash(destination) != expected:
                raise ValueError("Prepared project inputs have changed; use a new project")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(local_path(source.parent, name), destination)
            if file_hash(destination) != expected:
                raise ValueError("Environment input changed while preparing snapshot")
        lab.compose.write_text(serialized, encoding="utf-8")
        return lab

    def run(self, params: DockerLabParams) -> ToolOutput:
        config = self.configuration()
        commands = {
            "pull": ["pull"],
            "build": ["build"],
            "up": ["up", "-d", "--wait", "--wait-timeout", str(params.timeout)],
            "status": ["ps", "--all", "--format", "json"],
            "logs": ["logs", "--no-color", "--tail", str(params.tail)],
            "down": ["down", "--timeout", "10"],
        }
        if params.action in {"pull", "build"}:
            selected = [name for name, service in config["services"].items()
                        if ("build" in service) == (params.action == "build")]
            if not selected:
                return ToolOutput("No matching services", {"action": params.action, "exit_code": 0, "skipped": True})
            commands[params.action].extend(selected)
        if params.action == "down":
            self.cleanup_jobs()
        if params.action == "logs" and params.since:
            commands["logs"].extend(["--since", params.since])
        argv = ["docker", "compose", "--project-name", self.project, "--project-directory", str(self.input_root), "--file", str(self.compose),
                *commands[params.action]]
        try:
            result = self.runner(argv, capture_output=True, text=True, encoding="utf-8",
                                 errors="replace", timeout=params.timeout + 15, shell=False,
                                 cwd=str(self.compose.parent))
        except subprocess.TimeoutExpired as exc:
            raise ToolTimeoutError("Docker command timed out; inspect status/logs before retrying") from exc
        except OSError as exc:
            raise ToolExecutionError(f"Cannot execute Docker: {exc}") from exc
        evidence = {"project": self.project, "action": params.action, "exit_code": result.returncode}
        output = result.stdout + result.stderr
        if result.returncode:
            raise ToolExecutionError(f"Docker {params.action} failed ({result.returncode}): {output}")
        if params.action == "status":
            try:
                raw = result.stdout.strip()
                containers = json.loads(raw) if raw.startswith("[") else [json.loads(line) for line in raw.splitlines()]
                expected = set(config["services"])
                running = {row["Service"] for row in containers if row.get("State") == "running"}
                all_running = expected <= running and all(row.get("State") == "running" for row in containers)
                evidence.update(containers=containers, all_running=all_running,
                                all_healthy=all_running and all(row.get("Health") == "healthy" for row in containers))
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                raise ToolExecutionError("Invalid Docker Compose status JSON") from exc
        return ToolOutput(output=output, evidence=evidence)

    def registry(self) -> ToolRegistry:
        registry = ToolRegistry()
        registry.register("docker_lab", DockerLabParams, self.run)
        registry.register("build_image", BuildParams, lambda p: self.run(DockerLabParams(action="build", timeout=p.timeout)))
        registry.register("validate_environment", BuildParams, lambda p: ToolOutput("Environment validated", {
            "services": list(self.configuration()["services"]),
            "assets": environment_assets(self.compose, self.configuration(), base=self.input_root)}))
        registry.register("run_in_container", ScriptRunParams, lambda p: ToolOutput("Script execution completed", self.run_script(
            p.service, local_path(self.compose.parent / "artifacts", p.script), args=p.args, environment=p.environment, timeout=p.timeout)))
        registry.register("collect_file_evidence", EvidenceParams, lambda p: ToolOutput("Target file evidence collected",
            self.read_container_file(p.service, p.path, timeout=p.timeout)))
        return registry

    def _invoke(self, argv, timeout):
        return self.runner(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, shell=False, cwd=str(self.compose.parent))

    def _prefix(self):
        return ["docker", "compose", "--project-name", self.project, "--project-directory", str(self.input_root),
                "--file", str(self.compose)]

    def cleanup_jobs(self):
        for name in list(self.jobs):
            result = self._invoke(["docker", "rm", "-f", name], 15)
            if result.returncode:
                raise ToolExecutionError(f"Cannot remove script container {name}: {result.stderr}")
            self.jobs.remove(name)

    def run_script(self, service: str, artifact: Path, *, args=(), environment=None, timeout=60):
        if service not in self.configuration()["services"]:
            raise ValueError("Script service is not in the prepared environment")
        if artifact.suffix != ".py" or not artifact.is_file() or artifact.stat().st_size > 262144:
            raise ValueError("Script artifact must be a Python file under 256 KiB")
        if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) for key in (environment or {})):
            raise ValueError("Invalid environment variable name")
        name = self.project + "-job-" + uuid4().hex[:10]
        self.jobs.add(name)
        argv = [*self._prefix(), "run", "--rm", "--no-deps", "-T", "--name", name,
                "--volume", f"{artifact.resolve()}:/lab-script.py:ro", "--entrypoint", "python"]
        for key, value in (environment or {}).items():
            argv.extend(["--env", f"{key}={value}"])
        argv.extend([service, "/lab-script.py", *args])
        evidence = {"service": service, "container": name, "script_sha256": file_hash(artifact), "timed_out": False}
        try:
            result = self._invoke(argv, timeout)
            evidence.update(exit_code=result.returncode, stdout=result.stdout[:65536], stderr=result.stderr[:65536],
                            truncated=len(result.stdout) > 65536 or len(result.stderr) > 65536)
        except subprocess.TimeoutExpired as exc:
            def decoded(value):
                return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
            evidence.update(exit_code=None, timed_out=True, stdout=decoded(exc.stdout)[:65536], stderr=decoded(exc.stderr)[:65536])
        finally:
            try:
                removed = self._invoke(["docker", "rm", "-f", name], 15)
                # --rm has already removed the job on normal completion.
                if removed.returncode and evidence.get("timed_out"):
                    evidence["cleanup_error"] = removed.stderr
                else:
                    self.jobs.discard(name)
            except Exception as exc:
                evidence["cleanup_error"] = str(exc)
        return evidence

    def read_container_file(self, service: str, path: str, *, timeout=30):
        if service not in self.configuration()["services"]:
            raise ValueError("Evidence service is not in the prepared environment")
        if not path.startswith("/") or ".." in path.split("/"):
            raise ValueError("Evidence requires an absolute container path")
        code = (
            "import pathlib,sys,json,stat,hashlib; p=pathlib.Path(sys.argv[1]); "
            "exists=p.exists(); regular=exists and stat.S_ISREG(p.lstat().st_mode); "
            "data=p.open('rb').read(65537) if regular else b''; "
            "print(json.dumps(dict(exists=exists,regular=regular,body=data[:65536].decode('utf-8','replace'),"
            "truncated=len(data)>65536,sha256=hashlib.sha256(data).hexdigest() if len(data)<=65536 else None)))"
        )
        result = self._invoke([*self._prefix(), "exec", "-T", service, "python", "-c", code, path], timeout)
        if result.returncode:
            raise ToolExecutionError(f"Evidence collection failed: {result.stderr}")
        evidence = json.loads(result.stdout)
        return {**evidence, "service": service, "path": path}


    def resolve_target_endpoint(self, service: str, published_port: int, *, network_name: str, metasploit_container: str, timeout: int = 15) -> dict:
        """Resolve one running Compose service to its private container IP/port.

        The published port must be explicitly bound to loopback in the reviewed
        Compose file. The returned private endpoint is intended for a separately
        network-attached Metasploit container, never for arbitrary host targets.
        """
        config = self.configuration()
        if service not in config["services"]:
            raise ValueError("Target service is not declared in the reviewed Compose file")
        declared = config["services"][service].get("ports", [])
        if not any(
            isinstance(item, str)
            and re.fullmatch(rf"127\.0\.0\.1:{published_port}:[0-9]+/tcp", item)
            for item in declared
        ):
            raise ValueError("Target port must be explicitly published on loopback as TCP")

        listed = self._invoke([*self._prefix(), "ps", "-q", service], timeout)
        if listed.returncode:
            raise ToolExecutionError(f"Cannot list target container: {listed.stderr}")
        container_ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
        if len(container_ids) != 1:
            raise ValueError("Expected exactly one container for the selected target service")
        inspected = self._invoke(["docker", "inspect", container_ids[0]], timeout)
        if inspected.returncode:
            raise ToolExecutionError(f"Cannot inspect target container: {inspected.stderr}")
        try:
            rows = json.loads(inspected.stdout)
            if not isinstance(rows, list) or len(rows) != 1:
                raise ValueError("Unexpected Docker inspect response")
            row = rows[0]
            if row.get("State", {}).get("Running") is not True:
                raise ValueError("Selected target container is not running")
            port_map = row.get("NetworkSettings", {}).get("Ports") or {}
            matches = []
            for container_binding, host_bindings in port_map.items():
                match = re.fullmatch(r"([0-9]+)/tcp", str(container_binding))
                if not match or not isinstance(host_bindings, list):
                    continue
                for binding in host_bindings:
                    if (binding.get("HostIp") == "127.0.0.1"
                            and str(binding.get("HostPort")) == str(published_port)):
                        matches.append(int(match.group(1)))
            if len(matches) != 1:
                raise ValueError("Published target port does not resolve to exactly one TCP container port")
            networks = row.get("NetworkSettings", {}).get("Networks") or {}
            network = networks.get(network_name)
            if not isinstance(network, dict) or not network.get("IPAddress"):
                raise ValueError("Target container is not attached to the requested Metasploit network")
            ip = ipaddress.ip_address(network["IPAddress"])
            if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local:
                raise ValueError("Selected target network must provide a private, non-loopback IPv4 address")
            address = str(ip)
            msf_inspected = self._invoke(["docker", "inspect", metasploit_container], timeout)
            if msf_inspected.returncode:
                raise ValueError("Cannot inspect the configured Metasploit container")
            msf_rows = json.loads(msf_inspected.stdout)
            if not isinstance(msf_rows, list) or len(msf_rows) != 1:
                raise ValueError("Unexpected Metasploit container inspect response")
            msf_row = msf_rows[0]
            if msf_row.get("State", {}).get("Running") is not True:
                raise ValueError("Configured Metasploit container is not running")
            msf_network = (msf_row.get("NetworkSettings", {}).get("Networks") or {}).get(network_name)
            if not isinstance(msf_network, dict) or not msf_network.get("IPAddress"):
                raise ValueError("Metasploit container is not attached to the selected target network")
            return {
                "project": self.project,
                "service": service,
                "container_id": container_ids[0],
                "host": address,
                "port": matches[0],
                "published_host_port": published_port,
                "network": network_name,
                "metasploit_container": metasploit_container,
                "metasploit_network_ip": msf_network["IPAddress"],
            }
        except (KeyError, TypeError, ValueError, ipaddress.AddressValueError) as exc:
            raise ValueError(f"Cannot safely resolve target endpoint: {exc}") from exc

    def probe_version(self, service, command, *, timeout=30):
        if service not in self.configuration()["services"]:
            raise ValueError("Version service is not in the prepared environment")
        result = self._invoke([*self._prefix(), "exec", "-T", service, *command], timeout)
        return {"service": service, "command": command, "exit_code": result.returncode,
                "stdout": result.stdout[:65536], "stderr": result.stderr[:65536],
                "truncated": len(result.stdout) > 65536 or len(result.stderr) > 65536}
