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
    if not isinstance(config, dict) or set(config) - {"services", "networks"} or "services" not in config:
        raise ValueError("Only top-level services and internal networks are supported")
    networks = config.get("networks", {})
    if not isinstance(networks, dict):
        raise ValueError("Compose networks must be a mapping")
    for network_name, network in networks.items():
        if (not isinstance(network_name, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", network_name)
                or not isinstance(network, dict) or set(network) - {"internal", "name"}
                or network.get("internal") is not True):
            raise ValueError("Only explicitly internal Docker networks are supported")
        explicit_name = network.get("name")
        if explicit_name is not None and (not isinstance(explicit_name, str)
                or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", explicit_name)):
            raise ValueError("Invalid explicit Docker network name")
    services = config["services"]
    if not isinstance(services, dict) or not services:
        raise ValueError("At least one service is required")
    base = base or source.parent
    allowed = {"image", "build", "volumes", "ports", "environment", "command", "entrypoint", "healthcheck", "depends_on", "networks"}
    for name, service in services.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", name):
            raise ValueError("Invalid service name")
        if not isinstance(service, dict) or set(service) - allowed:
            raise ValueError(f"Unsupported Compose fields in {name}")
        service_networks = service.get("networks", [])
        if (not isinstance(service_networks, list)
                or any(not isinstance(item, str) or item not in networks for item in service_networks)
                or len(service_networks) != len(set(service_networks))):
            raise ValueError(f"Service {name} references an undeclared or duplicate network")
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


    def prepare_metasploit_container(self, network_name: str, container: str, *,
                                     container_rpc_port: int = 55553,
                                     timeout: int = 15) -> dict:
        """Move a loopback-only RPC container from default bridge to the approved internal network.

        RPC is accessed via Docker Exec, so the Metasploit port must not be published on
        any host interface. Only a container attached solely to Docker default bridge
        may be moved automatically.
        """
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", network_name):
            raise ValueError("Invalid approved Docker network name")
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", container):
            raise ValueError("Invalid Metasploit container name")
        if not 1 <= container_rpc_port <= 65535:
            raise ValueError("Invalid Metasploit container RPC port")
        network_result = self._invoke(["docker", "network", "inspect", network_name], timeout)
        if network_result.returncode:
            raise ToolExecutionError(f"Cannot inspect approved lab network: {network_result.stderr}")
        networks = json.loads(network_result.stdout)
        if len(networks) != 1 or networks[0].get("Name") != network_name or networks[0].get("Internal") is not True:
            raise PermissionError("Metasploit can only join the approved Docker internal network")
        inspected = self._invoke(["docker", "inspect", container], timeout)
        if inspected.returncode:
            raise ToolExecutionError(f"Cannot inspect Metasploit container: {inspected.stderr}")
        rows = json.loads(inspected.stdout)
        if not isinstance(rows, list) or len(rows) != 1 or rows[0].get("State", {}).get("Running") is not True:
            raise ValueError("Metasploit container must exist and already be running")
        row = rows[0]
        bindings = (row.get("HostConfig", {}).get("PortBindings") or {}).get(f"{container_rpc_port}/tcp") or []
        if bindings:
            raise PermissionError("Metasploit RPC must not be published to host interfaces; use Docker Exec transport")
        attached = row.get("NetworkSettings", {}).get("Networks") or {}
        if set(attached) == {network_name}:
            return {"container_id": row.get("Id"), "network_name": network_name, "changed": False}
        if set(attached) != {"bridge"}:
            raise PermissionError("Metasploit container must be on Docker default bridge only before lab attachment")
        disconnected = self._invoke(["docker", "network", "disconnect", "bridge", container], timeout)
        if disconnected.returncode:
            raise ToolExecutionError(f"Cannot remove Metasploit default bridge attachment: {disconnected.stderr}")
        connected = self._invoke(["docker", "network", "connect", network_name, container], timeout)
        if connected.returncode:
            raise ToolExecutionError(f"Cannot attach Metasploit to approved internal network: {connected.stderr}")
        # Refresh Docker's published-port forwarding after changing the container's
        # sole network attachment. The RPC listener restarts on the internal interface.
        restarted = self._invoke(["docker", "restart", container], timeout)
        if restarted.returncode:
            raise ToolExecutionError(f"Cannot restart Metasploit after internal-network attachment: {restarted.stderr}")
        verified = self._invoke(["docker", "inspect", container], timeout)
        if verified.returncode:
            raise ToolExecutionError(f"Cannot verify Metasploit network attachment: {verified.stderr}")
        final_rows = json.loads(verified.stdout)
        final_networks = (final_rows[0].get("NetworkSettings", {}).get("Networks") or {}) if len(final_rows) == 1 else {}
        if set(final_networks) != {network_name}:
            raise PermissionError("Metasploit container retained an unexpected network attachment")
        return {"container_id": final_rows[0].get("Id"), "network_name": network_name, "changed": True}


    def restore_metasploit_container(self, network_name: str, container: str, *, timeout: int = 15) -> dict:
        """Detach Metasploit from the temporary lab network before Compose teardown."""
        inspected = self._invoke(["docker", "inspect", container], timeout)
        if inspected.returncode:
            raise ToolExecutionError(f"Cannot inspect Metasploit container during cleanup: {inspected.stderr}")
        rows = json.loads(inspected.stdout)
        if not isinstance(rows, list) or len(rows) != 1:
            raise ValueError("Unexpected Metasploit container inspect response during cleanup")
        attached = rows[0].get("NetworkSettings", {}).get("Networks") or {}
        if network_name not in attached:
            if set(attached) == {"bridge"}:
                return {"network_name": network_name, "restored_to": "bridge", "changed": False}
            if attached:
                raise PermissionError("Metasploit container is not on the expected lab network during cleanup")
            # Roll back a partial prepare operation that detached the default
            # bridge but failed before attaching the approved lab network.
            connected = self._invoke(["docker", "network", "connect", "bridge", container], timeout)
            if connected.returncode:
                raise ToolExecutionError(f"Cannot restore Metasploit default bridge after partial setup: {connected.stderr}")
            verified = self._invoke(["docker", "inspect", container], timeout)
            if verified.returncode:
                raise ToolExecutionError(f"Cannot verify restored Metasploit bridge after partial setup: {verified.stderr}")
            final_rows = json.loads(verified.stdout)
            final_networks = (final_rows[0].get("NetworkSettings", {}).get("Networks") or {}) if len(final_rows) == 1 else {}
            if set(final_networks) != {"bridge"}:
                raise PermissionError("Metasploit partial-setup rollback left unexpected Docker network attachments")
            return {"network_name": network_name, "restored_to": "bridge", "changed": True}
        disconnected = self._invoke(["docker", "network", "disconnect", network_name, container], timeout)
        if disconnected.returncode:
            raise ToolExecutionError(f"Cannot detach Metasploit from temporary lab network: {disconnected.stderr}")
        verified = self._invoke(["docker", "inspect", container], timeout)
        if verified.returncode:
            raise ToolExecutionError(f"Cannot verify Metasploit detach: {verified.stderr}")
        final_rows = json.loads(verified.stdout)
        final_networks = (final_rows[0].get("NetworkSettings", {}).get("Networks") or {}) if len(final_rows) == 1 else {}
        if not final_networks:
            connected = self._invoke(["docker", "network", "connect", "bridge", container], timeout)
            if connected.returncode:
                raise ToolExecutionError(f"Cannot restore Metasploit default bridge attachment: {connected.stderr}")
            verified = self._invoke(["docker", "inspect", container], timeout)
            if verified.returncode:
                raise ToolExecutionError(f"Cannot verify restored Metasploit bridge attachment: {verified.stderr}")
            final_rows = json.loads(verified.stdout)
            final_networks = (final_rows[0].get("NetworkSettings", {}).get("Networks") or {}) if len(final_rows) == 1 else {}
        if set(final_networks) != {"bridge"}:
            raise PermissionError("Metasploit cleanup left unexpected Docker network attachments")
        return {"network_name": network_name, "restored_to": "bridge", "changed": True}

    def resolve_target_endpoint(self, service: str, published_port: int, *, network_name: str,
                                metasploit_container: str, timeout: int = 15) -> dict:
        """Attest that target and Metasploit share one explicitly internal Docker network.

        Both containers must have exactly one network attachment. This prevents a
        second bridge/host-facing network from bypassing Docker internal egress restrictions.
        """
        config = self.configuration()
        if service not in config["services"]:
            raise ValueError("Target service is not declared in the reviewed Compose file")
        declared = config["services"][service].get("ports", [])
        if not any(isinstance(item, str) and re.fullmatch(
            rf"127\.0\.0\.1:{published_port}:[0-9]+/tcp", item) for item in declared):
            raise ValueError("Target port must be explicitly published on loopback as TCP")

        service_networks = config["services"][service].get("networks", [])
        network_alias = next((name for name in service_networks
                              if config["networks"][name].get("name", f"{self.project}_{name}") == network_name), None)
        if network_alias is None or config["networks"][network_alias].get("internal") is not True:
            raise ValueError("Target service must use the approved internal Docker network")

        network_result = self._invoke(["docker", "network", "inspect", network_name], timeout)
        if network_result.returncode:
            raise ToolExecutionError(f"Cannot inspect isolated Docker network: {network_result.stderr}")
        try:
            network_rows = json.loads(network_result.stdout)
            if not isinstance(network_rows, list) or len(network_rows) != 1:
                raise ValueError("Unexpected Docker network inspect response")
            network_row = network_rows[0]
            network_id = network_row.get("Id")
            if network_row.get("Name") != network_name or network_row.get("Internal") is not True:
                raise ValueError("Docker network is not the approved internal network")
            if not isinstance(network_id, str) or not re.fullmatch(r"[0-9a-f]{64}", network_id):
                raise ValueError("Docker returned an invalid network ID")
            listed = self._invoke([*self._prefix(), "ps", "-q", service], timeout)
            if listed.returncode:
                raise ToolExecutionError(f"Cannot list target container: {listed.stderr}")
            container_ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
            if len(container_ids) != 1:
                raise ValueError("Expected exactly one container for the selected target service")
            def inspect_container(container_id: str, label: str) -> dict:
                result = self._invoke(["docker", "inspect", container_id], timeout)
                if result.returncode:
                    raise ToolExecutionError(f"Cannot inspect {label} container: {result.stderr}")
                rows = json.loads(result.stdout)
                if not isinstance(rows, list) or len(rows) != 1:
                    raise ValueError(f"Unexpected {label} container inspect response")
                row = rows[0]
                if row.get("State", {}).get("Running") is not True:
                    raise ValueError(f"Selected {label} container is not running")
                attached = row.get("NetworkSettings", {}).get("Networks") or {}
                if set(attached) != {network_name}:
                    raise ValueError(f"{label} container must be attached only to the approved internal network")
                attachment = attached[network_name]
                if attachment.get("NetworkID") != network_id:
                    raise ValueError(f"{label} container network ID does not match Docker network inspection")
                address = ipaddress.ip_address(attachment.get("IPAddress", ""))
                if address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local:
                    raise ValueError(f"{label} container must have a private, non-loopback IPv4 address")
                return {"id": row.get("Id", container_id), "ip": str(address), "row": row}
            target = inspect_container(container_ids[0], "target")
            msf = inspect_container(metasploit_container, "Metasploit")
            # NetworkSettings.Ports can contain null entries when the image does not
            # declare EXPOSE, even though Compose has configured a host binding.
            # HostConfig.PortBindings is Docker Inspect API configured mapping.
            network_ports = target["row"].get("NetworkSettings", {}).get("Ports") or {}
            configured_ports = target["row"].get("HostConfig", {}).get("PortBindings") or {}
            port_maps = [network_ports, configured_ports]
            matches = set()
            for port_map in port_maps:
                for container_binding, host_bindings in port_map.items():
                    match = re.fullmatch(r"([0-9]+)/tcp", str(container_binding))
                    if not match or not isinstance(host_bindings, list):
                        continue
                    for binding in host_bindings:
                        if binding.get("HostIp") == "127.0.0.1" and str(binding.get("HostPort")) == str(published_port):
                            matches.add(int(match.group(1)))
            if len(matches) != 1:
                raise ValueError(f"Published target port {published_port} does not resolve to exactly one TCP container port; observed network bindings={network_ports!r}, configured bindings={configured_ports!r}")
            container_port = next(iter(matches))
            compose_sha256 = __import__("hashlib").sha256(
                json.dumps(config, sort_keys=True).encode("utf-8")
            ).hexdigest()
            return {
                "project": self.project, "service": service, "compose_sha256": compose_sha256,
                "target_container_id": target["id"], "target_host": target["ip"],
                "target_port": container_port, "published_host_port": published_port,
                "network_name": network_name, "network_id": network_id, "network_internal": True,
                "target_networks": [network_name], "metasploit_container_id": msf["id"],
                "metasploit_host": msf["ip"], "metasploit_networks": [network_name],
            }
        except (KeyError, TypeError, ValueError, ipaddress.AddressValueError) as exc:
            raise ValueError(f"Cannot safely attest isolated target endpoint: {exc}") from exc


    def probe_version(self, service, command, *, timeout=30):
        if service not in self.configuration()["services"]:
            raise ValueError("Version service is not in the prepared environment")
        result = self._invoke([*self._prefix(), "exec", "-T", service, *command], timeout)
        return {"service": service, "command": command, "exit_code": result.returncode,
                "stdout": result.stdout[:65536], "stderr": result.stderr[:65536],
                "truncated": len(result.stdout) > 65536 or len(result.stderr) > 65536}
