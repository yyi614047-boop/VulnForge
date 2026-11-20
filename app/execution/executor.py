"""Plan-driven local tools with durable step evidence and bounded recovery.

Graph routing stays in pipeline.py. This executor performs only requested steps;
it cannot change probes, assertions, or the deployment plan.
"""
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Event

from app.execution.probes import request, verify
from app.domain.reproduction import ReproductionSpec as Card
from app.targets.vulhub.catalog import TargetCatalog
from app.execution.artifacts import digest
from app.environments.docker.manager import DockerLab, DockerLabParams, load_compose
from app.tools.registry import ToolTimeoutError
from app.tools.builtin.filesystem import WorkspaceFiles, WriteParams, local_path, file_hash
from app.environments.docker.manager import environment_assets
from app.execution.artifacts import collect_assets
from app.execution.verifier import EvidenceVerifier
from app.domain.results import Evidence
from app.domain.plans import ExecutionPlan, ExecutionStep
from app.domain.policies import ExecutionPolicy
from app.domain.targets import TargetSpec
from app.domain.reproduction import ReproductionSpec
from app.domain.poc import PoCCandidate
from app.domain.poc_execution import build_poc_execution_spec
from app.agents.planner import validate_execution_plan


def atomic_json(path: Path, payload):
    """先写临时文件再原子替换，以持久化一致的 JSON 报告。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class StepFailure(Exception):
    def __init__(self, message, category, *, retryable=False, evidence=None):
        """初始化组件及其运行所需的配置、依赖和状态。"""
        super().__init__(message)
        self.category, self.retryable, self.evidence = category, retryable, evidence or {}


class StepExecutor:
    def __init__(self, knowledge: Path, workspace: Path, project: str, report_path: Path,
                 *, lab_factory=DockerLab.prepare, requester=request, sleeper=None, cancel=None,
                 recovery_controller=None, recovery_budget=0, metasploit_adapter=None,\n                 metasploit_target_port=None, metasploit_options=None):
        """初始化组件及其运行所需的配置、依赖和状态。"""
        # Validate the project before using it in filesystem paths.
        DockerLab(workspace / project / "compose.json", project)
        self.kb, self.workspace, self.project = TargetCatalog(knowledge), workspace, project
        self.report_path = report_path
        self.lab_factory, self.requester = lab_factory, requester
        self.cancel = cancel or Event()
        self.sleeper = sleeper or self.cancel.wait
        if not 0 <= recovery_budget <= 2:
            raise ValueError("Recovery budget must be 0..2")
        self.recovery_controller, self.recovery_budget = recovery_controller, recovery_budget
        self.recovery_remaining = recovery_budget
        self.lab = None
        self.started = False
        self.locks = []
        self.plan = self.card = self.bundle = self.report = None
        self.observations, self.logs = [], None
        self.probe_started_at = None
        self.file_observations = {}
        self.artifacts = {}
        self.metasploit_adapter = metasploit_adapter
        self.metasploit_target_port = metasploit_target_port
        self.metasploit_options = dict(metasploit_options or {})

    def open(self, plan: ExecutionPlan, bundle: dict, *, execution_policy: ExecutionPolicy | None = None,
             target_spec: TargetSpec | None = None, reproduction_spec: ReproductionSpec | None = None):
        """Revalidate the canonical plan and its source fingerprints before side effects."""
        if self.report is not None:
            raise ValueError("Executor instances are single-run")
        if execution_policy is None or target_spec is None or reproduction_spec is None:
            raise PermissionError("ExecutionPolicy, approved TargetSpec and ReproductionSpec are required")
        plan = ExecutionPlan.model_validate(plan.model_dump(mode="json") if hasattr(plan, "model_dump") else plan)
        if bundle["card_hash"] != reproduction_spec.fingerprint():
            raise PermissionError("Research bundle is not bound to the reviewed reproduction specification")
        expected = {
            "reproduction": bundle["card_hash"],
            "compose": bundle["compose_hash"],
            "assets": bundle["assets_hash"],
            "poc_candidates": bundle.get("poc_candidates_hash", digest("[]")),
        }
        if plan.input_fingerprints != expected:
            raise PermissionError("Execution plan provenance differs from the research bundle")
        current = self.kb.get(reproduction_spec.id)
        current_target = self.kb.to_target_spec(current)
        if current.fingerprint() != reproduction_spec.fingerprint():
            raise PermissionError("Reproduction specification changed after policy validation")
        if current_target.fingerprint() != target_spec.fingerprint():
            raise PermissionError("Target sources or environment changed after policy validation")
        validated = validate_execution_plan(
            plan, bundle, current_target, current, execution_policy,
            retries=max((step.retries for step in plan.steps), default=0),
            timeout=max((step.timeout_seconds for step in plan.steps), default=60),
            keep=any(step.action == "keep" for step in plan.steps),
        )
        if validated.model_dump(mode="json") != plan.model_dump(mode="json"):
            raise PermissionError("Execution plan failed canonical validation")
        for step in plan.steps:
            execution_policy.authorize_action(step.action, timeout_seconds=step.timeout_seconds, retries=step.retries)
        self.recovery_budget = min(self.recovery_budget, execution_policy.max_recovery_actions)
        self.recovery_remaining = self.recovery_budget
        self.plan = self.domain_plan = plan
        self.execution_policy, self.target_spec, self.reproduction_spec = execution_policy, current_target, current
        self.card, self.bundle = Card.model_validate(bundle["card"]), bundle
        config = load_compose(self.kb.environment(current))
        if current.fingerprint() != expected["reproduction"] or digest(json.dumps(config, sort_keys=True)) != expected["compose"]:
            raise ValueError("Research inputs changed since planning; research and plan again")
        if digest(json.dumps(collect_assets(self.kb, current, config), sort_keys=True)) != expected["assets"]:
            raise ValueError("Build, mount or script inputs changed since planning")
        lock_dir = self.workspace / ".locks"
        lock_dir.mkdir(parents=True, exist_ok=True)
        try:
            for name in [self.project, f"port-{self.card.port}"]:
                path = lock_dir / (name + ".lock")
                with path.open("x", encoding="utf-8") as handle:
                    handle.write(json.dumps({"pid": os.getpid(), "project": self.project, "report": str(self.report_path)}))
                self.locks.append(path)
            if self.report_path.exists():
                raise FileExistsError("Report already exists; choose a new report path to preserve prior evidence")
            self.report = {
                "id": self.card.id, "project": self.project, "status": "pending", "cleanup": "not_needed",
                "research": bundle, "plan": plan.model_dump(mode="json"),
                "authorization": {"policy_id": execution_policy.policy_id,
                    "target_fingerprint": current_target.fingerprint(),
                    "reproduction_fingerprint": current.fingerprint()},
                "steps": [], "events": [], "started_at": datetime.now(timezone.utc).isoformat(),
            }
            self.save()
        except BaseException:
            self.release()
            raise

    def run_metasploit(self):
        """Run the selected existing Metasploit PoC after the lab is deployed."""
        record = {"status": "not_selected"}
        selected_id = self.domain_plan.selected_poc_candidate_id
        if not selected_id:
            self.report["metasploit"] = record
            self.save()
            return record
        if not self.started or self.report.get("status") == "environment_error":
            record = {"status": "skipped", "reason": "Target lab is not running"}
            self.report["metasploit"] = record
            self.save()
            return record
        if self.cancel.is_set():
            record = {"status": "skipped", "reason": "Run was cancelled"}
            self.report["metasploit"] = record
            self.save()
            return record
        if not self.execution_policy.allow_metasploit_check:
            record = {"status": "policy_blocked", "reason": "Metasploit checks are disabled by policy"}
            self.report["metasploit"] = record
            self.save()
            return record
        if self.metasploit_adapter is None:
            record = {"status": "adapter_unavailable", "reason": "Metasploit RPC adapter was not configured"}
            self.report["metasploit"] = record
            self.save()
            return record

        candidate_data = next(
            (item for item in self.bundle.get("poc_candidates", [])
             if item.get("candidate_id") == selected_id),
            None,
        )
        if candidate_data is None:
            raise PermissionError("Selected PoC candidate is missing from the research bundle")
        candidate = PoCCandidate.model_validate(candidate_data)
        published_ports = {
            port for ports in self.target_spec.environment.published_ports.values() for port in ports
        }
        target_port = self.metasploit_target_port
        if target_port is None:
            if len(published_ports) != 1:
                record = {
                    "status": "configuration_required",
                    "reason": "Specify --metasploit-target-port when the lab exposes zero or multiple ports",
                    "available_ports": sorted(published_ports),
                }
                self.report["metasploit"] = record
                self.save()
                return record
            target_port = next(iter(published_ports))

        spec, assessment = build_poc_execution_spec(
            candidate, self.target_spec, target_host="127.0.0.1",
            target_port=target_port, supplied_options=self.metasploit_options,
        )
        record = {
            "status": "checking",
            "candidate_id": candidate.candidate_id,
            "module_path": candidate.module_path,
            "execution_spec": spec.model_dump(mode="json"),
            "compatibility": assessment.model_dump(mode="json"),
        }
        self.report["metasploit"] = record
        self.save()
        try:
            check = self.metasploit_adapter.check(
                spec, candidate, self.target_spec, self.execution_policy,
                timeout=min(60, self.execution_policy.max_timeout_seconds),
            )
            record["check"] = check.model_dump(mode="json")
            if check.result_code != "vulnerable":
                record["status"] = "check_" + check.result_code
            elif not self.execution_policy.allow_metasploit_execute:
                record["status"] = "check_vulnerable_execution_disabled"
            else:
                execution = self.metasploit_adapter.execute(
                    spec, candidate, self.target_spec, self.execution_policy, check,
                    timeout=min(120, self.execution_policy.max_timeout_seconds),
                )
                record["execution"] = execution.model_dump(mode="json")
                record["status"] = "executed"
        except Exception as exc:
            record["status"] = "failed"
            record["error"] = str(exc)
        self.report["metasploit"] = record
        self.save()
        return record

    def save(self):
        """把当前执行报告原子写入磁盘。"""
        atomic_json(self.report_path, self.report)

    def release(self):
        """释放本次运行持有的项目和端口文件锁。"""
        for path in self.locks:
            path.unlink(missing_ok=True)
        self.locks = []

    def steps(self, phase):
        """筛选指定阶段下的全部计划步骤。"""
        return [step for step in self.domain_plan.steps if step.phase == phase]

    def execute_phase(self, phase):
        """按计划顺序执行某一个实验阶段中的步骤。"""
        for step in self.steps(phase):
            self.execute_step(step)
        return self.report

    def execute_step(self, step: ExecutionStep):
        """持久化并执行单个步骤，同时处理依赖、重试和取消。"""
        if step not in self.domain_plan.steps:
            raise ValueError("Step is not in the validated plan")
        self.execution_policy.authorize_action(step.action, timeout_seconds=step.timeout_seconds, retries=step.retries)
        if any(record["step_id"] == step.step_id for record in self.report["steps"]):
            raise ValueError("A completed or uncertain step cannot be replayed")
        record = {"step_id": step.step_id, "action": step.action, "phase": step.phase,
                  "status": "pending", "attempts": []}
        self.report["steps"].append(record)
        if step.action in {"verify_http", "read_file"} and (not self.started or self.report["status"] == "environment_error"):
            record.update(status="skipped", reason="Target environment is unavailable")
            self.save()
            return
        # Verification/diagnostics/cleanup are allowed after failed dependencies.
        if step.phase not in {"verify", "cleanup"}:
            preceding = {row["step_id"]: row["status"] for row in self.report["steps"]}
            if self.report["status"] != "pending" or any(preceding.get(dep) != "succeeded" for dep in step.depends_on):
                record.update(status="skipped", reason="Failed or missing dependency")
                self.save()
                return
        if self.cancel.is_set() and step.phase != "cleanup":
            record.update(status="skipped", reason="Cancelled")
            self.report["status"] = "cancelled"
            self.save()
            return
        total_attempts = step.retries + self.recovery_budget + 1
        for number in range(total_attempts):
            attempt = {"number": number + 1, "started_at": datetime.now(timezone.utc).isoformat(), "status": "running"}
            record["attempts"].append(attempt)
            record["status"] = "running"
            self.save()  # running persisted before a potentially side-effecting call
            started = time.monotonic()
            try:
                evidence = self.dispatch(step)
                attempt.update(status="succeeded", evidence=evidence)
                record["status"] = "succeeded"
                return
            except StepFailure as exc:
                attempt.update(status="failed", error=str(exc), category=exc.category, evidence=exc.evidence)
                policy_retryable = step.action in self.execution_policy.retryable_actions
                planned_retry = exc.retryable and policy_retryable and number < step.retries and not self.cancel.is_set()
                recovery_retry = False
                if (not planned_retry and exc.retryable and policy_retryable and self.recovery_controller is not None
                        and self.recovery_remaining > 0 and not self.cancel.is_set()):
                    try:
                        decision = self.recovery_controller.decide(
                            step=step, failure=exc, attempt=number + 1,
                            retry_allowed=True, remaining_budget=self.recovery_remaining,
                            recent_events=self.report["events"][-10:],
                        )
                        self.recovery_remaining -= 1
                        recovery_retry = decision.action == "retry"
                        self.report["events"].append({
                            "step_id": step.step_id, "action": "recovery_decision",
                            "decision": decision.action, "reason": decision.reason,
                            "attempt": number + 1,
                        })
                    except Exception as decision_error:
                        self.recovery_remaining = max(0, self.recovery_remaining - 1)
                        self.report["events"].append({
                            "step_id": step.step_id, "action": "recovery_error",
                            "reason": str(decision_error), "fallback": "abort",
                        })
                retry = planned_retry or recovery_retry
                if retry:
                    delay = min(2 ** max(number, 0), 8)
                    self.report["events"].append({
                        "step_id": step.step_id,
                        "action": "planned_retry" if planned_retry else "agent_retry",
                        "reason": str(exc), "wait_seconds": delay,
                    })
                    self.save()
                    self.sleeper(delay)
                    if not self.cancel.is_set() or step.phase == "cleanup":
                        continue
                record["status"] = "failed"
                if step.phase == "cleanup":
                    self.report.update(cleanup="failed", cleanup_error=str(exc))
                elif step.action != "logs" and self.report["status"] == "pending":
                    self.report["status"] = "cancelled" if self.cancel.is_set() else (
                        "environment_error" if step.phase == "deploy" or step.action == "health" else "inconclusive")
                return
            except Exception as exc:
                attempt.update(status="failed", error=str(exc), category="unexpected_error")
                record["status"] = "failed"
                if step.phase == "cleanup":
                    self.report.update(cleanup="failed", cleanup_error=str(exc))
                elif self.report["status"] == "pending":
                    self.report.update(status="execution_error", error=str(exc))
                return
            finally:
                attempt["duration_ms"] = round((time.monotonic() - started) * 1000, 2)
                self.save()

    def dispatch(self, step):
        """根据步骤动作分派到对应 Docker、HTTP、脚本或验证工具。"""
        if step.action == "version":
            import re
            probe = next(p for p in self.card.version_probes if p.id == step.parameters.get("probe_id"))
            evidence = self.lab.probe_version(probe.service, probe.command, timeout=step.timeout_seconds)
            evidence["matched"] = (evidence.get("service") == probe.service and evidence.get("command") == probe.command
                and evidence.get("exit_code") == 0 and not evidence.get("truncated")
                and re.search(probe.expected_pattern, evidence.get("stdout", "") + evidence.get("stderr", "")) is not None)
            if not evidence["matched"]:
                raise StepFailure("Runtime version did not match the trusted requirement", "version_mismatch", evidence=evidence)
            return evidence
        if step.action == "stage_artifacts":
            store = WorkspaceFiles(self.workspace / self.project / "artifacts", writable=True)
            records = []
            for script in [*self.card.initialization, *self.card.scripts]:
                source = local_path(self.kb.root, script.source)
                expected = self.bundle["assets"]["scripts"][script.source]
                if file_hash(source) != expected:
                    raise StepFailure("Script changed after planning", "invalid_artifact")
                with source.open(encoding="utf-8", newline="") as handle:
                    content = handle.read()
                artifact = local_path(store.root, script.id + ".py")
                previous = file_hash(artifact) if artifact.exists() else None
                if previous and previous != expected:
                    raise StepFailure("Artifact already contains different code", "invalid_artifact")
                record = store.write(WriteParams(path=script.id + ".py", content=content, expected_hash=previous))
                self.artifacts[script.id] = artifact
                records.append(record.evidence)
            return {"artifacts": records}
        if step.action in {"initialize", "script"}:
            script = next(p for p in [*self.card.initialization, *self.card.scripts] if p.id == step.parameters.get("probe_id"))
            artifact = self.artifacts[script.id]
            if file_hash(artifact) != self.bundle["assets"]["scripts"][script.source]:
                raise StepFailure("Prepared script changed", "invalid_artifact")
            if self.probe_started_at is None:
                self.probe_started_at = datetime.now(timezone.utc).isoformat()
            evidence = self.lab.run_script(script.service, artifact, args=script.args, environment=script.environment,
                                           timeout=step.timeout_seconds)
            if evidence.get("timed_out") or evidence.get("exit_code") != 0 or evidence.get("cleanup_error"):
                raise StepFailure("Script execution failed", "timeout" if evidence.get("timed_out") else "script_error", evidence=evidence)
            return evidence
        if step.action == "read_file":
            rule = next(p for p in self.card.file_evidence if p.id == step.parameters.get("probe_id"))
            evidence = self.lab.read_container_file(rule.service, rule.path, timeout=step.timeout_seconds)
            self.file_observations[rule.id] = evidence
            return evidence
        if step.action == "keep":
            self.report["cleanup"] = "kept" if self.started else "not_needed"
            return {"kept": self.started}
        if step.action == "down" and not self.started:
            return {"cleanup": "not_needed"}
        if step.action == "verify":
            if self.target_spec.verification_assertions:
                evidence_items = []
                verification_probes = {probe.id: probe for probe in self.card.verification_requests}
                for observation in self.observations:
                    probe = verification_probes.get(observation.get("probe_id"))
                    if probe is None:
                        continue
                    if observation.get("status") is not None:
                        evidence_items.append(Evidence(evidence_id=f"{probe.id}-status", kind="http",
                            source=f"{probe.path}#status", observed_value=observation["status"], summary="HTTP response status"))
                    if observation.get("body") is not None:
                        evidence_items.append(Evidence(evidence_id=f"{probe.id}-body", kind="http",
                            source=f"{probe.path}#body", observed_value=observation["body"], summary="HTTP response body"))
                for rule in self.card.file_evidence:
                    observed = self.file_observations.get(rule.id)
                    if observed and observed.get("regular") is True and not observed.get("truncated"):
                        evidence_items.append(Evidence(evidence_id=rule.id, kind="file", source=rule.path,
                            observed_value=observed.get("body", ""), summary="Target file evidence"))
                if self.logs is not None:
                    evidence_items.append(Evidence(evidence_id="compose-logs", kind="log", source="compose_logs",
                        observed_value=self.logs, summary="Docker Compose logs"))
                outcome = EvidenceVerifier().verify(self.target_spec, evidence_items, self.execution_policy)
                result = {"status": outcome.status, "reason": outcome.summary,
                          "checks": [item.model_dump(mode="json") for item in outcome.checks]}
            else:
                probes = list(self.card.reproduction)
                result = verify(probes, self.observations, self.logs) if probes else {
                    "status": "inconclusive", "checks": [], "reason": "No independent verification assertions were declared"}
            self.report["verification"] = result
            if self.report["status"] == "pending":
                self.report["status"] = result["status"]
            return result
        if step.action in {"health", "http", "verify_http"}:
            probe = self.card.health if step.action == "health" else next(p for p in [*self.card.reproduction, *self.card.verification_requests] if p.id == step.parameters.get("probe_id"))
            if self.probe_started_at is None:
                self.probe_started_at = datetime.now(timezone.utc).isoformat()
            observation = self.requester(self.card.port, probe, timeout=step.timeout_seconds)
            if observation.get("probe_id") != probe.id:
                raise StepFailure("HTTP evidence is bound to another probe", "invalid_evidence")
            if observation.get("error"):
                raise StepFailure(observation["error"], "connection_error", retryable=step.action == "health" or probe.retry_safe, evidence=observation)
            if step.action == "health":
                result = verify([probe], [observation], None)
                if result["status"] != "success":
                    raise StepFailure("HTTP readiness assertion failed", "not_ready", retryable=True, evidence=observation)
            else:
                self.observations.append(observation)
            return observation
        try:
            if self.lab is None:
                self.lab = self.lab_factory(self.kb.environment(self.card), self.workspace, self.project)
                # Verify the prepared snapshot as well as the source.
                if hasattr(self.lab, "compose"):
                    prepared = self.lab.configuration()
                    if digest(json.dumps(prepared, sort_keys=True)) != self.plan.input_fingerprints["compose"]:
                        raise StepFailure("Prepared environment changed", "invalid_environment")
                    if environment_assets(self.lab.compose, prepared, base=self.lab.input_root) != self.bundle["assets"]["environment"]:
                        raise StepFailure("Prepared build or mount inputs changed", "invalid_environment")
            if step.action == "up":
                self.started = True
            params = DockerLabParams(action=step.action, timeout=step.timeout_seconds,
                                     since=self.probe_started_at if step.action == "logs" else None)
            result = self.lab.run(params)
            if step.action == "status" and result.evidence.get("all_running") is not True:
                raise StepFailure("Expected services are not running", "not_ready", retryable=True, evidence=result.evidence)
            if step.action == "logs":
                self.logs = result.output
            if step.action == "down":
                self.report["cleanup"] = "completed"
            return {"output": result.output, **result.evidence}
        except StepFailure:
            raise
        except ToolTimeoutError as exc:
            raise StepFailure(str(exc), "timeout", retryable=step.action in {"pull", "status", "logs", "down"}) from exc
        except Exception as exc:
            message = str(exc).lower()
            transient_pull = step.action == "pull" and any(marker in message for marker in (
                "eof", "connection reset", "tls handshake timeout", "temporary failure", "i/o timeout", "502 bad gateway", "503 service unavailable"))
            raise StepFailure(str(exc), "registry_connection_error" if transient_pull else "tool_error",
                              retryable=transient_pull) from exc

    def finish(self):
        """完成清理、汇总最终状态并保存报告。"""
        try:
            if self.lab is not None and hasattr(self.lab, "cleanup_jobs"):
                try:
                    self.lab.cleanup_jobs()
                except Exception as exc:
                    self.report.update(cleanup="failed", cleanup_error=str(exc))
            # Cleanup is a finalizer: always runs, including interruption paths.
            for step in self.steps("cleanup"):
                if not any(row["step_id"] == step.step_id for row in self.report["steps"]):
                    self.execute_step(step)
            if self.lab is not None and getattr(self.lab, "jobs", None):
                self.report.update(cleanup="failed", cleanup_error="Script containers still require cleanup")
            known = {row["step_id"] for row in self.report["steps"]}
            for step in self.domain_plan.steps:
                if step.step_id not in known:
                    self.report["steps"].append({"step_id": step.step_id, "action": step.action, "phase": step.phase,
                                                "status": "skipped", "reason": "Execution interrupted", "attempts": []})
            self.report["finished_at"] = datetime.now(timezone.utc).isoformat()
            self.save()
        finally:
            self.release()
