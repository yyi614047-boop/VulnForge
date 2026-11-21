"""LangGraph is the orchestration layer; components are independently testable."""
from pathlib import Path
from threading import Lock
import os

from app.runtime.context import isolated_run, state_boundary
from app.runtime.tracing import TraceRecorder, emit

from app.agents.planner import StructuredPlanner
from app.agents.recovery import RecoveryController
from app.execution.executor import StepExecutor, atomic_json
from app.agents.researcher import Researcher
from app.environments.docker.engine import EngineParams
from app.workflows.reproduction.state import PipelineState
from app.domain.policies import ExecutionPolicy
from app.domain.plans import ExecutionPlan
from app.domain.targets import TargetSpec
from app.domain.reproduction import ReproductionSpec
from app.targets.vulhub.catalog import TargetCatalog
from app.workflows.reproduction.metasploit import MetasploitCandidateRunner


class Pipeline:
    def __init__(self, knowledge: Path, workspace: Path, project: str, *, llm=None, retries=1, timeout=60, keep=False, executor_options=None,
                 docker_engine=None, engine_timeout=120, execution_policy: ExecutionPolicy | None = None,
                 poc_discovery=None, metasploit_adapter=None, metasploit_check_only=False):
        """初始化组件及其运行所需的配置、依赖和状态。"""
        self._run_lock = Lock()
        self.knowledge, self.workspace, self.project = knowledge, workspace, project
        self.researcher = Researcher(knowledge, llm, poc_discovery=poc_discovery)
        self.planner = StructuredPlanner(llm)
        self.recovery_controller = RecoveryController(llm) if llm is not None else None
        self.retries, self.timeout, self.keep = retries, timeout, keep
        self.executor_options = executor_options or {}
        self.executor = None
        self.active = False
        self.docker_engine, self.engine_timeout = docker_engine, engine_timeout
        self.execution_policy = execution_policy
        self.metasploit_adapter = metasploit_adapter
        self.metasploit_check_only = metasploit_check_only
        self._metasploit_network_context = None

    @state_boundary(reads=['identifier'], writes=['bundle', 'status', 'error'])
    def research(self, state):
        """读取实验标识并检索可信资料，更新管线研究状态。"""
        try:
            return {"bundle": self.researcher.research(state["identifier"]), "status": "researched"}
        except Exception as exc:
            return {"status": "information_missing", "error": str(exc)}

    @state_boundary(reads=['status', 'bundle', 'identifier'], writes=['plan', 'target_spec', 'reproduction_spec', 'status', 'error'])
    def plan(self, state):
        """Generate the canonical domain plan against the selected target and policy."""
        if state.get("status") != "researched":
            return {}
        try:
            catalog = TargetCatalog(self.knowledge)
            reproduction_spec = catalog.get(state["identifier"])
            target_spec = catalog.to_target_spec(reproduction_spec)
            if self.execution_policy is None:
                return {"status": "policy_denied", "error": "ExecutionPolicy is required before planning or execution"}
            plan = self.planner.generate(
                state["bundle"], target=target_spec, spec=reproduction_spec,
                policy=self.execution_policy, retries=self.retries, timeout=self.timeout, keep=self.keep,
            )
            return {
                "plan": plan.model_dump(mode="json"),
                "target_spec": target_spec.model_dump(mode="json"),
                "reproduction_spec": reproduction_spec.model_dump(mode="json"),
                "status": "planned",
            }
        except Exception as exc:
            return {"status": "invalid_plan", "error": str(exc)}

    @state_boundary(reads=['status', 'plan', 'bundle', 'target_spec', 'reproduction_spec'], writes=['status', 'engine', 'error', 'deployment_ready'])
    def deploy(self, state):
        """Revalidate the canonical plan before starting Docker or target processes."""
        if state.get("status") != "planned":
            return {"deployment_ready": False}
        if self.execution_policy is None:
            return {"status": "policy_denied", "error": "ExecutionPolicy is required before deployment", "deployment_ready": False}
        try:
            plan = ExecutionPlan.model_validate(state["plan"])
            target = TargetSpec.model_validate(state["target_spec"])
            reproduction = ReproductionSpec.model_validate(state["reproduction_spec"])
            plan.validate_policy(self.execution_policy, target, reproduction)
            if plan.input_fingerprints != {
                "reproduction": state["bundle"]["card_hash"],
                "compose": state["bundle"]["compose_hash"],
                "assets": state["bundle"]["assets_hash"],
                "poc_candidates": state["bundle"].get("poc_candidates_hash", __import__("hashlib").sha256(b"[]").hexdigest()),
            }:
                raise PermissionError("Plan provenance changed after planning")
        except Exception as exc:
            return {"status": "policy_denied", "error": str(exc), "deployment_ready": False}
        engine = {}
        try:
            self.executor.open(plan, state["bundle"], execution_policy=self.execution_policy,
                               target_spec=target, reproduction_spec=reproduction)
            self.active = True
            if self.docker_engine is not None:
                engine = self.docker_engine.ensure(EngineParams(timeout=self.engine_timeout)).evidence
                if not engine["ready"]:
                    message = engine.get("error", engine.get("last_probe_error", "Docker engine unavailable"))
                    self.executor.report.update(status="environment_error", error=message)
                    self.executor.save()
                    return {"status": "environment_error", "engine": engine,
                            "error": message, "deployment_ready": False}
            if engine:
                self.executor.report["engine"] = engine
                self.executor.save()
            self.executor.execute_phase("deploy")
            ready = self.executor.report["status"] == "pending"
            return {"status": self.executor.report["status"], "deployment_ready": ready}
        except PermissionError as exc:
            if self.active and self.executor.report is not None:
                self.executor.report.update(status="policy_denied", error=str(exc))
                self.executor.save()
            return {"status": "policy_denied", "error": str(exc), "engine": engine, "deployment_ready": False}
        except Exception as exc:
            if self.active and self.executor.report is not None:
                self.executor.report.update(status="environment_error", error=str(exc))
                self.executor.save()
            return {"status": "environment_error", "error": str(exc), "engine": engine, "deployment_ready": False}

    @state_boundary(reads=['status', 'deployment_ready', 'plan', 'bundle', 'target_spec', 'reproduction_spec'], writes=['status', 'poc_execution', 'error'])
    def metasploit(self, state):
        """在本地实验范围内执行已审批的 Metasploit 候选。"""
        if state.get("deployment_ready") is not True or not self.active or self.executor.report.get("status") != "pending":
            return {}
        plan = ExecutionPlan.model_validate(state["plan"])
        if not plan.selected_poc_candidate_id:
            result = {"status": "inconclusive", "reason": "Planner did not select an independently checkable Metasploit candidate"}
            if self.metasploit_check_only:
                self.executor.report["status"] = "inconclusive"
                self.executor.report["metasploit"] = result
                self.executor.save()
                return {"poc_execution": result, "status": "inconclusive"}
            return {"poc_execution": {"status": "skipped", "reason": "Planner did not select a Metasploit candidate"}}
        if self.metasploit_adapter is None:
            result = {"status": "inconclusive" if self.metasploit_check_only else "skipped",
                      "reason": "Metasploit adapter is not enabled"}
            self.executor.report["metasploit"] = result
            if result["status"] == "inconclusive":
                self.executor.report["status"] = "inconclusive"
            self.executor.save()
            return {"poc_execution": result, "status": self.executor.report["status"]}
        try:
            target = TargetSpec.model_validate(state["target_spec"])
            reproduction = ReproductionSpec.model_validate(state["reproduction_spec"])
            network_name = self.execution_policy.approved_lab_networks.get(target.target_id)
            metasploit_container = os.environ.get("MSF_CONTAINER_NAME", "")
            if not network_name or not metasploit_container:
                raise PermissionError("Metasploit requires an explicitly approved internal lab network and MSF_CONTAINER_NAME")
            if self.executor.lab is None or not hasattr(self.executor.lab, "resolve_target_endpoint"):
                raise PermissionError("The active Docker lab cannot attest the selected target endpoint")
            self._metasploit_network_context = (network_name, metasploit_container)
            network_setup = self.executor.lab.prepare_metasploit_container(
                network_name, metasploit_container,
                container_rpc_port=int(os.getenv("MSFRPC_CONTAINER_PORT", "55553")),
            )
            attestation = self.executor.lab.resolve_target_endpoint(
                reproduction.service, reproduction.port, network_name=network_name,
                metasploit_container=metasploit_container,
            )
            if attestation.get("project") != self.project:
                raise PermissionError("Docker target attestation belongs to a different lab project")
            runner = MetasploitCandidateRunner(self.metasploit_adapter)
            run_method = runner.verify if self.metasploit_check_only else runner.run
            result = run_method(
                plan=plan, bundle=state["bundle"], target=target,
                reproduction=reproduction, policy=self.execution_policy,
                target_attestation=attestation,
            )
            result["network_setup"] = network_setup
            self.executor.report["metasploit"] = result
            if result["status"] == "not_reproduced":
                self.executor.report["status"] = "not_reproduced"
            elif result["status"] == "inconclusive":
                self.executor.report["status"] = "inconclusive"
            elif result["status"] == "failed":
                self.executor.report.update(status="execution_error", error="Metasploit execution or session cleanup failed")
            self.executor.save()
            return {"poc_execution": result, "status": self.executor.report["status"]}
        except PermissionError as exc:
            self.executor.report.update(status="policy_denied", error=str(exc))
            self.executor.report["metasploit"] = {"status": "policy_denied", "reason": str(exc)}
            self.executor.save()
            return {"status": "policy_denied", "error": str(exc)}
        except Exception as exc:
            self.executor.report.update(status="execution_error", error=str(exc))
            self.executor.report["metasploit"] = {"status": "failed", "reason": str(exc)}
            self.executor.save()
            return {"status": "execution_error", "error": str(exc)}

    @state_boundary(reads=['status', 'deployment_ready'], writes=['status'])
    def reproduce(self, state):
        """执行复现阶段中的脚本或 HTTP 请求。"""
        if state.get("deployment_ready") is True and self.active and self.executor.report.get("status") == "pending":
            self.executor.execute_phase("reproduce")
            return {"status": self.executor.report["status"]}
        return {}

    @state_boundary(reads=['deployment_ready'], writes=['status'])
    def verification(self, state):
        """执行独立验证步骤并产出成功判据，即使 Metasploit 结论不确定也保留证据。"""
        if (state.get("deployment_ready") is True and self.active
                and self.executor.report.get("status") in {"pending", "inconclusive", "not_reproduced"}):
            self.executor.execute_phase("verify")
            return {"status": self.executor.report["status"]}
        return {}

    @state_boundary(reads=['identifier', 'status', 'error', 'engine', 'bundle', 'plan'], writes=['report', 'status'])
    def cleanup(self, state):
        """清理实验资源并保存最终执行报告。"""
        if self.active:
            if self._metasploit_network_context is not None:
                network_name, container_name = self._metasploit_network_context
                try:
                    network_cleanup = self.executor.lab.restore_metasploit_container(
                        network_name, container_name,
                    )
                    self.executor.report.setdefault("metasploit", {})["network_cleanup"] = network_cleanup
                except Exception as exc:
                    self.executor.report.update(
                        status="execution_error", cleanup="failed",
                        cleanup_error=f"Metasploit network cleanup failed: {exc}",
                    )
                finally:
                    self._metasploit_network_context = None
            self.executor.finish()
            self.active = False
            return {"report": self.executor.report, "status": self.executor.report["status"]}
        return {"report": {"id": state["identifier"], "status": state.get("status", "execution_error"),
                           "error": state.get("error"), "cleanup": "not_needed",
                           "engine": state.get("engine"),
                           "research": state.get("bundle"), "plan": state.get("plan"),
                           "plan": state.get("plan")}}

    def graph(self):
        """构建 LangGraph 编排图并连接各实验阶段。"""
        from langgraph.graph import END, StateGraph
        graph = StateGraph(PipelineState)
        names = ["researcher", "planner", "deployer", "metasploit", "reproducer", "verifier", "cleanup"]
        for name, node in zip(names, [self.research, self.plan, self.deploy, self.metasploit, self.reproduce, self.verification, self.cleanup]):
            graph.add_node(name, node)
        graph.set_entry_point("researcher")
        graph.add_conditional_edges("researcher", lambda s: "planner" if s["status"] == "researched" else "cleanup")
        graph.add_conditional_edges("planner", lambda s: "deployer" if s["status"] == "planned" else "cleanup")
        graph.add_edge("deployer", "reproducer")
        graph.add_edge("reproducer", "metasploit")
        graph.add_edge("metasploit", "verifier")
        graph.add_edge("verifier", "cleanup")
        graph.add_edge("cleanup", END)
        return graph.compile()

    def run(self, identifier, report_path):
        """启动一次完整实验，并将最终报告写入指定路径。"""
        if not self._run_lock.acquire(blocking=False):
            raise RuntimeError("Pipeline instance already running; use a separate instance")
        try:
            return self._run_isolated(identifier, report_path)
        finally:
            self.active = False
            self.executor = None
            self._run_lock.release()

    @isolated_run
    def _run_isolated(self, identifier, report_path):
        """在隔离上下文中执行指定工作流引擎对应的一次实验。"""
        self.active = False
        graph = self.graph()
        if report_path.exists():
            raise FileExistsError("Report exists; choose a new report path")
        executor_options = dict(self.executor_options)
        executor_options.setdefault("recovery_controller", self.recovery_controller)
        policy_recovery_budget = self.execution_policy.max_recovery_actions if self.execution_policy else 0
        executor_options.setdefault("recovery_budget", min(1, policy_recovery_budget)
                                     if self.recovery_controller is not None else 0)
        self.executor = StepExecutor(self.knowledge, self.workspace, self.project, report_path, **executor_options)
        trace_path = report_path.with_suffix(".trace.jsonl")
        if trace_path.exists():
            raise FileExistsError("Trace exists; choose a new report path")
        state = {"identifier": identifier}
        with TraceRecorder(trace_path, self.project):
            emit("run.start", identifier=identifier, report=str(report_path))
            try:
                for update in graph.stream(state, stream_mode="updates"):
                    for node, changes in update.items():
                        if isinstance(changes, dict):
                            state.update(changes)
                            emit("stage.end", stage=node, status=state.get("status"),
                                 updated_keys=sorted(changes))
                emit("run.end", status=state.get("status"))
            except BaseException as exc:
                emit("run.error", error_type=type(exc).__name__)
                if self.active:
                    self.executor.report.update(status="cancelled" if isinstance(exc, KeyboardInterrupt) else "execution_error", error=str(exc))
                state.update(status="execution_error", error=str(exc))
                state.update(self.cleanup(state))
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
            finally:
                if "report" in state:
                    state["report"]["trace_path"] = str(trace_path)
                    if self.executor.report is not None:
                        self.executor.report["trace_path"] = str(trace_path)
                        self.executor.save()
                    elif not report_path.exists():
                        atomic_json(report_path, state["report"])
        return state["report"]
