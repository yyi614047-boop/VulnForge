"""LangGraph is the orchestration layer; components are independently testable."""
from pathlib import Path
from threading import Lock

from app.runtime.context import isolated_run, state_boundary

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
                 poc_discovery=None, metasploit_adapter=None):
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

    @state_boundary(reads=['status', 'plan', 'bundle', 'target_spec', 'reproduction_spec'], writes=['status', 'engine', 'error'])
    def deploy(self, state):
        """Revalidate the canonical plan before starting Docker or target processes."""
        if state.get("status") != "planned":
            return {}
        if self.execution_policy is None:
            return {"status": "policy_denied", "error": "ExecutionPolicy is required before deployment"}
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
            return {"status": "policy_denied", "error": str(exc)}
        engine = {}
        try:
            self.executor.open(plan, state["bundle"], execution_policy=self.execution_policy,
                               target_spec=target, reproduction_spec=reproduction)
            self.active = True
            if self.docker_engine is not None:
                engine = self.docker_engine.ensure(EngineParams(timeout=self.engine_timeout)).evidence
                if not engine["ready"]:
                    return {"status": "environment_error", "engine": engine,
                            "error": engine.get("error", engine.get("last_probe_error", "Docker engine unavailable"))}
            if engine:
                self.executor.report["engine"] = engine
                self.executor.save()
            self.executor.execute_phase("deploy")
            return {"status": self.executor.report["status"]}
        except PermissionError as exc:
            return {"status": "policy_denied", "error": str(exc), "engine": engine}
        except Exception as exc:
            return {"status": "environment_error", "error": str(exc), "engine": engine}

    @state_boundary(reads=['status', 'plan', 'bundle', 'target_spec', 'reproduction_spec'], writes=['status', 'poc_execution', 'error'])
    def metasploit(self, state):
        """在本地实验范围内执行已审批的 Metasploit 候选。"""
        if not self.active or self.executor.report.get("status") != "pending":
            return {}
        plan = ExecutionPlan.model_validate(state["plan"])
        if not plan.selected_poc_candidate_id:
            return {"poc_execution": {"status": "skipped", "reason": "Planner did not select a Metasploit candidate"}}
        if self.metasploit_adapter is None:
            result = {"status": "skipped", "reason": "Metasploit execution was not explicitly enabled"}
            self.executor.report["metasploit"] = result
            self.executor.save()
            return {"poc_execution": result}
        try:
            target = TargetSpec.model_validate(state["target_spec"])
            reproduction = ReproductionSpec.model_validate(state["reproduction_spec"])
            result = MetasploitCandidateRunner(self.metasploit_adapter).run(
                plan=plan, bundle=state["bundle"], target=target,
                reproduction=reproduction, policy=self.execution_policy,
            )
            self.executor.report["metasploit"] = result
            if result["status"] == "not_reproduced":
                self.executor.report["status"] = "not_reproduced"
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

    @state_boundary(reads=['status'], writes=['status'])
    def reproduce(self, state):
        """执行复现阶段中的脚本或 HTTP 请求。"""
        if self.active and self.executor.report.get("status") == "pending":
            self.executor.execute_phase("reproduce")
            return {"status": self.executor.report["status"]}
        return {}

    @state_boundary(reads=[], writes=['status'])
    def verification(self, state):
        """执行独立验证步骤并产出成功判据。"""
        if self.active:
            self.executor.execute_phase("verify")
            return {"status": self.executor.report["status"]}
        return {}

    @state_boundary(reads=['identifier', 'status', 'error', 'engine', 'bundle', 'plan'], writes=['report', 'status'])
    def cleanup(self, state):
        """清理实验资源并保存最终执行报告。"""
        if self.active:
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
        graph.add_edge("deployer", "metasploit")
        graph.add_edge("metasploit", "reproducer")
        graph.add_edge("reproducer", "verifier")
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
        state = {"identifier": identifier}
        try:
            state = graph.invoke(state)
        except BaseException as exc:
            if self.active:
                self.executor.report.update(status="cancelled" if isinstance(exc, KeyboardInterrupt) else "execution_error", error=str(exc))
            state.update(status="execution_error", error=str(exc))
            state.update(self.cleanup(state))
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
        finally:
            if "report" in state and not report_path.exists():
                atomic_json(report_path, state["report"])
        return state["report"]
