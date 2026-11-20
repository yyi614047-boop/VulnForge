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


class Pipeline:
    def __init__(self, knowledge: Path, workspace: Path, project: str, *, llm=None, retries=1, timeout=60, keep=False, executor_options=None,
                 docker_engine=None, engine_timeout=120, auto_port=False):
        """初始化组件及其运行所需的配置、依赖和状态。"""
        self._run_lock = Lock()
        self.knowledge, self.workspace, self.project = knowledge, workspace, project
        self.researcher = Researcher(knowledge, llm)
        self.planner = StructuredPlanner(llm)
        self.recovery_controller = RecoveryController(llm) if llm is not None else None
        self.retries, self.timeout, self.keep = retries, timeout, keep
        self.executor_options = executor_options or {}
        self.executor = None
        self.active = False
        self.docker_engine, self.engine_timeout = docker_engine, engine_timeout
        self.auto_port, self.port_selection = auto_port, None

    @state_boundary(reads=['identifier'], writes=['bundle', 'status', 'error'])
    def research(self, state):
        """读取实验标识并检索可信资料，更新管线研究状态。"""
        try:
            return {"bundle": self.researcher.research(state["identifier"]), "status": "researched"}
        except Exception as exc:
            return {"status": "information_missing", "error": str(exc)}

    @state_boundary(reads=['status', 'bundle'], writes=['plan', 'status', 'error'])
    def plan(self, state):
        """根据研究包生成结构化计划并更新管线规划状态。"""
        if state.get("status") != "researched":
            return {}
        try:
            plan = self.planner.generate(state["bundle"], retries=self.retries, timeout=self.timeout, keep=self.keep)
            return {"plan": plan.model_dump(), "status": "planned"}
        except Exception as exc:
            return {"status": "invalid_plan", "error": str(exc)}

    @state_boundary(reads=['status', 'plan', 'bundle'], writes=['status', 'engine', 'error'])
    def deploy(self, state):
        """确保 Docker 就绪并部署计划中的实验环境。"""
        if state.get("status") != "planned":
            return {}
        engine = {}
        try:
            if self.docker_engine is not None:
                engine = self.docker_engine.ensure(EngineParams(timeout=self.engine_timeout)).evidence
                if not engine["ready"]:
                    return {"status": "environment_error", "engine": engine,
                            "error": engine.get("error", engine.get("last_probe_error", "Docker engine unavailable"))}
            self.executor.open(self.planner_plan(state), state["bundle"], retries=self.retries, timeout=self.timeout, keep=self.keep)
            self.active = True
            if engine:
                self.executor.report["engine"] = engine
                self.executor.save()
            self.executor.execute_phase("deploy")
            return {"status": self.executor.report["status"]}
        except Exception as exc:
            return {"status": "environment_error", "error": str(exc), "engine": engine}

    @staticmethod
    def planner_plan(state):
        """把管线状态中的字典形式计划转换为 Pydantic 模型。"""
        from app.lab.planning import DeploymentPlan
        return DeploymentPlan.model_validate(state["plan"])

    @state_boundary(reads=[], writes=['status'])
    def reproduce(self, state):
        """执行复现阶段中的脚本或 HTTP 请求。"""
        if self.active:
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
                           "research": state.get("bundle"), "plan": state.get("plan")}}

    def graph(self):
        """构建 LangGraph 编排图并连接各实验阶段。"""
        from langgraph.graph import END, StateGraph
        graph = StateGraph(PipelineState)
        names = ["researcher", "planner", "deployer", "reproducer", "verifier", "cleanup"]
        for name, node in zip(names, [self.research, self.plan, self.deploy, self.reproduce, self.verification, self.cleanup]):
            graph.add_node(name, node)
        graph.set_entry_point("researcher")
        graph.add_conditional_edges("researcher", lambda s: "planner" if s["status"] == "researched" else "cleanup")
        graph.add_conditional_edges("planner", lambda s: "deployer" if s["status"] == "planned" else "cleanup")
        graph.add_edge("deployer", "reproducer")
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
        self.port_selection = None
        graph = self.graph()
        if report_path.exists():
            raise FileExistsError("Report exists; choose a new report path")
        if self.auto_port:
            from app.lab.ports import prepare_port
            try:
                self.knowledge, self.port_selection = prepare_port(self.knowledge, self.workspace, identifier)
                self.researcher.knowledge = self.knowledge
            except (ValueError, OSError) as exc:
                report = {"id": identifier, "status": "information_missing", "cleanup": "not_needed", "error": str(exc)}
                atomic_json(report_path, report)
                return report
        executor_options = dict(self.executor_options)
        executor_options.setdefault("recovery_controller", self.recovery_controller)
        executor_options.setdefault("recovery_budget", 1 if self.recovery_controller is not None else 0)
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
            if "report" in state and self.port_selection:
                state["report"]["port_selection"] = self.port_selection
                atomic_json(report_path, state["report"])
            if "report" in state and not report_path.exists():
                atomic_json(report_path, state["report"])
        return state["report"]
