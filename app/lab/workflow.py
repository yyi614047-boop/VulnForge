"""Shared nodes for LangGraph and an explicit dependency-light sequential runner."""
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

from app.lab.http import request, verify
from app.lab.knowledge import KnowledgeBase
from app.tools.docker_lab import DockerLab, DockerLabParams, load_compose


class LabState(TypedDict, total=False):
    identifier: str
    report: dict
    retry: bool


class LabWorkflow:
    def __init__(self, knowledge: Path, workspace: Path, project: str, *, retries=1,
                 timeout=60, keep=False, lab_factory=DockerLab.prepare, requester=request, sleeper=time.sleep):
        """初始化组件及其运行所需的配置、依赖和状态。"""
        if not 0 <= retries <= 3 or not 1 <= timeout <= 300:
            raise ValueError("Retries must be 0..3 and timeout 1..300")
        self.kb = KnowledgeBase(knowledge)
        self.workspace, self.project = workspace, project
        self.retries, self.timeout, self.keep = retries, timeout, keep
        self.lab_factory, self.requester, self.sleep = lab_factory, requester, sleeper
        self.card = self.lab = None
        self.started = False
        self.report = None

    def research(self, state):
        """检索或研究当前实验标识对应的可信资料并产出研究包。"""
        report = {"id": state["identifier"], "project": self.project, "status": "pending", "events": [], "attempts": []}
        self.report = report
        try:
            self.card = self.kb.get(state["identifier"])
            config = load_compose(self.kb.environment(self.card))
            service = config["services"].get(self.card.service, {})
            if not any(p.startswith(f"127.0.0.1:{self.card.port}:") and not p.endswith("/udp") for p in service.get("ports", [])):
                raise ValueError("Card port must belong to its Compose service")
            report["research"] = self.card.model_dump()
            report["environment"] = config
        except Exception as exc:
            report.update(status="information_missing", error=str(exc))
        return {"report": report}

    def plan(self, state):
        """根据研究结果生成并校验结构化执行计划。"""
        report = state["report"]
        if report["status"] == "pending":
            report["plan"] = [
                {"action": "pull", "timeout": self.timeout},
                {"action": "up", "timeout": self.timeout},
                {"action": "status"}, {"action": "health", "probe": self.card.health.id},
                *[{"action": "http", "probe": p.id} for p in self.card.reproduction],
                {"action": "logs"}, {"action": "verify"},
                {"action": "keep" if self.keep else "down"},
            ]
        return {"report": report}

    def docker(self, report, action, **kwargs):
        """调用 Docker 工具执行指定操作并写入结构化诊断。"""
        try:
            result = self.lab.run(DockerLabParams(action=action, timeout=self.timeout, **kwargs))
        except Exception as exc:
            report["events"].append({"action": action, "error": str(exc)})
            raise
        report["events"].append({"action": action, "output": result.output, "evidence": result.evidence})
        return result

    def deploy(self, state):
        """检查 Docker 状态并执行计划中的部署阶段。"""
        report = state["report"]
        if report["status"] != "pending":
            return {"report": report}
        try:
            self.lab = self.lab_factory(self.kb.environment(self.card), self.workspace, self.project)
            self.docker(report, "pull")
            self.started = True  # up can partially create resources before failing
            self.docker(report, "up")
            status = self.docker(report, "status")
            if status.evidence.get("all_running") is not True:
                raise RuntimeError("Expected lab services are not all running")
        except Exception as exc:
            report.update(status="environment_error", error=str(exc))
        return {"report": report}

    def reproduce(self, state):
        """在已完成部署的前提下执行复现阶段。"""
        report = state["report"]
        if report["status"] != "pending":
            return {"report": report}
        attempt = {"number": len(report["attempts"]) + 1, "observations": [],
                   "started_at": datetime.now(timezone.utc).isoformat()}
        report["attempts"].append(attempt)
        health = self.requester(self.card.port, self.card.health)
        attempt["health"] = health
        result = verify([self.card.health], [health], None)
        if result["status"] != "success":
            attempt["verification"] = {"status": "environment_error", "reason": "HTTP readiness check failed", "checks": result["checks"]}
            attempt["retryable"] = True
        else:
            for probe in self.card.reproduction:
                observation = self.requester(self.card.port, probe)
                attempt["observations"].append(observation)
                if observation.get("error"):
                    break
            attempt["retryable"] = bool(any(o.get("error") for o in attempt["observations"])) and all(p.retry_safe for p in self.card.reproduction)
        return {"report": report}

    def verification(self, state):
        """执行独立 HTTP、文件和日志等验证步骤。"""
        report = state["report"]
        logs = None
        if self.lab is not None:
            try:
                since = report["attempts"][-1]["started_at"] if report["attempts"] else None
                logs = self.docker(report, "logs", since=since).output
            except Exception as exc:
                report["events"].append({"action": "logs", "error": str(exc)})
        if report["status"] == "pending":
            attempt = report["attempts"][-1]
            attempt["logs"] = logs
            if "verification" not in attempt:
                attempt["verification"] = verify(self.card.reproduction, attempt["observations"], logs)
            result = attempt["verification"]
            retry = bool(attempt.get("retryable")) and len(report["attempts"]) <= self.retries
            if not retry:
                report.update(status=result["status"], verification=result)
            return {"report": report, "retry": retry}
        return {"report": report, "retry": False}

    def recover(self, state):
        """根据失败状态选择恢复动作并更新实验状态。"""
        report = state["report"]
        attempt = report["attempts"][-1]
        delay = min(2 ** attempt["number"], 8)
        report["events"].append({"action": "recovery", "reason": attempt["verification"]["reason"],
                                 "adjustment": f"wait {delay}s, recheck readiness, then replay retry-safe requests"})
        self.sleep(delay)
        return {"report": report, "retry": False}

    def cleanup(self, state):
        """结束当前实验并保存清理状态和报告。"""
        report = state["report"]
        report["cleanup"] = "not_needed"
        if self.started:
            if self.keep:
                report["cleanup"] = "kept"
            else:
                try:
                    self.docker(report, "down")
                    report["cleanup"] = "completed"
                except Exception as exc:
                    report["cleanup"] = "failed"
                    report["cleanup_error"] = str(exc)
        return {"report": report}

    def graph(self):
        """构建 LangGraph 编排图并连接各实验阶段。"""
        from langgraph.graph import END, StateGraph
        graph = StateGraph(LabState)
        for name in ["research", "plan", "deploy", "reproduce", "verification", "recover", "cleanup"]:
            graph.add_node(name, getattr(self, name))
        graph.set_entry_point("research")
        for first, second in [("research", "plan"), ("plan", "deploy"), ("deploy", "reproduce"), ("reproduce", "verification"), ("recover", "reproduce")]:
            graph.add_edge(first, second)
        graph.add_conditional_edges("verification", lambda state: "recover" if state.get("retry") else "cleanup")
        graph.add_edge("cleanup", END)
        return graph.compile()

    def run(self, identifier: str, report_path: Path, *, engine="langgraph"):
        """启动一次完整实验，并将最终报告写入指定路径。"""
        self.card = self.lab = None
        self.started = False
        self.report = None
        state = {"identifier": identifier}
        # Check graph availability before any side effects.
        graph = self.graph() if engine == "langgraph" else None
        if engine not in {"langgraph", "sequential"}:
            raise ValueError("Unknown workflow engine")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            if graph is not None:
                state = graph.invoke(state, {"recursion_limit": 50})
            else:
                for node in [self.research, self.plan, self.deploy]:
                    state.update(node(state))
                while True:
                    state.update(self.reproduce(state))
                    state.update(self.verification(state))
                    if not state.get("retry"):
                        break
                    state.update(self.recover(state))
                state.update(self.cleanup(state))
        except BaseException as exc:
            report = self.report or {"id": identifier, "events": [], "attempts": []}
            state["report"] = report
            report.update(status="execution_error", error=str(exc))
            state.update(self.cleanup(state))
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
        finally:
            if "report" in state:
                report_path.write_text(json.dumps(state["report"], ensure_ascii=False, indent=2), encoding="utf-8")
        return state["report"]
