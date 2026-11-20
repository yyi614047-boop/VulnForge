"""Durable sequential task queue: resume pending work without replaying ambiguity."""
import json
import os
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from app.execution.artifacts import snapshot
from app.workflows.reproduction.graph import Pipeline
from app.execution.executor import atomic_json
from app.tools.builtin.filesystem import file_hash, local_path


@contextmanager
def batch_lock(path):
    """使用文件锁确保同一批次不会被并发恢复。"""
    # OS locks are released even when the owner crashes. Keep the lock file so
    # competing processes always synchronize on the same inode/file object.
    with path.open("a+b") as handle:
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise ValueError("Batch already has a live owner") from exc
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class Batch:
    def __init__(self, *, pipeline_factory=Pipeline, docker_engine=None):
        """初始化组件及其运行所需的配置、依赖和状态。"""
        self.pipeline_factory, self.docker_engine = pipeline_factory, docker_engine

    def create(self, identifiers, knowledge, workspace, path, *, timeout=60):
        """创建新的顺序批量任务队列及初始任务状态。"""
        path = Path(path)
        if path.exists():
            raise FileExistsError("Batch report exists")
        if not 1 <= len(identifiers) <= 100 or not 1 <= timeout <= 300:
            raise ValueError("Batch requires 1..100 tasks and a 1..300 second step budget")
        root = Path(workspace).resolve() / ("batch-" + uuid4().hex[:12])
        seed = root / "knowledge"
        snapshot(Path(knowledge), seed)
        manifest = {p.relative_to(seed).as_posix(): file_hash(p) for p in seed.rglob("*") if p.is_file()}
        report = {"schema_version": 1, "status": "pending", "root": str(root), "manifest": manifest,
                  "timeout": timeout, "tasks": [{"id": identifier, "status": "pending"} for identifier in identifiers]}
        atomic_json(path, report)
        return self.resume(path)

    def resume(self, path):
        """检查并恢复尚未完成或状态不明确的批量任务。"""
        path = Path(path)
        with batch_lock(path.with_name(path.name + ".lock")):
            return self._resume_locked(path)

    def _resume_locked(self, path):
        """在持有批次锁的情况下执行批量任务续跑逻辑。"""
        report = json.loads(path.read_text(encoding="utf-8"))
        try:
            if report.get("schema_version") != 1:
                raise ValueError("Unsupported batch report schema")
            root = Path(report["root"])
            seed = root / "knowledge"
            actual = {p.relative_to(seed).as_posix(): file_hash(local_path(seed, p.relative_to(seed).as_posix()))
                      for p in seed.rglob("*") if p.is_file()}
            if actual != report["manifest"]:
                raise ValueError("Batch knowledge snapshot changed; do not resume")
            report["status"] = "running"
            for number, task in enumerate(report["tasks"]):
                if task["status"] == "completed":
                    if task.get("cleanup") not in {"completed", "not_needed"}:
                        report["status"] = "cleanup_failed"
                        break
                    continue
                if task["status"] in {"running", "needs_reconciliation"}:
                    previous = Path(task["report"])
                    execution = json.loads(previous.read_text(encoding="utf-8")) if previous.exists() else {}
                    if execution.get("finished_at") and execution.get("cleanup") in {"completed", "not_needed"}:
                        task.update(status="completed", result=execution["status"], cleanup=execution["cleanup"])
                        atomic_json(path, report)
                        continue
                    task["status"] = "needs_reconciliation"
                    report["status"] = "needs_reconciliation"
                    break
                project = "lab-batch-" + uuid4().hex[:12]
                execution_path = root / "tasks" / f"{number+1}.json"
                task.update(status="running", project=project, report=str(execution_path))
                atomic_json(path, report)
                flow = self.pipeline_factory(seed, root / "labs", project, timeout=report["timeout"],
                                             docker_engine=self.docker_engine, auto_port=True)
                execution = flow.run(task["id"], execution_path)
                task.update(status="completed", result=execution["status"], cleanup=execution.get("cleanup"))
                atomic_json(path, report)
                if execution.get("cleanup") not in {"completed", "not_needed"}:
                    report["status"] = "cleanup_failed"
                    break
            else:
                report["status"] = "success" if all(t.get("result") == "success" for t in report["tasks"]) else "completed_with_failures"
        except BaseException as exc:
            report.update(status="interrupted" if isinstance(exc, KeyboardInterrupt) else "batch_error", error=str(exc))
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
        finally:
            atomic_json(path, report)
        return report
