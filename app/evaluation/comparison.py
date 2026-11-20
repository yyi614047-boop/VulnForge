"""Run identical reproduction/assertions against vulnerable and fixed fixtures."""
from pathlib import Path
from uuid import uuid4

from app.execution.artifacts import snapshot
from app.targets.vulhub.legacy_cards import KnowledgeBase
from app.workflows.reproduction.graph import Pipeline
from app.execution.executor import atomic_json
from app.tools.builtin.filesystem import file_hash, local_path


def comparable(first, second):
    """检查两份知识卡是否具备可对比的相同复现步骤和断言。"""
    left_kb, left = first
    right_kb, right = second
    for field in ["health", "reproduction", "initialization", "scripts", "verification_requests", "file_evidence"]:
        if getattr(left, field) != getattr(right, field):
            raise ValueError("Comparison requires identical probes, scripts, initialization and assertions")
    for script in [*left.initialization, *left.scripts]:
        if file_hash(local_path(left_kb.root, script.source)) != file_hash(local_path(right_kb.root, script.source)):
            raise ValueError("Comparison scripts differ between versions")


def compare_versions(knowledge, fixed_knowledge, identifier, fixed_identifier, workspace, report_path,
                     *, timeout=60, docker_engine=None, pipeline_factory=Pipeline):
    """分别运行原始和修复版本，并汇总是否存在可确认的结果差异。"""
    report_path = Path(report_path)
    if report_path.exists():
        raise FileExistsError("Comparison report exists")
    run_id = "lab-compare-" + uuid4().hex[:12]
    root = Path(workspace) / run_id
    original, patched = root / "inputs/vulnerable", root / "inputs/fixed"
    snapshot(Path(knowledge), original)
    snapshot(Path(fixed_knowledge), patched)
    knowledge, fixed_knowledge = original, patched
    kb, fixed_kb = KnowledgeBase(knowledge), KnowledgeBase(fixed_knowledge)
    comparable((kb, kb.get(identifier)), (fixed_kb, fixed_kb.get(fixed_identifier)))
    report = {"status": "running", "arms": {}}
    atomic_json(report_path, report)
    try:
        for label, source, card_id in [("vulnerable", knowledge, identifier), ("fixed", fixed_knowledge, fixed_identifier)]:
            path = root / (label + ".json")
            report["arms"][label] = {"report": str(path.resolve()), "status": "running"}
            atomic_json(report_path, report)
            execution = pipeline_factory(Path(source), root / "labs", f"{run_id}-{label}",
                timeout=timeout, docker_engine=docker_engine, auto_port=True,
                ).run(card_id, path)
            report["arms"][label].update(status=execution["status"], cleanup=execution.get("cleanup"),
                verification=execution.get("verification"),
                failed_steps=[s["action"] for s in execution.get("steps", []) if s["status"] == "failed"])
            if execution.get("cleanup") not in {"completed", "not_needed"}:
                report["status"] = "cleanup_failed"
                break
            if execution["status"] not in {"success", "not_reproduced"}:
                report["status"] = "inconclusive"
                break
        else:
            vulnerable, fixed = report["arms"]["vulnerable"], report["arms"]["fixed"]
            report["status"] = ("confirmed_difference" if vulnerable["status"] == "success" and
                                fixed["status"] == "not_reproduced" and not vulnerable["failed_steps"] and
                                not fixed["failed_steps"] else "difference_not_confirmed")
    except Exception as exc:
        report.update(status="comparison_error", error=str(exc))
    finally:
        atomic_json(report_path, report)
    return report
