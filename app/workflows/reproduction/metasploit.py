"""Policy-gated orchestration for one selected Metasploit candidate in a local lab."""
from app.domain.poc import PoCCandidate
from app.domain.poc_execution import build_poc_execution_spec
from app.domain.plans import ExecutionPlan
from app.domain.policies import ExecutionPolicy
from app.domain.reproduction import ReproductionSpec
from app.domain.targets import TargetSpec


class MetasploitCandidateRunner:
    """Run Check, conditionally Execute, then defer verification to independent assertions."""

    def __init__(self, adapter):
        self.adapter = adapter

    def run(self, *, plan: ExecutionPlan, bundle: dict, target: TargetSpec,
            reproduction: ReproductionSpec, policy: ExecutionPolicy) -> dict:
        selected_id = plan.selected_poc_candidate_id
        if not selected_id:
            return {"status": "skipped", "reason": "No Metasploit candidate selected"}
        if plan.target_id != target.target_id or plan.policy_id != policy.policy_id:
            raise PermissionError("Plan target or policy binding changed before Metasploit execution")
        if plan.input_fingerprints.get("poc_candidates") != bundle.get("poc_candidates_hash"):
            raise PermissionError("PoC candidate discovery data changed after planning")
        matches = [row for row in (bundle.get("poc_candidates") or []) if row.get("candidate_id") == selected_id]
        if len(matches) != 1:
            raise PermissionError("Selected Metasploit candidate is absent or ambiguous in the reviewed research bundle")
        candidate = PoCCandidate.model_validate(matches[0])
        if candidate.source != "metasploit":
            raise PermissionError("Selected candidate is not a Metasploit module")
        policy.authorize_target(target, reproduction)
        spec, compatibility = build_poc_execution_spec(
            candidate, target, target_host="127.0.0.1", target_port=reproduction.port,
        )
        check = self.adapter.check(spec, candidate, target, policy, timeout=min(60, policy.max_timeout_seconds))
        check_payload = check.model_dump(mode="json")
        if check.status != "completed" or check.result_code != "vulnerable":
            status = "not_reproduced" if check.result_code in {"safe", "not_vulnerable"} else "inconclusive"
            return {
                "status": status, "candidate_id": candidate.candidate_id,
                "compatibility": compatibility.model_dump(mode="json"),
                "check": check_payload, "execution": None, "verification": "not_started",
            }
        execution = self.adapter.execute(
            spec, candidate, target, policy, check, timeout=min(120, policy.max_timeout_seconds),
        )
        return {
            "status": "executed" if execution.status == "completed" else "failed",
            "candidate_id": candidate.candidate_id,
            "compatibility": compatibility.model_dump(mode="json"),
            "check": check_payload,
            "execution": execution.model_dump(mode="json"),
            "verification": "pending_independent_assertions",
        }
