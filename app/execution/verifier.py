"""Provider-neutral, deterministic verification over collected evidence."""
import re
from typing import Protocol, Sequence
from app.domain.policies import ExecutionPolicy
from app.domain.results import Evidence, VerificationOutcome, AssertionResult
from app.domain.targets import TargetSpec


class VerificationProvider(Protocol):
    def verify(self, target: TargetSpec, evidence: Sequence[Evidence], policy: ExecutionPolicy) -> VerificationOutcome: ...


class EvidenceVerifier:
    """Evaluate reviewed target assertions independently of planning and reproduction."""

    def verify(self, target: TargetSpec, evidence: Sequence[Evidence], policy: ExecutionPolicy) -> VerificationOutcome:
        policy.authorize_target(target)
        assertions = target.verification_assertions
        if not assertions:
            return VerificationOutcome(status="inconclusive", summary="Target has no reviewed verification assertions.")
        results = []
        for assertion in assertions:
            matches = [item for item in evidence if item.kind == assertion.evidence_kind and item.source == assertion.source]
            if not matches or matches[-1].observed_value is None:
                results.append(AssertionResult(assertion_id=assertion.assertion_id, status="missing",
                    expected_value=assertion.expected_value, reason="Required evidence is missing."))
                continue
            item = matches[-1]
            observed = str(item.observed_value)
            if assertion.operator == "equals":
                matched = observed == assertion.expected_value
            elif assertion.operator == "contains":
                matched = assertion.expected_value in observed
            else:
                matched = re.search(assertion.expected_value, observed) is not None
            results.append(AssertionResult(assertion_id=assertion.assertion_id,
                status="matched" if matched else "mismatched", evidence_id=item.evidence_id,
                expected_value=assertion.expected_value, observed_value=item.observed_value,
                reason="Assertion matched." if matched else "Observed evidence did not satisfy the assertion."))
        required = [result for result, assertion in zip(results, assertions) if assertion.required]
        if not required:
            return VerificationOutcome(status="inconclusive", checks=results, summary="No required verification assertions were declared.")
        if any(result.status == "missing" for result in required):
            status, summary = "inconclusive", "Required verification evidence is missing."
        elif any(result.status == "mismatched" for result in required):
            status, summary = "not_reproduced", "One or more required assertions did not match."
        else:
            status, summary = "success", "All required independent assertions matched."
        return VerificationOutcome(status=status, checks=results, summary=summary)
