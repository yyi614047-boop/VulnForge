from app.lab.recovery_controller import RecoveryController


class FakeStructuredModel:
    def __init__(self, action="retry"):
        self.action = action

    def with_structured_output(self, _schema):
        return self

    def invoke(self, _prompt):
        return {"action": self.action, "reason": "Transient connection failure; retry once."}


class FakeStep:
    def model_dump(self):
        return {"id": "step-1", "action": "pull"}


class FakeFailure(Exception):
    category = "registry_connection_error"
    retryable = True
    evidence = {"status": 503}


def test_recovery_controller_allows_policy_approved_retry():
    controller = RecoveryController(FakeStructuredModel("retry"))
    decision = controller.decide(
        step=FakeStep(), failure=FakeFailure("temporary registry error"),
        attempt=2, retry_allowed=True, remaining_budget=1, recent_events=[],
    )
    assert decision.action == "retry"


def test_recovery_controller_cannot_override_retry_policy():
    controller = RecoveryController(FakeStructuredModel("retry"))
    decision = controller.decide(
        step=FakeStep(), failure=FakeFailure("non-retryable"),
        attempt=1, retry_allowed=False, remaining_budget=1, recent_events=[],
    )
    assert decision.action == "abort"


def test_recovery_controller_can_abort():
    controller = RecoveryController(FakeStructuredModel("abort"))
    decision = controller.decide(
        step=FakeStep(), failure=FakeFailure("persistent failure"),
        attempt=2, retry_allowed=True, remaining_budget=1, recent_events=[],
    )
    assert decision.action == "abort"
