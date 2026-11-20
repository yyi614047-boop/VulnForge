"""Compatibility import; canonical deterministic executor lives in app.execution."""
from app.execution.executor import StepExecutor, StepFailure, atomic_json
__all__ = ["StepExecutor", "StepFailure", "atomic_json"]
