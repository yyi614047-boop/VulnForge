"""Compatibility import; canonical hashing lives in app.execution.artifacts."""
from app.execution.artifacts import digest
__all__ = ["digest"]
