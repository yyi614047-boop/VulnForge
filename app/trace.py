"""Compatibility import; canonical tracing lives in app.runtime."""
from app.runtime.tracing import traced_call
__all__ = ["traced_call"]
