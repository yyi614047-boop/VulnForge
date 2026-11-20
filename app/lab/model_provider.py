"""Compatibility import; canonical model configuration lives in app.runtime."""
from app.runtime.models import configured_model
__all__ = ["configured_model"]
