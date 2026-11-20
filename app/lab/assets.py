"""Compatibility import; canonical artifact utilities live in app.execution."""
from app.execution.artifacts import collect_assets, digest
__all__ = ["collect_assets", "digest"]
