"""Compatibility import; canonical comparison workflow lives in app.evaluation."""
from app.evaluation.comparison import comparable, compare_versions
__all__ = ["comparable", "compare_versions"]
