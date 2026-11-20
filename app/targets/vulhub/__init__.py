"""Adapter for the upstream Vulhub target corpus."""
from app.targets.vulhub.loader import VulhubTargetLoader
from app.targets.vulhub.catalog import TargetCatalog

__all__ = ["TargetCatalog", "VulhubTargetLoader"]
