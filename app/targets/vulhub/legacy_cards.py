"""Deprecated import path; use app.domain.reproduction and app.targets.vulhub.catalog."""
from app.domain.reproduction import Card, FileEvidence, Probe, ReproductionSpec, Script, StrictModel, VersionProbe
from app.targets.vulhub.catalog import KnowledgeBase, TargetCatalog

__all__ = [
    "Card", "FileEvidence", "KnowledgeBase", "Probe", "ReproductionSpec",
    "Script", "StrictModel", "TargetCatalog", "VersionProbe",
]
