"""Compatibility exports for the retired KnowledgeBase module."""
from app.domain.reproduction import Card, FileEvidence, Probe, ReproductionSpec, Script, StrictModel, VersionProbe
from app.targets.vulhub.catalog import TargetCatalog

KnowledgeBase = TargetCatalog
__all__ = ["Card", "FileEvidence", "KnowledgeBase", "Probe", "ReproductionSpec", "Script", "StrictModel", "TargetCatalog", "VersionProbe"]
