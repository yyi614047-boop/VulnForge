"""Compatibility import; canonical legacy card adapter lives under targets."""
from app.targets.vulhub.legacy_cards import Card, FileEvidence, KnowledgeBase, Probe, Script, StrictModel, VersionProbe
__all__ = ["Card", "FileEvidence", "KnowledgeBase", "Probe", "Script", "StrictModel", "VersionProbe"]
