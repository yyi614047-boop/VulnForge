"""Minimal read-only Metasploit integration."""
from app.integrations.metasploit.client import MetasploitRPCClient
from app.integrations.metasploit.discovery import MetasploitDiscovery
from app.integrations.metasploit.models import ModuleMetadata, PoCCandidate
from app.integrations.metasploit.compatibility import CompatibilityAssessment, assess_compatibility
from app.integrations.metasploit.options import PreparedModuleOptions, prepare_module_options

__all__ = ["MetasploitRPCClient", "MetasploitDiscovery", "ModuleMetadata", "PoCCandidate", "CompatibilityAssessment", "assess_compatibility", "PreparedModuleOptions", "prepare_module_options"]
