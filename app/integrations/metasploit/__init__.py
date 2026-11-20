"""Minimal read-only Metasploit integration."""
from app.integrations.metasploit.client import MetasploitRPCClient
from app.integrations.metasploit.discovery import MetasploitDiscovery
from app.integrations.metasploit.models import ModuleMetadata, PoCCandidate

__all__ = ["MetasploitRPCClient", "MetasploitDiscovery", "ModuleMetadata", "PoCCandidate"]
