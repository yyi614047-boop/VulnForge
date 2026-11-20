"""Deterministic Metasploit CVE discovery and module inspection.

This first integration stage is read-only: it searches modules and inspects
metadata through msfconsole. It never invokes check, exploit, payload, or
session commands. All console invocations use argv (never a shell), and user
input is validated before it is interpolated into an msfconsole command.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
from typing import Callable

from app.domain.poc import PoCCandidate, PoCOption

CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)
MODULE_PATTERN = re.compile(r"^(?:exploit|auxiliary)/[A-Za-z0-9_./-]+$")
MODULE_IN_OUTPUT = re.compile(r"\b(?:exploit|auxiliary)/[A-Za-z0-9_./-]+\b")
CVE_IN_OUTPUT = re.compile(r"\bCVE-[0-9]{4}-[0-9]{4,}\b", re.IGNORECASE)
SECTION_NAMES = {
    "basic options", "advanced options", "evasion options", "targets",
    "references", "description", "payload information",
}


def valid_module_path(module: str) -> bool:
    return bool(MODULE_PATTERN.fullmatch(module)) and all(
        part not in {"", ".", ".."} for part in module.split("/")
    )


def _section_lines(output: str, section: str) -> list[str]:
    lines = output.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip().casefold().rstrip(":") == section.casefold():
            start = index + 1
            break
    if start is None:
        return []
    result = []
    for line in lines[start:]:
        stripped = line.strip()
        if stripped.casefold().rstrip(":") in SECTION_NAMES and result:
            break
        if stripped.startswith(("Name", "----")) and not result:
            continue
        if stripped and set(stripped) <= {"-", " "}:
            continue
        result.append(line.rstrip())
    return result


def parse_module_info(module: str, cve: str, output: str) -> PoCCandidate:
    """Extract stable fields while retaining a bounded raw metadata excerpt."""
    if not valid_module_path(module):
        raise ValueError("Invalid Metasploit module path")
    normalized_cve = cve.upper()
    if not CVE_PATTERN.fullmatch(normalized_cve):
        raise ValueError("Expected a CVE identifier such as CVE-2021-25646")

    def field(pattern: str) -> str | None:
        match = re.search(pattern, output, flags=re.IGNORECASE | re.MULTILINE)
        return match.group(1).strip() if match else None

    name = field(r"^\s*Name\s*:\s*(.+)$")
    rank = field(r"^\s*Rank\s*:\s*(.+)$")
    disclosure = field(r"^\s*Disclosure Date\s*:\s*(.+)$")

    description_lines = _section_lines(output, "Description")
    description = "\n".join(description_lines).strip()
    reference_lines = _section_lines(output, "References")
    references = list(dict.fromkeys(CVE_IN_OUTPUT.findall("\n".join(reference_lines))))

    targets = []
    for line in _section_lines(output, "Targets"):
        match = re.match(r"^\s*\d+\s+(.+?)\s*$", line)
        if match:
            targets.append(match.group(1))

    options: list[PoCOption] = []
    for section in ("Basic Options", "Advanced Options"):
        for line in _section_lines(output, section):
            match = re.match(
                r"^\s*([A-Z][A-Z0-9_]*)\s+(.*?)\s+(yes|no)\s{2,}(.+?)\s*$",
                line, flags=re.IGNORECASE,
            )
            if not match:
                continue
            option_name, current, required, description_text = match.groups()
            options.append(PoCOption(
                name=option_name,
                required=required.casefold() == "yes",
                current_value=current.strip() or None,
                description=description_text.strip(),
            ))

    # Check support is only set when the inspected metadata explicitly says so.
    check_supported = None
    check_match = re.search(r"^\s*Check Supported\s*:\s*(yes|no)\s*$", output,
                            flags=re.IGNORECASE | re.MULTILINE)
    if check_match:
        check_supported = check_match.group(1).casefold() == "yes"

    excerpt = output[-32000:]
    digest = hashlib.sha256(excerpt.encode("utf-8")).hexdigest()
    return PoCCandidate(
        candidate_id=f"metasploit:{module}",
        source="metasploit",
        cve_ids=references,
        discovery_query_cve=normalized_cve,
        module_type=module.split("/", 1)[0],
        module_path=module,
        name=name,
        description=description[:12000],
        rank=rank,
        disclosure_date=disclosure,
        references=references,
        targets=targets,
        options=options,
        check_supported=check_supported,
        metadata_sha256=digest,
        metadata_excerpt=excerpt,
        inspected=True,
    )


class MetasploitDiscovery:
    """Read-only CVE module discovery and metadata inspection."""

    def __init__(self, *, executable: str = "msfconsole", timeout: int = 180,
                 runner: Callable = subprocess.run):
        if not 1 <= timeout <= 900:
            raise ValueError("timeout must be between 1 and 900 seconds")
        self.executable = executable
        self.timeout = timeout
        self.runner = runner

    def _run_console(self, commands: str) -> str:
        result = self.runner(
            [self.executable, "-q", "-x", commands],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=self.timeout, shell=False,
        )
        output = (result.stdout or "") + "\n" + (result.stderr or "")
        if result.returncode != 0:
            raise RuntimeError(
                f"msfconsole exited with status {result.returncode}: {output[-4000:]}"
            )
        return output[-32000:]

    @staticmethod
    def validate_cve(cve: str) -> str:
        if not CVE_PATTERN.fullmatch(cve):
            raise ValueError("Expected a CVE identifier such as CVE-2021-25646")
        return cve.upper()

    def discover(self, cve: str) -> list[str]:
        """Return unique exploit/auxiliary module paths matching a CVE search."""
        normalized = self.validate_cve(cve)
        output = self._run_console(f"search cve:{normalized}; exit")
        modules = []
        for module in MODULE_IN_OUTPUT.findall(output):
            if valid_module_path(module) and module not in modules:
                modules.append(module)
        return modules

    def inspect(self, cve: str, module: str) -> PoCCandidate:
        """Fetch and normalize one module's metadata without executing it."""
        normalized = self.validate_cve(cve)
        if not valid_module_path(module):
            raise ValueError("Invalid Metasploit module path")
        output = self._run_console(f"info {module}; exit")
        return parse_module_info(module, normalized, output)

    def search_and_inspect(self, cve: str, *, limit: int = 20) -> list[PoCCandidate]:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        normalized = self.validate_cve(cve)
        modules = self.discover(normalized)
        return [self.inspect(normalized, module) for module in modules[:limit]]
