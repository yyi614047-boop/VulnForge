"""Deterministic Metasploit module discovery and local check execution.

This adapter deliberately never asks an LLM to select, generate, or judge a PoC.
It searches CVE-tagged Metasploit modules and invokes their native Check method
against an explicitly local lab endpoint. It does not run exploit payloads.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import asdict, dataclass
from typing import Callable

CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)
MODULE_PATTERN = re.compile(r"^(?:exploit|auxiliary)/[A-Za-z0-9_./-]+$")
MODULE_IN_OUTPUT = re.compile(r"\b(?:exploit|auxiliary)/[A-Za-z0-9_./-]+\b")


@dataclass(frozen=True)
class ModuleCheck:
    module: str
    status: str
    output: str


class MetasploitRunner:
    """Discover CVE-tagged modules and invoke their native Check method."""

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

    def discover(self, cve: str) -> list[str]:
        """Return unique Metasploit exploit/auxiliary module paths for a CVE."""
        if not CVE_PATTERN.fullmatch(cve):
            raise ValueError("Expected a CVE identifier such as CVE-2021-25646")
        output = self._run_console(f"search cve:{cve.upper()}; exit")
        modules = []
        for match in MODULE_IN_OUTPUT.findall(output):
            if MODULE_PATTERN.fullmatch(match) and match not in modules:
                modules.append(match)
        return modules

    @staticmethod
    def _validate_target(host: str, port: int) -> None:
        if host not in {"127.0.0.1", "localhost"}:
            raise ValueError("Metasploit checks are restricted to localhost lab targets")
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")

    @staticmethod
    def classify_check(output: str) -> str:
        """Classify explicit Metasploit CheckCode-style outcomes only."""
        text = output.casefold()
        if "checkcode::vulnerable" in text or re.search(
            r"\b(target|service) (?:is|appears to be) vulnerable\b", text
        ):
            return "vulnerable"
        if "checkcode::safe" in text or re.search(
            r"\b(target|service) (?:is|appears to be) safe\b", text
        ):
            return "not_vulnerable"
        if "checkcode::detected" in text or "appears to be detected" in text:
            return "detected"
        if "does not support check" in text or "check is not supported" in text or "checknotsupported" in text:
            return "unsupported"
        return "inconclusive"

    def check_module(self, module: str, host: str, port: int) -> ModuleCheck:
        """Run one module's native check; never invoke its exploit method."""
        self._validate_target(host, port)
        if not MODULE_PATTERN.fullmatch(module):
            raise ValueError("Invalid Metasploit module path")
        output = self._run_console(
            f"use {module}; set RHOSTS {host}; set RPORT {port}; check; exit"
        )
        return ModuleCheck(module, self.classify_check(output), output)

    def verify(self, cve: str, *, host: str = "127.0.0.1", port: int) -> dict:
        """Discover candidate modules and check them without LLM involvement."""
        self._validate_target(host, port)
        try:
            modules = self.discover(cve)
        except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
            return {"cve": cve.upper(), "status": "inconclusive",
                    "reason": f"Metasploit module discovery failed: {exc}", "modules": []}
        if not modules:
            return {"cve": cve.upper(), "status": "unsupported",
                    "reason": "No Metasploit exploit or auxiliary module matched this CVE",
                    "modules": []}

        results = []
        for module in modules:
            try:
                results.append(asdict(self.check_module(module, host, port)))
            except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
                results.append({"module": module, "status": "inconclusive", "output": str(exc)})

        statuses = {item["status"] for item in results}
        if "vulnerable" in statuses:
            status = "vulnerable"
        elif statuses and statuses <= {"not_vulnerable"}:
            status = "not_vulnerable"
        elif statuses and statuses <= {"unsupported"}:
            status = "unsupported"
        elif "detected" in statuses:
            status = "detected"
        else:
            status = "inconclusive"
        return {"cve": cve.upper(), "target": {"host": host, "port": port},
                "status": status, "modules": results}
