"""Semgrep integration — runs security rules against target repository."""
from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class SemgrepFinding:
    rule_id: str
    file: str
    line: int
    column: int
    end_line: int
    end_column: int
    message: str
    severity: str
    category: str = ""
    cwe: str = ""


class SemgrepRunner:
    def __init__(self, rules_dir: Path | None = None):
        self.rules_dir = rules_dir

    def run(self, repo_path: Path, languages: list[str] | None = None) -> list[SemgrepFinding]:
        if not self._semgrep_available():
            logger.warning("semgrep not installed. Skipping Semgrep analysis.")
            return []

        findings: list[SemgrepFinding] = []

        if self.rules_dir and self.rules_dir.exists():
            findings.extend(self._run_custom_rules(repo_path, languages))
        else:
            findings.extend(self._run_builtin_rules(repo_path, languages))

        return findings

    def _semgrep_available(self) -> bool:
        try:
            subprocess.run(
                ["semgrep", "--version"],
                capture_output=True, timeout=10,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _run_builtin_rules(
        self, repo_path: Path, languages: list[str] | None = None
    ) -> list[SemgrepFinding]:
        """Run built-in Semgrep registry rules (p/default)."""
        logger.info("Running Semgrep with built-in rules (p/default)...")
        cmd = [
            "semgrep", "scan",
            "--config", "p/default",
            "--json",
            "--no-git-ignore",
            "--metrics", "off",
            str(repo_path),
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode not in (0, 1):
                logger.error(f"Semgrep error: {result.stderr[:500]}")
                return []
            return self._parse_output(result.stdout)
        except subprocess.TimeoutExpired:
            logger.warning("Semgrep timed out (10 min limit)")
            return []
        except Exception as e:
            logger.error(f"Semgrep run failed: {e}")
            return []

    def _run_custom_rules(
        self, repo_path: Path, languages: list[str] | None = None
    ) -> list[SemgrepFinding]:
        """Run custom rule files from rules_dir."""
        logger.info(f"Running Semgrep with custom rules from {self.rules_dir}...")
        all_findings: list[SemgrepFinding] = []

        for rule_file in self.rules_dir.glob("*.yaml"):
            cmd = [
                "semgrep", "scan",
                "--config", str(rule_file),
                "--json",
                "--no-git-ignore",
                "--metrics", "off",
                str(repo_path),
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.returncode in (0, 1):
                    all_findings.extend(self._parse_output(result.stdout))
            except (subprocess.TimeoutExpired, Exception):
                continue

        return all_findings

    def _parse_output(self, output: str) -> list[SemgrepFinding]:
        findings: list[SemgrepFinding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []

        for result in data.get("results", []):
            findings.append(SemgrepFinding(
                rule_id=result.get("check_id", ""),
                file=result.get("path", ""),
                line=result.get("start", {}).get("line", 0),
                column=result.get("start", {}).get("col", 0),
                end_line=result.get("end", {}).get("line", 0),
                end_column=result.get("end", {}).get("col", 0),
                message=result.get("extra", {}).get("message", ""),
                severity=result.get("extra", {}).get("severity", "WARNING"),
                category=result.get("extra", {}).get("metadata", {}).get("category", ""),
                cwe=",".join(result.get("extra", {}).get("metadata", {}).get("cwe", [])),
            ))

        return findings
