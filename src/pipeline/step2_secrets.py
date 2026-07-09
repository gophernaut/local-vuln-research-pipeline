"""Step 2b: Secrets/config scanner.

Detects hardcoded credentials, API keys, tokens, and sensitive config.
Runs before code-level analysis — these are instant findings.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from src.analysis.secrets_scanner import SecretsScanner
from src.utils.logger import get_logger

logger = get_logger()


def run(repo_path: Path) -> list[dict[str, Any]]:
    logger.info("Step 2b: Scanning for hardcoded secrets...")

    scanner = SecretsScanner()
    matches = scanner.scan(repo_path)

    results = []
    for match in matches:
        results.append({
            "file": match.file,
            "line": match.line,
            "rule_id": match.rule_id,
            "category": match.category,
            "matched_text": match.matched_text,
            "entropy": match.entropy,
        })

    if results:
        logger.info(f"  {len(results)} secrets found")
    else:
        logger.info("  No secrets found")

    return results
