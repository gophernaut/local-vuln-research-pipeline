"""Memory analysis orchestrator — runs all memory corruption analyzers.

Combines: allocation tracking, buffer analysis, lifetime analysis, integer
overflow detection, format string analysis. Outputs a unified list of memory
vulnerability findings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.analysis.ast_parser import LANGUAGE_EXTENSIONS, SKIP_DIRS
from src.analysis.memory.alloc_tracker import AllocTracker, AllocFinding
from src.analysis.memory.buffer_analyzer import BufferAnalyzer, BufferFinding
from src.analysis.memory.lifetime import LifetimeAnalyzer, LifetimeFinding
from src.analysis.memory.int_overflow import IntOverflowAnalyzer, IntOverflowFinding
from src.analysis.memory.format_string import FormatStringAnalyzer, FormatStringFinding
from src.utils.logger import get_logger

logger = get_logger()

MEMORY_LANGUAGES = {"c", "cpp", "rust"}


@dataclass
class MemoryFinding:
    file: str
    line: int
    vulnerability_class: str
    description: str
    severity: str
    confidence: float
    cwe_id: str
    source_module: str


def run_memory_analysis(repo_path: Path) -> list[MemoryFinding]:
    logger.info("Running memory corruption analysis...")

    alloc_tracker = AllocTracker()
    buffer_analyzer = BufferAnalyzer()
    lifetime_analyzer = LifetimeAnalyzer()
    int_overflow_analyzer = IntOverflowAnalyzer()
    format_string_analyzer = FormatStringAnalyzer()

    all_findings: list[MemoryFinding] = []

    files_processed = 0
    for ext, lang in LANGUAGE_EXTENSIONS.items():
        if lang not in MEMORY_LANGUAGES:
            continue
        for filepath in repo_path.rglob(f"*{ext}"):
            if any(d in filepath.parts for d in SKIP_DIRS):
                continue
            try:
                with open(filepath, encoding="utf-8", errors="replace") as f:
                    source = f.read()
            except Exception:
                continue

            for finding in alloc_tracker.analyze_file(filepath, source, lang):
                all_findings.append(MemoryFinding(
                    file=finding.file, line=finding.line,
                    vulnerability_class=finding.vulnerability_class,
                    description=finding.description,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    cwe_id=finding.cwe_id,
                    source_module="alloc_tracker",
                ))

            for finding in buffer_analyzer.analyze_file(filepath, source, lang):
                all_findings.append(MemoryFinding(
                    file=finding.file, line=finding.line,
                    vulnerability_class=finding.vulnerability_class,
                    description=finding.description,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    cwe_id=finding.cwe_id,
                    source_module="buffer_analyzer",
                ))

            for finding in lifetime_analyzer.analyze_file(filepath, source, lang):
                all_findings.append(MemoryFinding(
                    file=finding.file, line=finding.line,
                    vulnerability_class=finding.vulnerability_class,
                    description=finding.description,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    cwe_id=finding.cwe_id,
                    source_module="lifetime",
                ))

            for finding in int_overflow_analyzer.analyze_file(filepath, source, lang):
                all_findings.append(MemoryFinding(
                    file=finding.file, line=finding.line,
                    vulnerability_class=finding.vulnerability_class,
                    description=finding.description,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    cwe_id=finding.cwe_id,
                    source_module="int_overflow",
                ))

            for finding in format_string_analyzer.analyze_file(filepath, source, lang):
                all_findings.append(MemoryFinding(
                    file=finding.file, line=finding.line,
                    vulnerability_class=finding.vulnerability_class,
                    description=finding.description,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    cwe_id=finding.cwe_id,
                    source_module="format_string",
                ))

            files_processed += 1

    critical = sum(1 for f in all_findings if f.severity == "CRITICAL")
    high = sum(1 for f in all_findings if f.severity == "HIGH")
    medium = sum(1 for f in all_findings if f.severity == "MEDIUM")
    logger.info(
        f"Memory analysis: {len(all_findings)} findings in {files_processed} files "
        f"({critical} CRITICAL, {high} HIGH, {medium} MEDIUM)"
    )

    return all_findings
