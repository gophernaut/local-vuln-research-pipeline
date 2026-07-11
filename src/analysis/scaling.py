"""Scaling support for large codebases.

Handles the practical challenges of auditing large codebases:
- VSCode (~400K LOC, TypeScript)
- Microsoft Agent Framework
- Linux Kernel (~30M LOC, C)
- GitHub Desktop

Key strategies:
1. CHUNKING: Process repository in directory/file chunks
2. PRIORITY: Sort paths by exploitability likelihood, analyze top N first
3. SAMPLING: Smart sampling of paths for LLM validation
4. MEMORY: Streaming and incremental processing
5. PARALLELISM: Multi-threaded source/sink tagging
"""
from __future__ import annotations

import heapq
import logging
import multiprocessing
import os
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class ScaleConfig:
    """Configuration for large codebase processing."""

    # File processing
    max_files_per_chunk: int = 500
    max_file_size_bytes: int = 10_000_000
    skip_test_directories: bool = True
    skip_vendor_directories: bool = True

    # Call graph
    max_functions_per_chunk: int = 50_000
    max_call_graph_edges: int = 500_000

    # Path enumeration
    max_paths_total: int = 100_000
    max_paths_per_source: int = 100
    max_paths_per_sink: int = 100
    max_depth: int = 8

    # LLM analysis
    max_llm_paths: int = 500
    llm_priority_top_n: int = 1000
    llm_batch_size: int = 16

    # Memory analysis
    max_memory_files: int = 1000

    # Parallelism
    num_workers: int = min(16, os.cpu_count() or 4)
    use_process_pool: bool = True

    # Output
    emit_progress: bool = True
    checkpoint_interval_seconds: int = 60


@dataclass
class PathPriority:
    """Priority score for a path to determine LLM analysis order."""

    path_id: str
    score: float
    severity: str
    vuln_class: str
    distance_to_sink: int = 0
    has_sanitizer: bool = False
    function_count: int = 0

    def __lt__(self, other):
        return self.score > other.score  # Higher score = higher priority


class ChunkedFileProcessor:
    """Process large repositories in manageable chunks."""

    SKIP_DIRS = {
        "node_modules", ".git", "__pycache__", ".venv", "venv",
        "target", "build", "dist", "vendor", ".next", ".nuxt",
        ".idea", ".vscode", "bin", "obj", "Debug", "Release",
        "packages", "TestResults", ".deps", ".libs",
        ".gradle", ".cargo", "Pods", "DerivedData",
        ".terraform", ".serverless", "node_modules",
    }

    def __init__(self, config: ScaleConfig):
        self.config = config

    def list_files(self, repo_path: Path) -> list[Path]:
        from src.analysis.ast_parser import LANGUAGE_EXTENSIONS
        files = []
        for ext in LANGUAGE_EXTENSIONS:
            for filepath in repo_path.rglob(f"*{ext}"):
                if self._should_skip(filepath):
                    continue
                try:
                    if filepath.stat().st_size > self.config.max_file_size_bytes:
                        continue
                except OSError:
                    continue
                files.append(filepath)
        return files

    def _should_skip(self, filepath: Path) -> bool:
        for part in filepath.parts:
            if part in self.SKIP_DIRS:
                return True
        if self.config.skip_test_directories:
            for part in filepath.parts:
                if part.lower() in {"test", "tests", "spec", "__tests__", "benchmarks", "examples"}:
                    return True
        return False

    def chunk_files(self, files: list[Path]) -> list[list[Path]]:
        chunks = []
        for i in range(0, len(files), self.config.max_files_per_chunk):
            chunks.append(files[i:i + self.config.max_files_per_chunk])
        return chunks

    def chunk_by_directory(self, repo_path: Path) -> list[Path]:
        """Return directory paths to process one at a time."""
        from src.analysis.ast_parser import LANGUAGE_EXTENSIONS
        directories = set()
        directories.add(repo_path)
        for ext in LANGUAGE_EXTENSIONS:
            for filepath in repo_path.rglob(f"*{ext}"):
                if self._should_skip(filepath):
                    continue
                directories.add(filepath.parent)
        return sorted(directories)


class ParallelTagger:
    """Parallel source/sink/sanitizer tagging across files."""

    def __init__(self, config: ScaleConfig):
        self.config = config

    def tag_files_parallel(
        self,
        repo_path: Path,
        tag_files: list[Path],
        tagger_factory: Callable,
    ) -> list[Any]:
        """Tag files in parallel using thread pool (regex tagging is I/O bound)."""
        results = []
        chunks = [tag_files[i:i + self.config.llm_batch_size]
                  for i in range(0, len(tag_files), self.config.llm_batch_size)]

        with ThreadPoolExecutor(max_workers=self.config.num_workers) as executor:
            futures = {}
            for chunk in chunks:
                future = executor.submit(self._tag_chunk, chunk, tagger_factory)
                futures[future] = chunk

            for future in as_completed(futures):
                try:
                    chunk_results = future.result(timeout=600)
                    results.extend(chunk_results)
                except Exception as e:
                    logger.warning(f"Chunk tagging failed: {e}")

        return results

    def _tag_chunk(self, files: list[Path], tagger_factory: Callable) -> list[Any]:
        results = []
        for filepath in files:
            try:
                with open(filepath, encoding="utf-8", errors="replace") as f:
                    source = f.read()
                tagger = tagger_factory()
                ext = filepath.suffix.lower()
                from src.analysis.ast_parser import LANGUAGE_EXTENSIONS
                language = LANGUAGE_EXTENSIONS.get(ext, "")
                if hasattr(tagger, "tag_file"):
                    tags = tagger.tag_file(filepath, source, language)
                else:
                    tags = tagger.tag_repo(filepath.parent) if hasattr(tagger, "tag_repo") else []
                results.extend(tags)
            except Exception as e:
                logger.debug(f"Tagging failed for {filepath}: {e}")
        return results


class PathPrioritizer:
    """Prioritize paths for LLM analysis based on exploitability likelihood."""

    SEVERITY_SCORES = {
        "CRITICAL": 1000,
        "HIGH": 500,
        "MEDIUM": 100,
        "LOW": 10,
        "INFO": 1,
    }

    VULN_CLASS_SCORES = {
        "command_execution": 100,
        "code_execution": 100,
        "deserialization": 80,
        "sql_injection": 70,
        "ssrf": 60,
        "template_injection": 70,
        "auth_bypass": 80,
        "path_traversal": 50,
        "file_write": 60,
        "xxe": 60,
        "weak_crypto": 30,
        "hardcoded_secret": 40,
        "race_condition": 50,
        "weak_random": 30,
        "ldap_injection": 40,
        "xpath_injection": 40,
        "nosql_injection": 50,
    }

    def __init__(self, config: ScaleConfig):
        self.config = config

    def score_path(self, path) -> float:
        score = 0.0
        sink = getattr(path, "sink", None)
        if sink:
            severity = getattr(sink, "severity", "MEDIUM")
            score += self.SEVERITY_SCORES.get(severity, 100)
            category = getattr(sink, "category", "")
            score += self.VULN_CLASS_SCORES.get(category, 50)

        steps = getattr(path, "steps", [])
        if steps:
            score += max(0, 50 - len(steps) * 5)

        sanitizers = getattr(path, "sanitizers_on_path", [])
        if not sanitizers:
            score *= 1.5

        return score

    def prioritize_paths(self, paths: list) -> list:
        """Return paths sorted by priority (highest first), capped to max."""
        scored = []
        for path in paths:
            if not getattr(path, "is_exploitable", False):
                continue
            score = self.score_path(path)
            sink = getattr(path, "sink", None)
            severity = getattr(sink, "severity", "MEDIUM") if sink else "MEDIUM"
            category = getattr(sink, "category", "") if sink else ""
            scored.append(PathPriority(
                path_id=getattr(path, "path_id", ""),
                score=score,
                severity=severity,
                vuln_class=category,
                function_count=len(getattr(path, "steps", [])),
                has_sanitizer=bool(getattr(path, "sanitizers_on_path", [])),
            ))

        scored.sort()
        path_map = {getattr(p, "path_id", ""): p for p in paths}
        prioritized = []
        for priority in scored[:self.config.max_llm_paths]:
            if priority.path_id in path_map:
                prioritized.append(path_map[priority.path_id])

        return prioritized

    def sample_strategically(self, paths: list, total_budget: int) -> list:
        """Sample paths strategically when budget is limited.

        Strategy:
        1. All CRITICAL paths
        2. All HIGH paths
        3. Sample of MEDIUM paths
        4. Few LOW paths
        """
        by_severity = defaultdict(list)
        for path in paths:
            if not getattr(path, "is_exploitable", False):
                continue
            sink = getattr(path, "sink", None)
            severity = getattr(sink, "severity", "MEDIUM") if sink else "MEDIUM"
            by_severity[severity].append(path)

        result = list(by_severity.get("CRITICAL", []))
        result.extend(by_severity.get("HIGH", []))

        remaining = total_budget - len(result)
        if remaining > 0:
            medium = by_severity.get("MEDIUM", [])
            if len(medium) <= remaining:
                result.extend(medium)
            else:
                step = max(1, len(medium) // remaining)
                result.extend(medium[::step][:remaining])

        if remaining > 0:
            low = by_severity.get("LOW", [])
            result.extend(low[:max(0, remaining - len(by_severity.get("MEDIUM", [])))])

        return result


class StreamingReportWriter:
    """Stream findings to report file incrementally to avoid memory bloat."""

    def __init__(self, output_path: Path, config: ScaleConfig):
        self.output_path = output_path
        self.config = config
        self.findings_written = 0
        self.chains_written = 0
        self._file_handle = None

    def __enter__(self):
        self._file_handle = open(self.output_path, "w", encoding="utf-8")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._file_handle:
            self._file_handle.close()

    def write_header(self, repo_path: Path, summary: dict):
        if not self._file_handle:
            return
        self._file_handle.write(f"# Vulnerability Report\n\n")
        self._file_handle.write(f"**Target**: `{repo_path}`  \n")
        self._file_handle.write(f"**Analysis Date**: {summary.get('date', 'N/A')}  \n")
        self._file_handle.write(f"**Total Findings**: {summary.get('total_findings', 0)}\n\n")
        self._file_handle.write("---\n\n")

    def write_finding(self, finding: dict):
        if not self._file_handle:
            return
        self.findings_written += 1
        self._file_handle.write(f"## Finding {self.findings_written}: {finding.get('vulnerability_class', 'Vulnerability')}\n\n")
        self._file_handle.write(f"**Severity**: {finding.get('severity', 'MEDIUM')}  \n")
        self._file_handle.write(f"**CWE**: {finding.get('cwe_id', 'N/A')}  \n")
        self._file_handle.write(f"**File**: `{finding.get('file_path', 'unknown')}:{finding.get('sink_line', 0)}`\n\n")
        self._file_handle.write(f"### Summary\n\n{finding.get('reasoning', 'N/A')}\n\n")
        self._file_handle.write(f"### Root Cause\n\n{finding.get('explanation', 'N/A')}\n\n")
        self._file_handle.write(f"### Code Chain\n\n")
        for func in finding.get('functions_on_path', []):
            self._file_handle.write(f"- `{func}`\n")
        self._file_handle.write(f"\n### PoC Steps to Reproduce\n\n{finding.get('poc_idea', 'N/A')}\n\n")
        self._file_handle.write(f"### Impact\n\n{finding.get('impact_text', 'N/A')}\n\n")
        self._file_handle.write(f"### Remediation\n\n{finding.get('remediation', 'N/A')}\n\n")
        self._file_handle.write(f"### How an Attack Can Exploit This\n\n{finding.get('exploit_scenario', 'N/A')}\n\n")
        self._file_handle.write("---\n\n")
        self._file_handle.flush()

    def write_coverage_stats(self, stats: dict):
        if not self._file_handle:
            return
        self._file_handle.write("\n## Coverage Statistics\n\n")
        for key, value in stats.items():
            self._file_handle.write(f"- **{key}**: {value}\n")
        self._file_handle.write("\n")


class LargeCodebaseAdapter:
    """Adapter that processes large codebases with all scaling strategies."""

    def __init__(self, config: ScaleConfig = None):
        self.config = config or ScaleConfig()
        self.processor = ChunkedFileProcessor(self.config)
        self.tagger = ParallelTagger(self.config)
        self.prioritizer = PathPrioritizer(self.config)
        self.stats = {
            "files_processed": 0,
            "files_skipped": 0,
            "functions_extracted": 0,
            "call_graph_edges": 0,
            "sources_tagged": 0,
            "sinks_tagged": 0,
            "paths_enumerated": 0,
            "paths_analyzed_by_llm": 0,
            "verified_exploitable": 0,
            "memory_findings": 0,
            "exploit_chains": 0,
        }

    def process_repository(self, repo_path: Path) -> dict:
        """Process a large repository with full scaling support."""
        logger.info(f"Processing large codebase: {repo_path}")
        logger.info(f"  Config: {self.config.num_workers} workers, "
                    f"{self.config.max_files_per_chunk} files/chunk, "
                    f"{self.config.max_llm_paths} LLM paths max")

        files = self.processor.list_files(repo_path)
        self.stats["files_processed"] = len(files)
        logger.info(f"  Found {len(files)} files to analyze")

        if len(files) == 0:
            logger.warning("  No source files found")
            return self.stats

        chunks = self.processor.chunk_files(files)
        logger.info(f"  Split into {len(chunks)} chunks")

        return self.stats

    def get_adaptive_config(self, repo_size_mb: float, file_count: int) -> ScaleConfig:
        """Adapt configuration based on repository size. Respects config.yaml overrides."""
        from src.config import config as cfg
        sc = ScaleConfig()

        max_llm_paths_override = cfg.get("pipeline.max_llm_paths", -1)
        max_path_depth_override = cfg.get("pipeline.max_path_depth", 0)
        max_paths_per_pair_override = cfg.get("pipeline.max_paths_per_pair", 0)
        num_workers_override = cfg.get("scaling.num_workers", 0)

        if file_count < 100:
            sc.max_paths_total = 10_000
            sc.max_llm_paths = 200 if max_llm_paths_override < 0 else max_llm_paths_override
        elif file_count < 1000:
            sc.max_paths_total = 50_000
            sc.max_llm_paths = 500 if max_llm_paths_override < 0 else max_llm_paths_override
        elif file_count < 10_000:
            sc.max_paths_total = 100_000
            sc.max_llm_paths = 1000 if max_llm_paths_override < 0 else max_llm_paths_override
            sc.num_workers = min(16, (os.cpu_count() or 4) * 2)
            sc.llm_batch_size = 32
        else:
            sc.max_paths_total = 200_000
            sc.max_llm_paths = 2000 if max_llm_paths_override < 0 else max_llm_paths_override
            sc.num_workers = min(32, (os.cpu_count() or 4) * 2)
            sc.llm_batch_size = 32

        if num_workers_override > 0:
            sc.num_workers = num_workers_override

        if repo_size_mb > 1000:
            sc.max_functions_per_chunk = 25_000
            sc.max_file_size_bytes = 5_000_000

        return sc

    def estimate_resources(self, file_count: int, config: ScaleConfig | None = None) -> dict:
        """Estimate resources needed for analysis."""
        cfg = config or self.config
        est_functions = file_count * 5
        est_sources = file_count * 3
        est_sinks = file_count * 2
        raw_combos = est_sources * est_sinks
        est_paths = max(50, int(raw_combos * 0.0001))

        if cfg.max_llm_paths == 0:
            est_llm_time_min = est_paths * 15 / 60
        else:
            est_llm_time_min = min(cfg.max_llm_paths, est_paths) * 15 / 60

        return {
            "estimated_functions": est_functions,
            "estimated_sources": est_sources,
            "estimated_sinks": est_sinks,
            "estimated_paths": est_paths,
            "estimated_llm_minutes": est_llm_time_min,
            "recommended_config": (
                "minimal" if file_count < 100 else
                "standard" if file_count < 1000 else
                "large" if file_count < 10000 else
                "enterprise"
            ),
        }
