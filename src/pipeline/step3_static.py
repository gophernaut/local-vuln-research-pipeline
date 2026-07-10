"""Step 3: Full static analysis — runs all deterministic analyzers.

Covers 100% of code. Provides SIGNALS (not gates) for LLM pipeline.
Taint flows = 0 is expected for non-web targets — LLM generates hypotheses from code directly.
"""
from __future__ import annotations

import concurrent.futures
from pathlib import Path
from typing import Any

from src.analysis.semgrep_runner import SemgrepRunner
from src.analysis.sink_finder import SinkFinder
from src.analysis.data_flow import DataFlowAnalyzer
from src.utils.logger import get_logger
from src.config import config

logger = get_logger()

UNIVERSAL_ENTRY_EXTENSIONS = {
    ".c": "C source", ".cpp": "C++ source", ".h": "C/C++ header", ".hpp": "C++ header",
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".java": "Java", ".go": "Go", ".rs": "Rust", ".cs": "C#",
    ".rb": "Ruby", ".php": "PHP", ".swift": "Swift", ".kt": "Kotlin",
    ".ps1": "PowerShell", ".psm1": "PowerShell module",
    ".sh": "Shell", ".bash": "Shell",
    ".yaml": "Config", ".yml": "Config", ".json": "Config", ".xml": "Config",
    ".toml": "Config", ".ini": "Config", ".cfg": "Config", ".conf": "Config",
    ".gradle": "Build", ".cmake": "Build",
}


def run(repo_path: Path) -> dict[str, Any]:
    logger.info("Step 3: Running full static analysis...")

    results: dict[str, Any] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(config.get("pipeline.parallel_analyzers", 16), 16)) as executor:
        futures = {
            executor.submit(_run_semgrep, repo_path): "semgrep",
            executor.submit(_run_sinks, repo_path): "sinks",
            executor.submit(_run_taint, repo_path): "taint",
        }
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result(timeout=600)
            except Exception as e:
                logger.error(f"  {name} failed: {e}")
                results[name] = [] if name != "semgrep" else []

    semgrep_findings = results.get("semgrep", [])
    sink_matches = results.get("sinks", [])
    taint_flows = results.get("taint", [])

    file_inventory = _build_file_inventory(repo_path)

    summary = {
        "semgrep_hits": len(semgrep_findings),
        "sinks_found": len(sink_matches),
        "taint_flows": len(taint_flows),
        "high_conf_flows": sum(1 for f in taint_flows if f.confidence >= 0.5),
        "files_scanned": file_inventory["total_files"],
        "languages_detected": file_inventory["languages"],
    }

    logger.info(
        f"  {summary['files_scanned']} files | {summary['semgrep_hits']} semgrep hits | "
        f"{summary['sinks_found']} sinks | {summary['taint_flows']} taint flows"
    )
    if summary["taint_flows"] == 0 and summary["sinks_found"] == 0:
        logger.info("  (Non-web target — LLM will analyze code directly)")

    return {
        "semgrep_findings": [{
            "rule_id": f.rule_id, "file": f.file, "line": f.line,
            "message": f.message, "severity": f.severity, "category": f.category, "cwe": f.cwe,
        } for f in semgrep_findings],
        "summary": summary,
        "file_inventory": file_inventory,
        "_sink_matches": [{
            "file": s.file, "line": s.line, "category": s.category,
            "sink_type": s.sink_type, "matched_text": s.matched_text, "cwe_id": s.cwe_id,
        } for s in sink_matches],
        "_taint_flows": [{
            "source_file": f.source.file, "source_line": f.source.line,
            "source_type": f.source.source_type,
            "sink_file": f.sink.file, "sink_line": f.sink.line,
            "sink_type": f.sink.sink_type, "sink_category": f.sink.category,
            "confidence": f.confidence, "cwe": f.sink.cwe_id,
        } for f in taint_flows],
        "_raw_semgrep": semgrep_findings,
        "_raw_sinks": sink_matches,
        "_raw_taint": taint_flows,
    }


def _build_file_inventory(repo_path: Path) -> dict[str, Any]:
    ext_count: dict[str, int] = {}
    total = 0
    all_files: list[dict[str, Any]] = []

    for ext in UNIVERSAL_ENTRY_EXTENSIONS:
        for f in repo_path.rglob(f"*{ext}"):
            if _skip_file(f):
                continue
            ext_count[ext] = ext_count.get(ext, 0) + 1
            total += 1
            all_files.append({
                "path": str(f.relative_to(repo_path)),
                "size": f.stat().st_size,
                "language": UNIVERSAL_ENTRY_EXTENSIONS.get(ext, str(ext)),
            })

    languages = {}
    for ext, count in ext_count.items():
        lang = UNIVERSAL_ENTRY_EXTENSIONS.get(ext, ext)
        languages[lang] = languages.get(lang, 0) + count

    all_files.sort(key=lambda f: -f["size"])

    return {
        "total_files": total,
        "languages": dict(sorted(languages.items(), key=lambda x: -x[1])),
        "all_files": all_files,
    }


def _skip_file(path: Path) -> bool:
    skip = {"node_modules", ".git", "__pycache__", ".venv", "venv",
            "target", "build", "dist", "vendor", ".next", ".nuxt",
            ".idea", ".vscode", "bin", "obj", "Debug", "Release",
            "packages", "TestResults", ".deps", ".libs"}
    return any(d in path.parts for d in skip)


def _run_semgrep(repo_path: Path) -> list:
    runner = SemgrepRunner()
    return runner.run(repo_path)


def _run_sinks(repo_path: Path) -> list:
    return SinkFinder().find_in_directory(repo_path)


def _run_taint(repo_path: Path) -> list:
    return DataFlowAnalyzer().analyze(repo_path)
