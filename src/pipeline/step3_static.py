"""Step 3: Full static analysis — runs Semgrep + file inventory scan.

Provides deterministic signals (not gates) for the LLM pipeline.
Sink/source/taint tagging is handled by the code graph step (3b).
"""
from __future__ import annotations

import concurrent.futures
from pathlib import Path
from typing import Any

from src.analysis.semgrep_runner import SemgrepRunner
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
    ".gradle": "Build",
}


def run(repo_path: Path) -> dict[str, Any]:
    logger.info("Step 3: Running full static analysis...")

    semgrep_findings = []
    try:
        runner = SemgrepRunner()
        semgrep_findings = runner.run(repo_path)
    except Exception as e:
        logger.error(f"  Semgrep failed: {e}")

    file_inventory = _build_file_inventory(repo_path)

    summary = {
        "semgrep_hits": len(semgrep_findings),
        "files_scanned": file_inventory["total_files"],
        "languages_detected": file_inventory["languages"],
    }

    logger.info(
        f"  {summary['files_scanned']} files | {summary['semgrep_hits']} semgrep hits"
    )

    return {
        "semgrep_findings": [{
            "rule_id": f.rule_id, "file": f.file, "line": f.line,
            "message": f.message, "severity": f.severity, "category": f.category, "cwe": f.cwe,
        } for f in semgrep_findings],
        "summary": summary,
        "file_inventory": file_inventory,
    }


def _build_file_inventory(repo_path: Path) -> dict[str, Any]:
    ext_count: dict[str, int] = {}
    total = 0
    all_files: list[dict[str, Any]] = []
    valid_exts = set(UNIVERSAL_ENTRY_EXTENSIONS.keys())

    for f in repo_path.rglob("*"):
        if not f.is_file() or _skip_file(f):
            continue
        ext = f.suffix.lower()
        if ext not in valid_exts:
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
