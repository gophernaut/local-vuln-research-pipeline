"""Step 4c: Per-path LLM analysis — validates each enumerated path for exploitability.

For each potentially exploitable path, loads full source of all functions and
asks the LLM to determine if the path is genuinely exploitable.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from src.analysis.path_analyze import analyze_paths_with_llm
from src.analysis.path_enum import ExploitPath, PathStep
from src.analysis.source_tag import SourceTag
from src.analysis.sink_tag import SinkTag
from src.utils.logger import get_logger
from src.config import config

logger = get_logger()


def _reconstruct_paths(path_data: dict) -> list[ExploitPath]:
    paths = []
    for p in path_data.get("paths", []):
        if not p.get("is_exploitable"):
            continue
        source = SourceTag(
            file=p["source"]["file"], line=p["source"]["line"],
            variable=p["source"]["variable"],
            source_type=p["source"]["source_type"],
            description=p["source"].get("description", ""),
        )
        sink = SinkTag(
            file=p["sink"]["file"], line=p["sink"]["line"],
            category=p["sink"]["category"],
            cwe_id=p["sink"]["cwe_id"],
            description=p["sink"].get("description", ""),
            severity=p["sink"].get("severity", "HIGH"),
        )

        steps = []
        for s in p.get("steps", []):
            steps.append(PathStep(
                function_key=f"{s['file']}::{s['function_name']}",
                file=s["file"], line=s["line"],
                function_name=s["function_name"],
                tainted_vars=set(s.get("tainted_vars", [])),
                sanitizer_seen=s.get("sanitizers", []),
            ))

        paths.append(ExploitPath(
            path_id=p["path_id"],
            source=source, sink=sink,
            steps=steps,
            is_exploitable=p.get("is_exploitable", True),
            is_blocked_by_sanitizer=p.get("is_blocked_by_sanitizer", False),
            cwe_id=sink.cwe_id,
        ))

    return paths


def run(repo_path: Path, path_data: dict, cve_catalog: dict | None = None) -> dict[str, Any]:
    logger.info("Step 4c: Per-path LLM analysis...")

    t0 = time.time()

    max_paths = config.get("pipeline.max_llm_paths", 500)
    temperature = config.get("pipeline.llm_temperature", 0.3)

    exploitable_paths = _reconstruct_paths(path_data)
    logger.info(f"  Reconstructed {len(exploitable_paths)} potentially exploitable paths")
    if cve_catalog:
        logger.info(f"  CVE catalog available: {cve_catalog.get('count', 0)} CVEs for context injection")

    if not exploitable_paths:
        logger.info("  No paths to analyze")
        return {
            "results": [],
            "summary": {
                "analyzed": 0,
                "verified_exploitable": 0,
                "blocked": 0,
                "uncertain": 0,
            },
            "elapsed_seconds": 0,
        }

    results = analyze_paths_with_llm(
        exploitable_paths, repo_path,
        max_paths=max_paths,
        temperature=temperature,
        cve_catalog=cve_catalog,
    )

    verified = sum(1 for r in results if r.verdict == "VERIFIED_EXPLOITABLE")
    blocked = sum(1 for r in results if r.verdict == "BLOCKED")
    uncertain = sum(1 for r in results if r.verdict == "uncertain")
    logger.info(
        f"  LLM analysis: {verified} VERIFIED EXPLOITABLE, {blocked} BLOCKED, "
        f"{uncertain} UNCERTAIN"
    )

    return {
        "results": [
            {
                "path_id": r.path_id,
                "verdict": r.verdict,
                "confidence": r.confidence,
                "reasoning": r.reasoning,
                "exploit_scenario": r.exploit_scenario,
                "severity": r.severity,
                "cwe_id": r.cwe_id,
                "entry_point": r.entry_point,
                "sink": r.sink,
                "file_path": r.file_path,
                "source_line": r.source_line,
                "sink_line": r.sink_line,
                "functions_on_path": r.functions_on_path,
                "sanitizers_seen": r.sanitizers_seen,
                "tainted_vars": r.tainted_vars,
                "poc_idea": r.poc_idea,
            }
            for r in results
        ],
        "summary": {
            "analyzed": len(results),
            "verified_exploitable": verified,
            "blocked": blocked,
            "uncertain": uncertain,
        },
        "elapsed_seconds": time.time() - t0,
    }
