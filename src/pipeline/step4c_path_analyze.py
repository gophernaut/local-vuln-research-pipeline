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


def _reconstruct_paths(path_data: list | dict) -> list[ExploitPath]:
    if isinstance(path_data, list):
        raw_paths = path_data
    else:
        raw_paths = path_data.get("paths", [])
    paths = []
    for p in raw_paths:
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

    paths_raw = path_data.get("paths", [])
    if not paths_raw and path_data.get("paths_count"):
        import json
        checkpoint_dir = repo_path.parent / "data" / "checkpoints"
        from src.utils.file_utils import repo_checkpoint_key
        ck = repo_checkpoint_key(repo_path)
        jsonl_path = checkpoint_dir / ck / "path_enum.jsonl"
        if jsonl_path.exists():
            logger.info(f"  Loading full paths from {jsonl_path}...")
            paths_raw = []
            with open(jsonl_path, encoding="utf-8") as f:
                for line in f:
                    try:
                        paths_raw.append(json.loads(line))
                    except Exception:
                        continue
            logger.info(f"  Loaded {len(paths_raw)} paths from JSONL")

    exploitable_paths = _reconstruct_paths(paths_raw if paths_raw else path_data)
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
    auto_classified = sum(1 for r in results if r.analysis_source == "auto")
    llm_validated = sum(1 for r in results if r.analysis_source == "llm")
    auto_blocked = sum(1 for r in results if r.verdict == "BLOCKED" and r.analysis_source == "auto")
    llm_blocked = sum(1 for r in results if r.verdict == "BLOCKED" and r.analysis_source == "llm")
    llm_exploitable = sum(1 for r in results if r.verdict == "VERIFIED_EXPLOITABLE" and r.analysis_source == "llm")
    uncertain = sum(1 for r in results if r.verdict == "uncertain")

    logger.info(
        f"  Coverage: {len(results)} unique paths ({auto_classified} auto, {llm_validated} LLM) — "
        f"{verified} exploitable, "
        f"{auto_blocked + llm_blocked} blocked, {uncertain} uncertain"
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
            "auto_classified": auto_classified,
            "llm_validated": llm_validated,
            "verified_exploitable": verified + llm_exploitable,
            "llm_exploitable": llm_exploitable,
            "blocked": auto_blocked + llm_blocked,
            "auto_blocked": auto_blocked,
            "llm_blocked": llm_blocked,
            "uncertain": uncertain,
        },
        "elapsed_seconds": time.time() - t0,
    }
