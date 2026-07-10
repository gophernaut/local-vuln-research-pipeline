"""Step 7: Chain synthesis — combines individual findings into multi-step exploit chains.

Builds attack graph from verified exploitable paths, computes valid chains.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from src.analysis.attack_graph import build_attack_graph, ExploitChain, ChainLink
from src.analysis.path_analyze import PathAnalysisResult
from src.utils.logger import get_logger

logger = get_logger()


def _paths_from_dict(results: list[dict]) -> list[PathAnalysisResult]:
    return [
        PathAnalysisResult(
            path_id=r["path_id"],
            verdict=r["verdict"],
            confidence=r["confidence"],
            reasoning=r.get("reasoning", ""),
            exploit_scenario=r.get("exploit_scenario", ""),
            severity=r.get("severity", "MEDIUM"),
            cwe_id=r.get("cwe_id", ""),
            entry_point=r.get("entry_point", ""),
            sink=r.get("sink", ""),
            file_path=r.get("file_path", ""),
            source_line=r.get("source_line", 0),
            sink_line=r.get("sink_line", 0),
            functions_on_path=r.get("functions_on_path", []),
            sanitizers_seen=r.get("sanitizers_seen", []),
            tainted_vars=r.get("tainted_vars", []),
            poc_idea=r.get("poc_idea", ""),
        )
        for r in results
    ]


def run(path_analysis: dict) -> dict[str, Any]:
    logger.info("Step 7: Chain synthesis...")

    t0 = time.time()

    results = path_analysis.get("results", [])
    findings = _paths_from_dict(results)

    chains = build_attack_graph(findings)

    logger.info(f"  Synthesized {len(chains)} chains")

    return {
        "chains": [
            {
                "name": c.name,
                "links": [
                    {
                        "finding_id": l.finding_id,
                        "role": l.role,
                        "description": l.description,
                        "file": l.file,
                        "line": l.line,
                        "cwe_id": l.cwe_id,
                        "severity": l.severity,
                        "impact": l.impact,
                    }
                    for l in c.links
                ],
                "description": c.description,
                "combined_impact": c.combined_impact,
                "combined_severity": c.combined_severity,
                "combined_confidence": c.combined_confidence,
                "valid": c.valid,
                "entry_point": c.entry_point,
                "final_impact": c.final_impact,
            }
            for c in chains
        ],
        "summary": {
            "total_chains": len(chains),
            "valid_chains": sum(1 for c in chains if c.valid),
        },
        "elapsed_seconds": time.time() - t0,
    }
