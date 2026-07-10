"""Step 4b: Path enumeration — enumerates all source-to-sink paths through call graph.

Uses the code graph from step 3b to enumerate every possible exploit path.
Each path is then analyzed for taint and sanitizers.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from src.analysis.call_graph import CallGraphBuilder
from src.analysis.path_enum import PathEnumerator
from src.analysis.source_tag import SourceTag
from src.analysis.sink_tag import SinkTag
from src.analysis.sanitizer_tag import SanitizerTag
from src.utils.logger import get_logger
from src.config import config

logger = get_logger()


def _sources_from_dict(dicts: list[dict]) -> list[SourceTag]:
    return [SourceTag(
        file=d["file"], line=d["line"], variable=d["variable"],
        source_type=d["source_type"], description=d["description"],
        is_attacker_controlled=d.get("is_attacker_controlled", True),
        confidence=d.get("confidence", 0.9),
    ) for d in dicts]


def _sinks_from_dict(dicts: list[dict]) -> list[SinkTag]:
    return [SinkTag(
        file=d["file"], line=d["line"], category=d["category"],
        cwe_id=d["cwe_id"], description=d["description"],
        matched_text=d.get("matched_text", ""),
        language=d.get("language", ""), severity=d.get("severity", "HIGH"),
    ) for d in dicts]


def _sanitizers_from_dict(dicts: list[dict]) -> list[SanitizerTag]:
    return [SanitizerTag(
        file=d["file"], line=d["line"], category=d["category"],
        function_name=d["function_name"], description=d["description"],
        protected_against=d.get("protected_against", []),
        is_effective=d.get("is_effective", True),
    ) for d in dicts]


def run(repo_path: Path, code_graph: dict[str, Any]) -> dict[str, Any]:
    logger.info("Step 4b: Enumerating all source-to-sink paths...")

    t0 = time.time()

    sources = _sources_from_dict(code_graph.get("sources", []))
    sinks = _sinks_from_dict(code_graph.get("sinks", []))
    sanitizers = _sanitizers_from_dict(code_graph.get("sanitizers", []))

    logger.info(f"  Inputs: {len(sources)} sources, {len(sinks)} sinks, {len(sanitizers)} sanitizers")

    cg_data = code_graph.get("code_graph", {})
    stored_funcs = cg_data.get("functions", [])

    cg_builder = CallGraphBuilder()
    call_graph = cg_builder.build(repo_path)

    logger.info("  Loading function bodies from stored code graph...")
    functions_by_file = {}
    func_lookup = {f["key"]: f for f in stored_funcs}
    for func_key, func in call_graph.nodes.items():
        stored = func_lookup.get(func_key, {})
        body = stored.get("body", "") or func.body
        if body:
            func.body = body
        if not func.params and stored.get("params"):
            func.params = stored["params"]

        functions_by_file[func_key] = {
            "file": func.file,
            "name": func.name,
            "language": func.file.split(".")[-1] if "." in func.file else "python",
            "params": func.params,
            "body": func.body,
        }

    from src.analysis.call_graph import CallGraph
    for func_key, func_info in functions_by_file.items():
        func = call_graph.nodes[func_key]
        call_sites_data = [
            {
                "function_name": cs.function_name,
                "arguments": cs.arguments,
                "line": cs.line,
            }
            for cs in func_info.get("call_sites", [])
        ]
        func_info["call_sites"] = call_sites_data
        if func_key in call_graph.edges:
            for callee in call_graph.edges[func_key]:
                func_info["call_sites"].append({
                    "function_name": callee.split("::")[-1] if "::" in callee else callee,
                    "arguments": [],
                    "line": func.line,
                })

    max_depth = config.get("pipeline.max_path_depth", 8)
    max_paths_per_pair = config.get("pipeline.max_paths_per_pair", 20)

    enumerator = PathEnumerator(max_depth=max_depth, max_paths_per_pair=max_paths_per_pair)
    paths = enumerator.enumerate_all_paths(
        call_graph, sources, sinks, sanitizers, []
    )

    exploitable_count = sum(1 for p in paths if p.is_exploitable and not p.is_blocked_by_sanitizer)
    blocked_count = sum(1 for p in paths if p.is_blocked_by_sanitizer)
    logger.info(
        f"  Enumerated {len(paths)} paths: {exploitable_count} potentially exploitable, "
        f"{blocked_count} blocked by sanitizers"
    )

    result = {
        "paths": [
            {
                "path_id": p.path_id,
                "source": {
                    "file": p.source.file, "line": p.source.line,
                    "source_type": p.source.source_type, "variable": p.source.variable,
                },
                "sink": {
                    "file": p.sink.file, "line": p.sink.line,
                    "category": p.sink.category, "cwe_id": p.sink.cwe_id,
                    "severity": p.sink.severity,
                },
                "steps": [
                    {
                        "function_name": s.function_name,
                        "file": s.file, "line": s.line,
                        "sanitizers": s.sanitizer_seen,
                        "tainted_vars": list(s.tainted_vars),
                    }
                    for s in p.steps
                ],
                "is_exploitable": p.is_exploitable,
                "is_blocked_by_sanitizer": p.is_blocked_by_sanitizer,
                "sanitizers_count": len(p.sanitizers_on_path),
                "reachable": p.reachable,
            }
            for p in paths
        ],
        "summary": {
            "total_paths": len(paths),
            "potentially_exploitable": exploitable_count,
            "blocked_by_sanitizers": blocked_count,
            "unique_sources": len(set(p.source.file + str(p.source.line) for p in paths)),
            "unique_sinks": len(set(p.sink.file + str(p.sink.line) for p in paths)),
        },
        "elapsed_seconds": time.time() - t0,
    }

    logger.info(
        f"  Path enumeration complete: {result['summary']['total_paths']} paths in "
        f"{result['elapsed_seconds']:.1f}s"
    )

    return result
