"""Step 3: Full static analysis — runs all deterministic analyzers.

Covers 100% of code: Semgrep, tree-sitter AST, sink finder, call graph,
initial taint flow. All analyzers run in parallel per file.
"""
from __future__ import annotations

import concurrent.futures
from pathlib import Path
from typing import Any

from src.analysis.semgrep_runner import SemgrepRunner
from src.analysis.ast_parser import ASTParser
from src.analysis.sink_finder import SinkFinder
from src.analysis.call_graph import CallGraphBuilder
from src.analysis.data_flow import DataFlowAnalyzer
from src.utils.logger import get_logger
from src.config import config

logger = get_logger()


def run(repo_path: Path) -> dict[str, Any]:
    logger.info("Step 3: Running full static analysis...")

    semgrep_findings = []
    ast_analyses = []
    sink_matches = []
    call_graph = None
    taint_flows = []

    analysis_funcs = {
        "semgrep": lambda: _run_semgrep(repo_path),
        "ast": lambda: _run_ast(repo_path),
        "sinks": lambda: _run_sinks(repo_path),
        "callgraph": lambda: _run_callgraph(repo_path),
        "taint": lambda: _run_taint(repo_path),
    }

    workers = min(config.get("pipeline.parallel_analyzers", 16), 16)
    results: dict[str, Any] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(func): name for name, func in analysis_funcs.items()}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result(timeout=600)
            except Exception as e:
                logger.error(f"  {name} failed: {e}")
                results[name] = None

    semgrep_findings = results.get("semgrep", [])
    ast_analyses = results.get("ast", [])
    sink_matches = results.get("sinks", [])
    call_graph = results.get("callgraph")
    taint_flows = results.get("taint", [])

    summary = {
        "semgrep_hits": len(semgrep_findings),
        "files_analyzed": len(ast_analyses),
        "sinks_found": len(sink_matches),
        "call_graph_functions": len(call_graph.nodes) if call_graph else 0,
        "call_graph_edges": sum(len(e) for e in call_graph.edges.values()) if call_graph else 0,
        "taint_flows": len(taint_flows),
        "high_confidence_flows": sum(1 for f in taint_flows if f.confidence >= 0.5),
    }

    logger.info(
        f"  {summary['files_analyzed']} files analyzed | "
        f"{summary['semgrep_hits']} semgrep hits | "
        f"{summary['sinks_found']} sinks | "
        f"{summary['taint_flows']} taint flows"
    )

    return {
        "semgrep_findings": [{
            "rule_id": f.rule_id,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "severity": f.severity,
            "category": f.category,
            "cwe": f.cwe,
        } for f in semgrep_findings],
        "summary": summary,
        "_ast_analyses": ast_analyses,
        "_sink_matches": [{
            "file": s.file, "line": s.line, "category": s.category,
            "sink_type": s.sink_type, "matched_text": s.matched_text,
            "cwe_id": s.cwe_id,
        } for s in sink_matches],
        "_call_graph": call_graph,
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


def _run_semgrep(repo_path: Path) -> list:
    runner = SemgrepRunner()
    return runner.run(repo_path)


def _run_ast(repo_path: Path) -> list:
    parser = ASTParser()
    return parser.parse_directory(repo_path)


def _run_sinks(repo_path: Path) -> list:
    finder = SinkFinder()
    return finder.find_in_directory(repo_path)


def _run_callgraph(repo_path: Path):
    builder = CallGraphBuilder()
    return builder.build(repo_path)


def _run_taint(repo_path: Path) -> list:
    analyzer = DataFlowAnalyzer()
    return analyzer.analyze(repo_path)
