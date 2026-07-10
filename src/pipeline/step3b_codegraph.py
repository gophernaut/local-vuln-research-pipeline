"""Step 3b: Code graph construction — builds the full code graph.

Constructs: call graph, source tags, sink tags, sanitizer tags, memory analysis.
This is the foundation for the path enumeration that follows.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from src.analysis.call_graph import CallGraphBuilder
from src.analysis.source_tag import SourceTagger
from src.analysis.sink_tag import SinkTagger
from src.analysis.sanitizer_tag import SanitizerTagger
from src.analysis.ast_parser import ASTParser
from src.analysis.memory.orchestrator import run_memory_analysis
from src.utils.logger import get_logger

logger = get_logger()


def run(repo_path: Path) -> dict[str, Any]:
    logger.info("Step 3b: Building complete code graph...")

    t0 = time.time()

    parser = ASTParser()
    logger.info("  Parsing all source files with tree-sitter...")
    analyses = parser.parse_directory(repo_path)
    logger.info(f"  Parsed {len(analyses)} files")

    logger.info("  Building call graph with import resolution...")
    cg_builder = CallGraphBuilder()
    call_graph = cg_builder.build(repo_path)
    logger.info(f"  Call graph: {len(call_graph.nodes)} functions, "
                f"{sum(len(e) for e in call_graph.edges.values())} edges")

    logger.info("  Tagging sources (untrusted entry points)...")
    source_tagger = SourceTagger()
    sources = source_tagger.tag_repo(repo_path)
    logger.info(f"  Found {len(sources)} source tags")

    logger.info("  Tagging sinks (dangerous operations)...")
    sink_tagger = SinkTagger()
    sinks = sink_tagger.tag_repo(repo_path)
    logger.info(f"  Found {len(sinks)} sink tags")

    logger.info("  Tagging sanitizers...")
    sanitizer_tagger = SanitizerTagger()
    sanitizers = sanitizer_tagger.tag_repo(repo_path)
    logger.info(f"  Found {len(sanitizers)} sanitizer tags")

    logger.info("  Running memory corruption analysis...")
    memory_findings = run_memory_analysis(repo_path)
    logger.info(f"  Found {len(memory_findings)} memory findings")

    result = {
        "code_graph": {
            "functions": [
                {
                    "key": f"{func.file}::{func.name}",
                    "name": func.name,
                    "file": func.file,
                    "line": func.line,
                    "end_line": func.end_line,
                    "params": func.params,
                    "is_exported": func.is_exported,
                    "is_static": func.is_static,
                    "is_constructor": func.is_constructor,
                    "class_name": func.class_name,
                    "body": func.body,
                }
                for func in call_graph.nodes.values()
            ],
            "edges": [
                {"from": caller, "to": callee}
                for caller, callees in call_graph.edges.items()
                for callee in callees
            ],
            "entry_points": call_graph.entry_points,
            "function_count": len(call_graph.nodes),
            "edge_count": sum(len(e) for e in call_graph.edges.values()),
        },
        "sources": [
            {
                "file": s.file, "line": s.line, "variable": s.variable,
                "source_type": s.source_type, "description": s.description,
                "is_attacker_controlled": s.is_attacker_controlled,
                "confidence": s.confidence,
            }
            for s in sources
        ],
        "sinks": [
            {
                "file": s.file, "line": s.line, "category": s.category,
                "cwe_id": s.cwe_id, "description": s.description,
                "matched_text": s.matched_text, "language": s.language,
                "severity": s.severity,
            }
            for s in sinks
        ],
        "sanitizers": [
            {
                "file": s.file, "line": s.line, "category": s.category,
                "function_name": s.function_name, "description": s.description,
                "protected_against": s.protected_against,
                "is_effective": s.is_effective,
            }
            for s in sanitizers
        ],
        "memory_findings": [
            {
                "file": f.file, "line": f.line,
                "vulnerability_class": f.vulnerability_class,
                "description": f.description, "severity": f.severity,
                "confidence": f.confidence, "cwe_id": f.cwe_id,
                "source_module": f.source_module,
            }
            for f in memory_findings
        ],
        "summary": {
            "files_analyzed": len(analyses),
            "functions": len(call_graph.nodes),
            "edges": sum(len(e) for e in call_graph.edges.values()),
            "entry_points": len(call_graph.entry_points),
            "sources": len(sources),
            "sinks": len(sinks),
            "sanitizers": len(sanitizers),
            "memory_findings": len(memory_findings),
        },
        "elapsed_seconds": time.time() - t0,
    }

    logger.info(
        f"  Code graph complete: {result['summary']['functions']} functions, "
        f"{result['summary']['sources']} sources, {result['summary']['sinks']} sinks, "
        f"{result['summary']['sanitizers']} sanitizers"
    )

    return result
