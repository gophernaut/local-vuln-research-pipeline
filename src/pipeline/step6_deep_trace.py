"""Step 6: Deep code tracing — LLM traces full path from entry point to sink.

Verifies each hop against actual code. Checks for mitigations.
For top-3 hypotheses, Joern CPG can verify taint flow independently.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from src.llm.client import LLMClient
from src.llm.prompts import deep_trace_system
from src.llm.context import ContextManager
from src.utils.logger import get_logger

logger = get_logger()


def run(
    repo_path: Path,
    classification: dict[str, Any],
    hypotheses: list[dict[str, Any]],
    static_analysis: dict[str, Any],
) -> list[dict[str, Any]]:
    logger.info("Step 6: Deep code tracing (LLM file-by-file)...")

    if not hypotheses:
        logger.info("  No hypotheses to trace.")
        return []

    client = LLMClient()
    ctx = ContextManager()

    methodology_ref = _load_methodology(classification)
    system = deep_trace_system(methodology_ref)

    results = []
    max_trace = min(len(hypotheses), 10)

    for i, hyp in enumerate(hypotheses[:max_trace]):
        logger.info(f"  Tracing hypothesis {i + 1}/{min(len(hypotheses), max_trace)}: {hyp.get('vulnerability_class', '?')}")

        component = hyp.get("component", "")
        entry = hyp.get("entry_point", "")
        sink = hyp.get("sink", "")

        relevant_files = _find_relevant_files(repo_path, component, entry, sink, static_analysis)
        code_files = _read_files(relevant_files, repo_path)

        user = (
            f"Trace the exploit path for this hypothesis:\n\n"
            f"Vulnerability class: {hyp.get('vulnerability_class')}\n"
            f"Affected component: {component}\n"
            f"Entry point: {entry} (type: {hyp.get('entry_point_type')})\n"
            f"Expected sink: {sink}\n"
            f"Preconditions: {hyp.get('preconditions')}\n"
            f"Expected impact: {hyp.get('expected_impact')}\n\n"
            f"Trace the FULL data flow from entry point through every function call, "
            f"variable assignment, and transformation to the sink.\n"
            f"Each hop MUST cite exact file:line. Check for any mitigations (sanitization, "
            f"auth checks, input validation, parameterization) at each step.\n"
        )

        alloc = ctx.allocate(system, code_files=code_files)
        full_prompt = f"{user}\n\n=== Source Code ===\n{alloc['code']}"

        try:
            result = client.chat_json(system, full_prompt, max_tokens=3072)
            if result:
                result["hypothesis_index"] = i
                result["hypothesis_class"] = hyp.get("vulnerability_class")
                result["hypothesis_confidence"] = hyp.get("confidence")
                results.append(result)

                if result.get("exploitable") and result.get("reachable"):
                    logger.info(f"    EXPLOITABLE - {result.get('summary', '')[:100]}")
                    if config.get("pipeline.early_termination", True):
                        logger.info("    Early termination: confirmed HIGH/CRIT finding")
                        break
                elif result.get("blocked_by"):
                    logger.info(f"    BLOCKED: {result['blocked_by']}")
                else:
                    logger.info(f"    Not exploitable: {result.get('summary', '')[:100]}")
        except Exception as e:
            logger.warning(f"    Trace failed: {e}")
            results.append({
                "hypothesis_index": i,
                "error": str(e),
                "reachable": False,
                "exploitable": False,
            })

        ctx.reset_dedup()

    return results


def _load_methodology(classification: dict[str, Any]) -> str:
    primary = classification.get("primary_class", "web_app")
    refs = classification.get("loaded_refs", [])

    methodology_map = {
        "web_app": "Trace HTTP request -> middleware chain -> handler -> service -> data layer.",
        "native_memory": "Trace input -> memory allocation -> buffer operation -> overflow/UAF.",
        "kernel": "Trace syscall/ioctl -> copy_from_user -> validation -> kernel operation.",
        "java_platform": "Trace HTTP/deserialization -> filter chain -> controller -> service -> sink.",
        "dotnet": "Trace HTTP/deserialization -> middleware -> controller -> service -> sink.",
        "distributed": "Trace API call -> proxy/gateway -> service handler -> internal call -> sink.",
        "cli_tool": "Trace CLI arg/env var -> argument parser -> execution/dynamic eval -> sink.",
    }

    return methodology_map.get(primary, "Trace from entry point through all intermediaries to the sink.")


def _find_relevant_files(
    repo_path: Path,
    component: str,
    entry: str,
    sink: str,
    static_analysis: dict[str, Any],
) -> list[Path]:
    files = set()

    for sink_match in static_analysis.get("_sink_matches", []):
        files.add(repo_path / sink_match["file"])

    for flow in static_analysis.get("_taint_flows", []):
        sf = flow.get("source_file", "")
        df = flow.get("sink_file", "")
        if sf:
            files.add(repo_path / sf)
        if df:
            files.add(repo_path / df)

    for semgrep in static_analysis.get("semgrep_findings", []):
        files.add(repo_path / semgrep["file"])

    existing = [f for f in files if f.exists()]
    return existing[:15]


def _read_files(paths: list[Path], repo_root: Path) -> dict[str, str]:
    code_files: dict[str, str] = {}
    for f in paths:
        try:
            rel = str(f.relative_to(repo_root))
            with open(f, encoding="utf-8", errors="replace") as fh:
                code_files[rel] = fh.read()
        except Exception:
            continue
    return code_files
