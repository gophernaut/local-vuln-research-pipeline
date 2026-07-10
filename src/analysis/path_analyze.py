"""Per-path LLM analysis — analyzes each enumerated exploit path with the LLM.

For each path produced by the path enumerator, builds a focused prompt with:
- Source: what data enters the system and where
- Sink: what dangerous operation is reached
- Complete source of all functions on the path
- Sanitizers found on the path
- Question: is this path actually exploitable?

The LLM returns: verdict (exploitable/blocked/uncertain), reasoning, exploit scenario.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.analysis.path_enum import ExploitPath, PathEnumerator
from src.analysis.call_graph import CallGraph
from src.analysis.sink_tag import SinkTag
from src.analysis.source_tag import SourceTag
from src.analysis.sanitizer_tag import SanitizerTag
from src.llm.client import LLMClient
from src.llm.prompts import GUARD_PREAMBLE
from src.config import config
from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class PathAnalysisResult:
    path_id: str
    verdict: str
    confidence: float
    reasoning: str
    exploit_scenario: str
    severity: str
    cwe_id: str
    entry_point: str
    sink: str
    file_path: str
    source_line: int
    sink_line: int
    functions_on_path: list[str]
    sanitizers_seen: list[str]
    tainted_vars: list[str]
    poc_idea: str = ""


def _build_path_prompt(path: ExploitPath, function_sources: dict[str, str]) -> str:
    source = path.source
    sink = path.sink

    code_blocks = []
    for step in path.steps:
        func_key = step.function_key
        if func_key in function_sources:
            code_blocks.append(
                f"--- FUNCTION: {step.function_name} ({step.file}:{step.line}) ---\n"
                f"{function_sources[func_key]}"
            )
        for s_name in step.sanitizer_seen:
            code_blocks.append(f"  SANITIZER FOUND: {s_name}")

    code_text = "\n\n".join(code_blocks) if code_blocks else "(no code available)"

    prompt = f"""ANALYZE THIS EXPLOIT PATH. Determine if it is genuinely exploitable.

== SOURCE (untrusted data entry) ==
Type: {source.source_type}
File: {source.file}:{source.line}
Variable: {source.variable}
Description: {source.description}

== SINK (dangerous operation) ==
Category: {sink.category}
File: {sink.file}:{sink.line}
CWE: {sink.cwe_id}
Description: {sink.description}
Code: {sink.matched_text}

== DATA FLOW PATH ==
The data flows through these functions (in order):
"""
    for i, step in enumerate(path.steps, 1):
        prompt += f"  {i}. {step.function_name} @ {step.file}:{step.line}"
        if step.sanitizer_seen:
            prompt += f" [sanitizers: {', '.join(step.sanitizer_seen)}]"
        if step.tainted_vars:
            prompt += f" [tainted: {', '.join(list(step.tainted_vars)[:3])}]"
        prompt += "\n"

    prompt += f"""
== COMPLETE SOURCE OF FUNCTIONS ON PATH ==
{code_text[:25000]}

== YOUR TASK ==
Determine:
1. Is this data flow path actually reachable at runtime?
2. Is the tainted data actually used at the sink (not just passed through)?
3. Do the sanitizers on the path actually protect against this exploit?
4. Can an external, unauthenticated attacker trigger this?
5. What is the concrete impact if exploited?
6. What is the precise attack scenario?

Be BRUTALLY honest. If the path is blocked, say so. If the sink is unreachable, say so. If the precondition grants equal power, discard.

OUTPUT FORMAT (valid JSON):
{{
  "verdict": "exploitable" | "blocked" | "uncertain",
  "confidence": 0.0-1.0,
  "reasoning": "detailed explanation of why this verdict",
  "exploit_scenario": "step-by-step how attacker would exploit this",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "preconditions": ["what must be true"],
  "is_externally_reachable": true/false,
  "poc_idea": "how to prove this is exploitable (HTTP request, input, etc.)"
}}
"""
    return prompt


def _load_function_sources(paths: list[ExploitPath], repo_path: Path) -> dict[str, str]:
    function_sources = {}
    for path in paths:
        for step in path.steps:
            func_key = step.function_key
            if func_key in function_sources:
                continue
            file_path = repo_path / step.file
            if not file_path.exists():
                continue
            try:
                with open(file_path, encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                start = max(0, step.line - 1)
                end = min(len(lines), start + 100)
                function_sources[func_key] = "".join(lines[start:end])
            except Exception:
                continue
    return function_sources


def analyze_paths_with_llm(
    paths: list[ExploitPath],
    repo_path: Path,
    max_paths: int = 500,
    temperature: float = 0.3,
) -> list[PathAnalysisResult]:
    logger.info(f"Analyzing {len(paths)} paths with LLM (max {max_paths})")

    if len(paths) > max_paths:
        priority_paths = sorted(
            paths,
            key=lambda p: (p.sink.severity == "CRITICAL", p.sink.severity == "HIGH",
                          len(p.sanitizers_on_path) == 0),
            reverse=True,
        )[:max_paths]
    else:
        priority_paths = paths

    function_sources = _load_function_sources(priority_paths, repo_path)

    client = LLMClient()
    results = []

    system = f"""{GUARD_PREAMBLE}

You are an elite exploit developer performing per-path exploitability analysis.

Your job: given a pre-traced source-to-sink path with the complete function code,
determine if it is genuinely exploitable. You are NOT searching for vulns — the
path has already been enumerated. You are validating ONE specific path.

DECISION CRITERIA:
- VERIFIED_EXPLOITABLE: Path is reachable, tainted data flows to sink, no
  effective sanitizers, attacker can control data externally.
- BLOCKED: Path has an effective sanitizer between source and sink, or the
  sink is unreachable, or the data is sanitized before reaching the sink.
- UNCERTAIN: Cannot determine without runtime info. Report what additional
  evidence would be needed.

Be specific. Cite exact lines. Don't pad with caveats. Make a decision.
"""

    for i, path in enumerate(priority_paths):
        if not path.is_exploitable:
            continue

        prompt = _build_path_prompt(path, function_sources)

        try:
            result = client.chat_json(
                system, prompt,
                temperature=temperature,
                max_tokens=2048,
            )

            if result:
                result_dict = result if isinstance(result, dict) else {}
                verdict = result_dict.get("verdict", "uncertain")
                if verdict == "exploitable":
                    verdict = "VERIFIED_EXPLOITABLE"
                elif verdict == "blocked":
                    verdict = "BLOCKED"

                results.append(PathAnalysisResult(
                    path_id=path.path_id,
                    verdict=verdict,
                    confidence=float(result_dict.get("confidence", 0.5)),
                    reasoning=result_dict.get("reasoning", ""),
                    exploit_scenario=result_dict.get("exploit_scenario", ""),
                    severity=result_dict.get("severity", path.sink.severity),
                    cwe_id=path.sink.cwe_id,
                    entry_point=f"{path.source.file}:{path.source.line} ({path.source.source_type})",
                    sink=f"{path.sink.file}:{path.sink.line} ({path.sink.category})",
                    file_path=path.sink.file,
                    source_line=path.source.line,
                    sink_line=path.sink.line,
                    functions_on_path=[s.function_name for s in path.steps],
                    sanitizers_seen=[s.function_name for s in path.sanitizers_on_path],
                    tainted_vars=list(path.steps[-1].tainted_vars) if path.steps else [],
                    poc_idea=result_dict.get("poc_idea", ""),
                ))

        except Exception as e:
            logger.warning(f"  LLM analysis failed for {path.path_id}: {e}")
            continue

        if (i + 1) % 50 == 0:
            logger.info(f"  Analyzed {i + 1}/{len(priority_paths)} paths")

    logger.info(f"LLM analysis complete: {len(results)} paths analyzed")
    return results


def analyze_paths(
    call_graph: CallGraph,
    sources: list[SourceTag],
    sinks: list[SinkTag],
    sanitizers: list[SanitizerTag],
    file_analyses: list,
    repo_path: Path,
    max_paths: int = 500,
) -> list[PathAnalysisResult]:
    enumerator = PathEnumerator()
    paths = enumerator.enumerate_all_paths(call_graph, sources, sinks, sanitizers, file_analyses)
    return analyze_paths_with_llm(paths, repo_path, max_paths=max_paths)
