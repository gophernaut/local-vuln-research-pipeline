"""Per-path LLM analysis — analyzes each enumerated exploit path with the LLM.

For each path produced by the path enumerator, builds a focused prompt with:
- Source: what data enters the system and where
- Sink: what dangerous operation is reached
- Complete source of all functions on the path
- Sanitizers found on the path
- Question: is this path actually exploitable?

Paths are deduplicated by unique (source, sink) pairs. Clear-cut cases
(sanitizer-blocked, unreachable) get deterministic verdicts without LLM.
Ambiguous paths go to the LLM for reasoning. No path is skipped.
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
    analysis_source: str = ""


def _build_cve_context(cve_catalog: dict | None, cwe_id: str, sink_category: str) -> str:
    if not cve_catalog:
        return ""

    cve_candidates = []
    classes = cve_catalog.get("classes", {})

    if cwe_id:
        cwe_id_stripped = cwe_id.replace("CWE-", "")
        for exploit_class, cves in classes.items():
            for cve in cves:
                cwe_field = cve.get("cwe_ids", "")
                if not isinstance(cwe_field, str):
                    continue
                if cwe_id in cwe_field or cwe_id_stripped in cwe_field:
                    cve_candidates.append(cve)

    if not cve_candidates:
        for key in (sink_category, sink_category.lower(), sink_category.replace("_", " ")):
            if key in classes:
                cve_candidates = classes[key]
                break

    if not cve_candidates:
        return ""

    lines = []
    lines.append("== SIMILAR KNOWN VULNERABILITIES (same CWE/product) ==")
    for cve in cve_candidates[:3]:
        cve_id = cve.get("cve_id", "")
        desc = (cve.get("description") or "")[:200]
        sev = cve.get("severity", "?")
        kev = " [CISA KEV]" if cve.get("kev_member") else ""
        lines.append(f"- {cve_id} ({sev}){kev}: {desc}")
    lines.append("")

    return "\n".join(lines)


def _build_path_prompt(path: ExploitPath, function_sources: dict[str, str],
                       cve_catalog: dict | None = None) -> str:
    source = path.source
    sink = path.sink

    cve_context = _build_cve_context(cve_catalog, sink.cwe_id, sink.category)

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

{cve_context}
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
            try:
                file_path = Path(step.file)
                if not file_path.is_absolute():
                    file_path = repo_path / step.file
            except Exception:
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


def _make_path_result(path: ExploitPath, verdict: str, confidence: float,
                      reasoning: str, exploit_scenario: str,
                      severity: str, poc_idea: str,
                      analysis_source: str = "") -> PathAnalysisResult:
    return PathAnalysisResult(
        path_id=path.path_id,
        verdict=verdict,
        confidence=confidence,
        reasoning=reasoning,
        exploit_scenario=exploit_scenario,
        severity=severity,
        cwe_id=path.sink.cwe_id,
        entry_point=f"{path.source.file}:{path.source.line} ({path.source.source_type})",
        sink=f"{path.sink.file}:{path.sink.line} ({path.sink.category})",
        file_path=path.sink.file,
        source_line=path.source.line,
        sink_line=path.sink.line,
        functions_on_path=[s.function_name for s in path.steps],
        sanitizers_seen=[s.function_name for s in path.sanitizers_on_path],
        tainted_vars=list(path.steps[-1].tainted_vars) if path.steps else [],
        poc_idea=poc_idea,
        analysis_source=analysis_source,
    )


def _has_real_function_path(steps) -> bool:
    return any(s.function_name and s.function_name != "<module-level>" for s in steps)


def _has_sink_reach(path: ExploitPath) -> bool:
    return any(s.sink_reach for s in path.steps)


def analyze_paths_with_llm(
    paths: list[ExploitPath],
    repo_path: Path,
    max_paths: int = 0,
    temperature: float = 0.3,
    cve_catalog: dict | None = None,
) -> list[PathAnalysisResult]:
    logger.info(f"Analyzing {len(paths)} enumerated paths")

    sev_value = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    deterministic_results: list[PathAnalysisResult] = []
    llm_candidates: list[ExploitPath] = []
    low_priority: list[ExploitPath] = []

    seen_combos = set()
    for path in paths:
        combo_key = (
            path.source.file, path.source.line,
            path.sink.file, path.sink.line, path.sink.category,
            path.is_blocked_by_sanitizer,
        )
        if combo_key in seen_combos:
            continue
        seen_combos.add(combo_key)

        if not path.is_exploitable:
            deterministic_results.append(_make_path_result(
                path, "BLOCKED", 0.95,
                "Sink is not in the last function on the call path — structurally unreachable.",
                "", path.sink.severity, "", "auto",
            ))
            continue

        has_real_path = _has_real_function_path(path.steps)
        sink_reached = _has_sink_reach(path)

        if not has_real_path and not sink_reached:
            low_priority.append(path)
        else:
            llm_candidates.append(path)

    all_llm = llm_candidates + low_priority

    logger.info(f"  Dedup: {len(paths)} raw → {len(seen_combos)} unique "
                f"(+{len(deterministic_results)} structurally invalid, "
                f"{len(llm_candidates)} direct, {len(low_priority)} module-level)")

    if max_paths > 0 and len(all_llm) > max_paths:
        logger.warning(f"  {len(all_llm)} paths need LLM but max_llm_paths={max_paths}. "
                       f"Sampling top {max_paths}. Set max_llm_paths: 0 in config.yaml for unlimited.")

        scored = []
        for p in llm_candidates:
            sev = sev_value.get(p.sink.severity.upper(), 0)
            scored.append((sev + 5, p))
        for p in low_priority:
            sev = sev_value.get(p.sink.severity.upper(), 0)
            scored.append((sev, p))
        scored.sort(key=lambda x: x[0], reverse=True)

        seen_sinks = set()
        priority = []
        for _score, p in scored:
            sk = f"{p.sink.file}:{p.sink.line}:{p.sink.category}"
            if sk not in seen_sinks:
                seen_sinks.add(sk)
                priority.append(p)
                if len(priority) >= max_paths:
                    break
        remaining = max_paths - len(priority)
        if remaining > 0:
            for _score, p in scored:
                if p not in priority:
                    priority.append(p)
                    if len(priority) >= max_paths:
                        break
        all_llm = priority

    function_sources = _load_function_sources(all_llm, repo_path)

    client = LLMClient()
    llm_results = []

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

    for i, path in enumerate(all_llm):
        if not path.is_exploitable:
            continue

        prompt = _build_path_prompt(path, function_sources, cve_catalog)

        try:
            result = client.chat_json(
                system, prompt,
                temperature=temperature,
                max_tokens=2048,
            )
        except Exception:
            result = None

        if not result:
            llm_results.append(_make_path_result(
                path, "uncertain", 0.3,
                "LLM call failed — could not analyze this path.",
                "", path.sink.severity, "", "llm",
            ))
            continue

        result_dict = result if isinstance(result, dict) else {}
        verdict = result_dict.get("verdict", "uncertain")
        confidence = float(result_dict.get("confidence", 0.5))

        if verdict == "exploitable":
            verdict = "VERIFIED_EXPLOITABLE"
        elif verdict == "blocked":
            verdict = "BLOCKED"

        if verdict == "uncertain" or confidence < 0.6:
            logger.info(f"  Low confidence ({confidence}) for {path.path_id}, running self-consistency...")
            try:
                sc_result = client.self_consistent(
                    system, prompt, runs=3, temperature=0.4,
                )
                if sc_result:
                    sc_dict = sc_result if isinstance(sc_result, dict) else {}
                    sc_verdict = sc_dict.get("verdict", "uncertain")
                    if sc_verdict == "exploitable":
                        sc_verdict = "VERIFIED_EXPLOITABLE"
                    elif sc_verdict == "blocked":
                        sc_verdict = "BLOCKED"
                    if sc_verdict != "uncertain":
                        verdict = sc_verdict
                        confidence = max(confidence, float(sc_dict.get("confidence", confidence)))
                        result_dict = sc_dict
            except Exception:
                pass

        llm_results.append(_make_path_result(
            path, verdict,
            confidence,
            result_dict.get("reasoning", ""),
            result_dict.get("exploit_scenario", ""),
            result_dict.get("severity", path.sink.severity),
            result_dict.get("poc_idea", ""),
            "llm",
        ))

        if (i + 1) % 50 == 0:
            logger.info(f"  LLM analyzed {i + 1}/{len(all_llm)} paths")

    all_results = deterministic_results + llm_results
    verified = sum(1 for r in all_results if r.verdict == "VERIFIED_EXPLOITABLE")
    auto_blocked = sum(1 for r in deterministic_results if r.verdict == "BLOCKED")
    llm_blocked = sum(1 for r in llm_results if r.verdict == "BLOCKED")
    uncertain = sum(1 for r in all_results if r.verdict == "uncertain")

    logger.info(
        f"  Coverage complete: {len(all_results)} unique paths analyzed "
        f"({verified} exploitable, {auto_blocked + llm_blocked} blocked "
        f"[{auto_blocked} auto/{llm_blocked} llm], {uncertain} uncertain)"
    )

    return all_results


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
