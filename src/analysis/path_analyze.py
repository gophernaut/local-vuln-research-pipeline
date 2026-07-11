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
import os
import tempfile
import threading
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

    sink_context_key = f"__sink__{path.path_id}"
    sink_context = function_sources.get(sink_context_key, "")
    sink_context_block = ""
    if sink_context:
        sink_context_block = f"""
== SINK SOURCE CONTEXT (code around the dangerous operation) ==
File: {sink.file}:{sink.line}
---
{sink_context[:8000]}
"""
    elif not code_blocks:
        sink_context_block = """

== SINK SOURCE CODE ==
Code: {sink.matched_text[:500]}
"""

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
{sink_context_block}
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
    file_cache: dict[str, list[str]] = {}
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
                resolved = str(file_path.resolve())
                if resolved not in file_cache:
                    with open(resolved, encoding="utf-8", errors="replace") as f:
                        file_cache[resolved] = f.readlines()
                lines = file_cache[resolved]
                start = max(0, step.line - 1)
                end = min(len(lines), start + 100)
                function_sources[func_key] = "".join(lines[start:end])
            except Exception:
                continue

        sink_key = f"__sink__{path.path_id}"
        if sink_key not in function_sources:
            try:
                sink_path = Path(path.sink.file)
                if not sink_path.is_absolute():
                    sink_path = repo_path / path.sink.file
            except Exception:
                sink_path = repo_path / path.sink.file
            if sink_path.exists():
                try:
                    resolved = str(sink_path.resolve())
                    if resolved not in file_cache:
                        with open(resolved, encoding="utf-8", errors="replace") as f:
                            file_cache[resolved] = f.readlines()
                    lines = file_cache[resolved]
                    start = max(0, path.sink.line - 11)
                    end = min(len(lines), path.sink.line + 5)
                    function_sources[sink_key] = "".join(lines[start:end])
                except Exception:
                    pass

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


_CHECKPOINT_LOCK = threading.Lock()

CHECKPOINT_FILENAME = "path_analysis_progress.jsonl"


def _result_to_checkpoint_dict(r: PathAnalysisResult) -> dict:
    return {
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
        "analysis_source": r.analysis_source,
    }


def _dict_to_result(d: dict) -> PathAnalysisResult:
    return PathAnalysisResult(
        path_id=d["path_id"],
        verdict=d["verdict"],
        confidence=d["confidence"],
        reasoning=d.get("reasoning", ""),
        exploit_scenario=d.get("exploit_scenario", ""),
        severity=d.get("severity", "MEDIUM"),
        cwe_id=d.get("cwe_id", ""),
        entry_point=d.get("entry_point", ""),
        sink=d.get("sink", ""),
        file_path=d.get("file_path", ""),
        source_line=d.get("source_line", 0),
        sink_line=d.get("sink_line", 0),
        functions_on_path=d.get("functions_on_path", []),
        sanitizers_seen=d.get("sanitizers_seen", []),
        tainted_vars=d.get("tainted_vars", []),
        poc_idea=d.get("poc_idea", ""),
        analysis_source=d.get("analysis_source", ""),
    )


def _append_checkpoint(checkpoint_dir: Path, result: PathAnalysisResult):
    """Append a single result to the JSONL checkpoint file atomically."""
    checkpoint_path = checkpoint_dir / CHECKPOINT_FILENAME
    line = json.dumps(_result_to_checkpoint_dict(result), default=str) + "\n"

    with _CHECKPOINT_LOCK:
        existing = ""
        if checkpoint_path.exists():
            try:
                existing = checkpoint_path.read_text(encoding="utf-8")
            except Exception:
                existing = ""

        fd, tmp = tempfile.mkstemp(dir=str(checkpoint_dir), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(existing)
                f.write(line)
            os.replace(str(tmp), str(checkpoint_path))
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def load_checkpoint_results(checkpoint_dir: Path) -> tuple[list[PathAnalysisResult], set[str]]:
    """Load existing checkpoint results. Returns (results, completed_path_ids)."""
    checkpoint_path = checkpoint_dir / CHECKPOINT_FILENAME
    if not checkpoint_path.exists():
        return [], set()

    results = []
    completed_ids = set()
    try:
        with open(checkpoint_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    results.append(_dict_to_result(d))
                    completed_ids.add(d["path_id"])
                except (json.JSONDecodeError, KeyError):
                    continue
    except Exception:
        return [], set()

    return results, completed_ids


_VULN_CLASS_WEIGHT = {
    "command_execution": 10, "code_execution": 10, "deserialization": 9,
    "sql_injection": 8, "auth_bypass": 8, "template_injection": 7,
    "spel_injection": 7, "command_injection": 7,
    "ssrf": 6, "xxe": 6, "file_inclusion": 6, "reflection_invoke": 6,
    "path_traversal": 5, "file_write": 5, "race_condition": 5,
    "nosql_injection": 5, "buffer_overflow": 5, "format_string": 5,
    "graphql_injection": 4, "ldap_injection": 4, "xpath_injection": 4,
    "prototype_pollution": 4, "integer_overflow": 4, "unsafe_block": 4,
    "hardcoded_secret": 3, "file_read": 3,
    "weak_crypto": 2, "weak_random": 2, "insecure_crypto": 2,
}

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _get_context_weights(language: str = "", frameworks: list | None = None) -> dict[str, int]:
    """Adapt vuln class weights to codebase context. Boosts classes most relevant to
    the detected language and frameworks."""
    w = dict(_VULN_CLASS_WEIGHT)
    lang = (language or "").lower()
    fw_text = " ".join(str(f).lower() for f in (frameworks or []))

    if lang in ("c", "c++"):
        w["buffer_overflow"] = w.get("buffer_overflow", 2) + 5
        w["format_string"] = w.get("format_string", 2) + 5
        w["integer_overflow"] = w.get("integer_overflow", 2) + 5
        w["race_condition"] = w.get("race_condition", 2) + 3
    elif lang == "python":
        w["deserialization"] = w.get("deserialization", 5) + 2
        w["template_injection"] = w.get("template_injection", 5) + 2
        w["command_execution"] = w.get("command_execution", 7) + 1
    elif lang in ("javascript", "typescript"):
        w["prototype_pollution"] = w.get("prototype_pollution", 2) + 5
        w["nosql_injection"] = w.get("nosql_injection", 3) + 4
        w["ssrf"] = w.get("ssrf", 4) + 2
        w["template_injection"] = w.get("template_injection", 5) + 2
    elif lang == "java":
        w["deserialization"] = w.get("deserialization", 5) + 5
        w["spel_injection"] = w.get("spel_injection", 4) + 5
        w["sql_injection"] = w.get("sql_injection", 6) + 2
    elif lang == "c#":
        w["deserialization"] = w.get("deserialization", 5) + 3
        w["command_execution"] = w.get("command_execution", 7) + 2
    elif lang == "go":
        w["race_condition"] = w.get("race_condition", 2) + 4
        w["command_execution"] = w.get("command_execution", 7) + 2
    elif lang == "rust":
        w["unsafe_block"] = w.get("unsafe_block", 3) + 5
        w["ffi"] = w.get("ffi", 1) + 4
        w["integer_overflow"] = w.get("integer_overflow", 2) + 3

    if "django" in fw_text:
        w["sql_injection"] = w.get("sql_injection", 6) + 2
        w["template_injection"] = w.get("template_injection", 5) + 1
    if "flask" in fw_text or "fastapi" in fw_text:
        w["template_injection"] = w.get("template_injection", 5) + 2
        w["ssrf"] = w.get("ssrf", 4) + 1
    if "spring" in fw_text:
        w["spel_injection"] = w.get("spel_injection", 4) + 5
        w["deserialization"] = w.get("deserialization", 5) + 3
    if "express" in fw_text:
        w["nosql_injection"] = w.get("nosql_injection", 3) + 3
        w["command_execution"] = w.get("command_execution", 7) + 1
    if "rails" in fw_text:
        w["deserialization"] = w.get("deserialization", 5) + 4
        w["sql_injection"] = w.get("sql_injection", 6) + 1
    if "ruby" in fw_text or lang == "ruby":
        w["deserialization"] = w.get("deserialization", 5) + 3

    return w


def _dedup_and_rank_by_sink(
    paths: list[ExploitPath],
    class_weights: dict[str, int] | None = None,
) -> list[ExploitPath]:
    """Deduplicate by unique sink (file, line, category). Keep highest-weighted path per sink."""
    weights = class_weights or _VULN_CLASS_WEIGHT
    sink_map: dict[tuple, ExploitPath] = {}
    for p in paths:
        key = (p.sink.file, p.sink.line, p.sink.category)
        if key not in sink_map:
            sink_map[key] = p
        else:
            existing_w = weights.get(sink_map[key].sink.category, 1)
            new_w = weights.get(p.sink.category, 1)
            if new_w > existing_w:
                sink_map[key] = p
    ranked = sorted(
        sink_map.values(),
        key=lambda p: (
            _SEVERITY_RANK.get(p.sink.severity.upper(), 3),
            -weights.get(p.sink.category, 1),
            not p.is_blocked_by_sanitizer,
        ),
    )
    return ranked


def _smart_prioritize_paths(
    llm_candidates: list[ExploitPath],
    low_priority: list[ExploitPath],
    ceiling: int,
    class_weights: dict[str, int] | None = None,
) -> tuple[list[ExploitPath], dict[str, int]]:
    """
    Smart prioritization that guarantees zero missed CRITICAL/HIGH vulns
    and ensures coverage of all unique sink categories in the codebase.

    Strategy:
    1. ALL real function chain paths (llm_candidates) — always included
    2. ALL CRITICAL severity from low_priority — always included
    3. ALL HIGH severity from low_priority — always included
    4. At least 1 path per unique sink category NOT covered by tiers 1-3
    5. MEDIUM — dedup by sink, rank by vuln class, fill remaining budget
    6. LOW — only if budget remains after all above
    """
    weights = class_weights or _VULN_CLASS_WEIGHT

    if not low_priority:
        stats = {
            "total_candidates": len(llm_candidates),
            "selected": len(llm_candidates),
            "skipped": 0,
            "real_chains": len(llm_candidates),
            "critical": 0, "high": 0,
            "medium_total": 0, "medium_selected": 0,
            "low_total": 0, "low_selected": 0,
            "coverage_extra": 0,
        }
        return list(llm_candidates), stats

    critical, high, medium, low = [], [], [], []
    for p in low_priority:
        sev = p.sink.severity.upper()
        if sev == "CRITICAL":
            critical.append(p)
        elif sev == "HIGH":
            high.append(p)
        elif sev == "MEDIUM":
            medium.append(p)
        else:
            low.append(p)

    selected = list(llm_candidates)
    selected.extend(critical)
    selected.extend(high)

    categories_covered = {p.sink.category for p in selected}

    coverage_extra = 0
    all_skipped = medium + low
    uncovered_cats = set()
    if ceiling > 0:
        uncovered_cats = {p.sink.category for p in all_skipped} - categories_covered
        if uncovered_cats:
            for cat in sorted(uncovered_cats):
                if len(selected) >= ceiling:
                    break
                for p in all_skipped:
                    if p.sink.category == cat and p not in selected:
                        selected.append(p)
                        coverage_extra += 1
                        break

    budget = ceiling - len(selected)

    medium_selected = 0
    if budget > 0 and medium:
        ranked = _dedup_and_rank_by_sink(medium, class_weights=weights)
        take = [p for p in ranked if p not in selected][:budget]
        selected.extend(take)
        medium_selected = len(take)

    budget = ceiling - len(selected)

    low_selected = 0
    if budget > 0 and low:
        ranked = _dedup_and_rank_by_sink(low, class_weights=weights)
        take = [p for p in ranked if p not in selected][:budget]
        selected.extend(take)
        low_selected = len(take)

    stats = {
        "total_candidates": len(llm_candidates) + len(low_priority),
        "selected": len(selected),
        "skipped": len(llm_candidates) + len(low_priority) - len(selected),
        "real_chains": len(llm_candidates),
        "critical": len(critical),
        "high": len(high),
        "medium_total": len(medium),
        "medium_selected": medium_selected,
        "low_total": len(low),
        "low_selected": low_selected,
        "coverage_extra": coverage_extra,
    }

    return selected, stats


def _compute_adaptive_cap(path_count: int, unique_cats: int, config_limit: int = 2000) -> int:
    """Compute an adaptive cap based on path count and sink category diversity.
    Returns 0 for small repos (no cap needed). Scales with category diversity.
    Config limit acts as minimum, never reduced below it."""
    if path_count < 5000:
        return 0
    if path_count < 10000:
        return max(config_limit, unique_cats * 25)
    if path_count < 30000:
        return max(config_limit, unique_cats * 30)
    return max(config_limit, min(unique_cats * 40, path_count // 8))


def analyze_paths_with_llm(
    paths: list[ExploitPath],
    repo_path: Path,
    max_paths: int = 0,
    temperature: float = 0.3,
    cve_catalog: dict | None = None,
    completed_ids: set[str] | None = None,
    checkpoint_dir: Path | None = None,
    classification: dict | None = None,
) -> list[PathAnalysisResult]:
    logger.info(f"Analyzing {len(paths)} enumerated paths")

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

    llm_candidates = [p for p in llm_candidates
                      if p.path_id not in completed_ids] if completed_ids else llm_candidates
    low_priority = [p for p in low_priority
                    if p.path_id not in completed_ids] if completed_ids else low_priority

    if completed_ids:
        skipped = len(all_llm) - len(llm_candidates) - len(low_priority)
        if skipped:
            logger.info(f"  Checkpoint resume: skipping {skipped} already-analyzed paths")

    total_need_llm = len(llm_candidates) + len(low_priority)
    unique_cats = len({p.sink.category for p in (llm_candidates + low_priority)})

    key_signals = (classification or {}).get("key_signals", {})
    language = key_signals.get("language", "")
    frameworks = key_signals.get("frameworks", [])
    class_weights = _get_context_weights(language, frameworks)

    logger.info(f"  Dedup: {len(paths)} raw → {len(seen_combos)} unique "
                f"(+{len(deterministic_results)} structurally invalid, "
                f"{len(llm_candidates)} direct, {len(low_priority)} module-level)")

    if language or frameworks:
        logger.info(f"  Context: lang={language} frameworks={frameworks} "
                    f"unique_sink_types={unique_cats}")

    workers = config.get("pipeline.parallel_analyzers", 4) or 4
    sec_per_path = 15.0 / max(workers, 1)

    smart_limit = config.get("pipeline.smart_limit_max", 2000)
    if max_paths == 0:
        adaptive = _compute_adaptive_cap(total_need_llm, unique_cats, config_limit=smart_limit)
        ceiling = adaptive if adaptive > 0 else smart_limit
    else:
        ceiling = max_paths

    if ceiling > 0 and total_need_llm > ceiling:
        all_llm, pstats = _smart_prioritize_paths(
            llm_candidates, low_priority, ceiling, class_weights=class_weights,
        )
        total_est = int(total_need_llm * sec_per_path / 60)
        smart_est = int(pstats["selected"] * sec_per_path / 60)
        coverage_info = f" coverage:+{pstats['coverage_extra']}" if pstats.get("coverage_extra") else ""

        logger.warning(
            f"  SMART LIMIT ({ceiling}): {pstats['total_candidates']} candidates → "
            f"{pstats['selected']} selected{coverage_info} "
            f"(real:{pstats['real_chains']} crit:{pstats['critical']} "
            f"high:{pstats['high']} med:{pstats['medium_selected']}/{pstats['medium_total']} "
            f"low:{pstats['low_selected']}/{pstats['low_total']}) — "
            f"{pstats['skipped']} skipped"
        )
        logger.warning(
            f"  Est LLM time ({workers} workers): unlimited ~{total_est}m | "
            f"smart ~{smart_est}m. "
            f"Config: smart_limit_max={smart_limit} max_llm_paths={max_paths}"
        )
    else:
        all_llm = llm_candidates + low_priority

    function_sources = _load_function_sources(all_llm, repo_path)

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

    client = LLMClient()
    use_concurrent = config.get("pipeline.parallel_analyzers", 0) > 0

    if use_concurrent and len(all_llm) > 10:
        concurrency = min(config.get("pipeline.parallel_analyzers", 4), 16)
        logger.info(f"  Using concurrent LLM analysis with {concurrency} workers")
        llm_results = _analyze_paths_concurrent(
            all_llm, system, function_sources, cve_catalog, temperature, client, concurrency,
            checkpoint_dir=checkpoint_dir,
        )
    else:
        llm_results = _analyze_paths_sequential(
            all_llm, system, function_sources, cve_catalog, temperature, client,
            checkpoint_dir=checkpoint_dir,
        )

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


def _analyze_paths_sequential(
    paths: list[ExploitPath],
    system: str,
    function_sources: dict[str, str],
    cve_catalog: dict | None,
    temperature: float,
    client: LLMClient,
    checkpoint_dir: Path | None = None,
) -> list[PathAnalysisResult]:
    llm_results: list[PathAnalysisResult] = []
    for i, path in enumerate(paths):
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

        if verdict == "uncertain" or confidence < 0.3:
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

        path_result = _make_path_result(
            path, verdict,
            confidence,
            result_dict.get("reasoning", ""),
            result_dict.get("exploit_scenario", ""),
            result_dict.get("severity", path.sink.severity),
            result_dict.get("poc_idea", ""),
            "llm",
        )
        llm_results.append(path_result)

        if checkpoint_dir:
            try:
                _append_checkpoint(checkpoint_dir, path_result)
            except Exception:
                pass

        if (i + 1) % 50 == 0:
            logger.info(f"  LLM analyzed {i + 1}/{len(paths)} paths")

    return llm_results


def _analyze_paths_concurrent(
    paths: list[ExploitPath],
    system: str,
    function_sources: dict[str, str],
    cve_catalog: dict | None,
    temperature: float,
    client: LLMClient,
    concurrency: int = 4,
    checkpoint_dir: Path | None = None,
) -> list[PathAnalysisResult]:
    import concurrent.futures

    def _analyze_one(path: ExploitPath) -> PathAnalysisResult:
        if not path.is_exploitable:
            return _make_path_result(
                path, "BLOCKED", 0.95,
                "Not exploitable.", "", path.sink.severity, "", "auto",
            )

        prompt = _build_path_prompt(path, function_sources, cve_catalog)
        c = LLMClient()

        try:
            result = c.chat_json(system, prompt, temperature=temperature, max_tokens=2048)
        except Exception:
            result = None

        if not result:
            return _make_path_result(
                path, "uncertain", 0.3,
                "LLM call failed.", "", path.sink.severity, "", "llm",
            )

        result_dict = result if isinstance(result, dict) else {}
        verdict = result_dict.get("verdict", "uncertain")
        confidence = float(result_dict.get("confidence", 0.5))

        if verdict == "exploitable":
            verdict = "VERIFIED_EXPLOITABLE"
        elif verdict == "blocked":
            verdict = "BLOCKED"

        if verdict == "uncertain" or confidence < 0.3:
            try:
                sc_result = c.self_consistent(system, prompt, runs=3, temperature=0.4)
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

        return _make_path_result(
            path, verdict, confidence,
            result_dict.get("reasoning", ""),
            result_dict.get("exploit_scenario", ""),
            result_dict.get("severity", path.sink.severity),
            result_dict.get("poc_idea", ""),
            "llm",
        )

    llm_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(_analyze_one, p): i for i, p in enumerate(paths)}
        for future in concurrent.futures.as_completed(futures):
            try:
                path_result = future.result()
                llm_results.append(path_result)
                if checkpoint_dir:
                    try:
                        _append_checkpoint(checkpoint_dir, path_result)
                    except Exception:
                        pass
            except Exception as e:
                idx = futures[future]
                err_result = _make_path_result(
                    paths[idx], "uncertain", 0.3,
                    f"Thread error: {e}", "", paths[idx].sink.severity, "", "llm",
                )
                llm_results.append(err_result)
                if checkpoint_dir:
                    try:
                        _append_checkpoint(checkpoint_dir, err_result)
                    except Exception:
                        pass

    logger.info(f"  Concurrent LLM analysis: {len(paths)} paths with {concurrency} workers")
    return llm_results


def analyze_paths(
    call_graph: CallGraph,
    sources: list[SourceTag],
    sinks: list[SinkTag],
    sanitizers: list[SanitizerTag],
    file_analyses: list,
    repo_path: Path,
    max_paths: int = 500,
    completed_ids: set[str] | None = None,
    checkpoint_dir: Path | None = None,
) -> list[PathAnalysisResult]:
    enumerator = PathEnumerator()
    paths = enumerator.enumerate_all_paths(call_graph, sources, sinks, sanitizers, file_analyses)
    return analyze_paths_with_llm(paths, repo_path, max_paths=max_paths,
                                  completed_ids=completed_ids, checkpoint_dir=checkpoint_dir)
