"""Step 5: Hypothesis generation — LLM generates ranked exploit hypotheses.

Each hypothesis: vulnerability class, entry point, sink, preconditions, confidence.
Self-consistency applied for hypotheses with confidence <= 0.7.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.llm.client import LLMClient
from src.llm.prompts import hypothesis_system
from src.llm.context import ContextManager
from src.config import config
from src.utils.logger import get_logger

logger = get_logger()


def run(
    repo_path: Path,
    classification: dict[str, Any],
    static_analysis: dict[str, Any],
    cve_context: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    logger.info("Step 5: Generating exploit hypotheses (LLM)...")

    max_hypotheses = config.max_hypotheses

    taint_flows = static_analysis.get("_taint_flows", [])
    if not taint_flows:
        logger.info("  No taint flows to base hypotheses on. Skipping.")
        return []

    high_conf_flows = [f for f in taint_flows if f.get("confidence", 0) >= 0.3]
    if not high_conf_flows:
        high_conf_flows = taint_flows[:10]

    methodology_ref = _load_methodology_refs(classification)
    relevant_cwes = list(set(f.get("cwe", "") for f in high_conf_flows if f.get("cwe")))

    cve_text = _format_cve_context(cve_context)

    system = hypothesis_system(methodology_ref, cve_text, relevant_cwes)

    user = _build_user_prompt(classification, static_analysis, high_conf_flows)

    client = LLMClient()
    ctx = ContextManager()

    code_files = _collect_relevant_files(repo_path, high_conf_flows)
    alloc = ctx.allocate(system, cve_context="", code_files=code_files)

    full_user = f"{alloc['code']}\n\n{user}"

    threshold = config.get("thresholds.hypothesis_confidence_cutoff", 0.6)

    try:
        result = client.chat_json(system, full_user, max_tokens=3072)
        if result:
            hypotheses = result.get("hypotheses", [])
        else:
            hypotheses = []
    except Exception as e:
        logger.warning(f"  LLM hypothesis gen failed: {e}")
        return []

    if threshold >= 0.5 and any(
        h.get("confidence", 0) <= 0.7 for h in hypotheses
    ):
        logger.info(f"  Applying self-consistency check ({config.get('pipeline.self_consistency_runs', 3)} runs)...")
        consistent = client.self_consistent(
            system, full_user,
            runs=config.get("pipeline.self_consistency_runs", 3),
            temperature=0.3,
        )
        if consistent:
            hypotheses = consistent.get("hypotheses", [])
            logger.info(f"  Self-consistency passed: {len(hypotheses)} hypotheses")

    ranked = sorted(
        hypotheses,
        key=lambda h: h.get("priority_score", h.get("confidence", 0)),
        reverse=True,
    )

    top_hypotheses = ranked[:max_hypotheses]

    logger.info(f"  {len(top_hypotheses)} hypotheses generated (from {len(hypotheses)} total)")

    return [
        {
            "vulnerability_class": h.get("vulnerability_class", ""),
            "component": h.get("component", ""),
            "entry_point": h.get("entry_point", ""),
            "entry_point_type": h.get("entry_point_type", ""),
            "sink": h.get("sink", ""),
            "preconditions": h.get("preconditions", []),
            "expected_impact": h.get("expected_impact", ""),
            "confidence": h.get("confidence", 0),
            "priority_score": h.get("priority_score", 0),
            "cwe_id": h.get("cwe_id", ""),
            "requires_authentication": h.get("requires_authentication", False),
        }
        for h in top_hypotheses
    ]


def _load_methodology_refs(classification: dict[str, Any]) -> str:
    refs = classification.get("loaded_refs", [])
    primary = classification.get("primary_class", "web_app")

    ref_text = f"Primary methodlogy: {primary} vulnerability research.\n"
    if refs:
        ref_text += f"Loaded references: {', '.join(refs)}\n"
    return ref_text


def _format_cve_context(cve_context: list[dict[str, Any]]) -> str:
    if not cve_context:
        return "No known CVE patterns available for this tech stack."

    lines = []
    for cve in cve_context[:15]:
        kev = " [CISA KEV - actively exploited!]" if cve.get("kev_member") else ""
        epss = cve.get("epss_score", 0) or 0
        lines.append(
            f"- {cve.get('cve_id')}: {cve.get('description', '')[:200]}"
            f" (CVSS: {cve.get('cvss_score')}, EPSS: {epss:.4f}, CWE: {cve.get('cwe_ids')}){kev}"
        )
    return "\n".join(lines)


def _build_user_prompt(
    classification: dict[str, Any],
    static_analysis: dict[str, Any],
    high_conf_flows: list[dict],
) -> str:
    summary = static_analysis.get("summary", {})
    entry_points_desc = _describe_entry_points(high_conf_flows)
    sinks_desc = _describe_sinks(high_conf_flows)

    return (
        f"=== Static Analysis Results ===\n"
        f"Files analyzed: {summary.get('files_analyzed', 0)}\n"
        f"Semgrep hits: {summary.get('semgrep_hits', 0)}\n\n"
        f"=== Entry Points (attacker-controlled inputs) ===\n{entry_points_desc}\n\n"
        f"=== Dangerous Sinks ===\n{sinks_desc}\n\n"
        f"=== Target Classification ===\n"
        f"Class: {classification.get('display_name')}\n"
        f"Primary: {classification.get('primary_class')}\n\n"
        f"Generate ranked exploit hypotheses. Focus on HIGH/CRITICAL impact only."
        f"Limit to top {config.max_hypotheses} most exploitable."
    )


def _describe_entry_points(flows: list[dict]) -> str:
    seen: set[str] = set()
    lines = []
    for f in flows:
        key = f"{f.get('source_file')}:{f.get('source_line')}"
        if key not in seen:
            seen.add(key)
            lines.append(
                f"  {f.get('source_type', 'INPUT')} @ "
                f"{f.get('source_file', '?')}:{f.get('source_line', '?')}"
            )
    return "\n".join(lines) if lines else "  None identified"


def _describe_sinks(flows: list[dict]) -> str:
    seen: set[str] = set()
    lines = []
    for f in flows:
        key = f"{f.get('sink_file')}:{f.get('sink_line')}"
        if key not in seen:
            seen.add(key)
            lines.append(
                f"  {f.get('sink_type', 'SINK')} ({f.get('sink_category', '?')}) @ "
                f"{f.get('sink_file', '?')}:{f.get('sink_line', '?')} "
                f"[{f.get('cwe', 'N/A')}] confidence: {f.get('confidence', 0):.2f}"
            )
    return "\n".join(lines) if lines else "  None identified"


def _collect_relevant_files(repo_path: Path, flows: list[dict]) -> dict[str, str]:
    files = set()
    for f in flows:
        src = f.get("source_file", "")
        sink = f.get("sink_file", "")
        if src:
            files.add(repo_path / src)
        if sink:
            files.add(repo_path / sink)

    code_files: dict[str, str] = {}
    for f in list(files)[:20]:
        if f.exists():
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    code_files[str(f)] = fh.read()
            except Exception:
                continue
    return code_files
