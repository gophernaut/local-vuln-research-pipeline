"""Step 5: Hypothesis generation — LLM generates exploit hypotheses from code analysis.

Works for ALL target types — web apps, kernel, CLI, native, PowerShell, etc.
Taint flows from static analysis provide signal boost but are NOT a gate.
For non-web targets (taint flows = 0), LLM analyzes code directly from file inventory.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.llm.client import LLMClient
from src.llm.prompts import hypothesis_system, GUARD_PREAMBLE
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
    sinks = static_analysis.get("_sink_matches", [])
    semgrep_hits = static_analysis.get("semgrep_findings", [])
    file_inventory = static_analysis.get("file_inventory", {})
    summary = static_analysis.get("summary", {})

    hypothesis_system_prompt = _build_system_prompt(classification, cve_context)

    user_prompt = _build_user_prompt(
        classification, summary, taint_flows, sinks, semgrep_hits, file_inventory
    )

    code_samples = _collect_code_samples(repo_path, taint_flows, sinks, file_inventory)

    client = LLMClient()
    ctx = ContextManager()
    alloc = ctx.allocate(hypothesis_system_prompt, code_files=code_samples)

    full_prompt = (
        f"{alloc['code']}\n\n"
        f"=== Repository Analysis ===\n\n{user_prompt}"
    )

    threshold = config.get("thresholds.hypothesis_confidence_cutoff", 0.6)

    try:
        result = client.chat_json(hypothesis_system_prompt, full_prompt, max_tokens=3072)
        hypotheses = result.get("hypotheses", []) if result else []
    except Exception as e:
        logger.warning(f"  LLM hypothesis gen failed: {e}")
        hypotheses = []

    if not hypotheses:
        logger.info("  No hypotheses generated. Target may be secure or LLM unable to parse code.")
        return []

    if any(h.get("confidence", 0) <= 0.7 for h in hypotheses):
        logger.info(f"  Self-consistency: {config.get('pipeline.self_consistency_runs', 3)} runs...")
        consistent = client.self_consistent(
            hypothesis_system_prompt, full_prompt,
            runs=config.get("pipeline.self_consistency_runs", 3),
            temperature=0.3,
        )
        if consistent:
            hypotheses = consistent.get("hypotheses", [])
            logger.info(f"  {len(hypotheses)} hypotheses after self-consistency")

    ranked = sorted(
        hypotheses,
        key=lambda h: h.get("priority_score", h.get("confidence", 0)),
        reverse=True,
    )

    top = ranked[:max_hypotheses]
    logger.info(f"  {len(top)} hypotheses (from {len(ranked)} total)")

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
        for h in top
    ]


def _build_system_prompt(
    classification: dict[str, Any],
    cve_context: list[dict[str, Any]],
) -> str:
    primary = classification.get("primary_class", "web_app")
    refs = classification.get("loaded_refs", [])

    methodology = f"Target class: {primary}. References: {', '.join(refs)}."

    cve_text = "No known CVE patterns available."
    if cve_context:
        lines = []
        for cve in cve_context[:15]:
            kev = " [CISA KEV — actively exploited]" if cve.get("kev_member") else ""
            lines.append(
                f"- {cve.get('cve_id')}: {cve.get('description', '')[:200]} "
                f"(CVSS: {cve.get('cvss_score')}, EPSS: {cve.get('epss_score') or 0:.4f}){kev}"
            )
        cve_text = "\n".join(lines)

    return f"""{GUARD_PREAMBLE}

You are an elite whitebox vulnerability researcher. Your goal: find 1-3 real,
HIGH/CRITICAL, unconditionally exploitable vulnerabilities in this codebase.
You analyze ANY type of target — web apps, kernels, CLI tools, native code,
PowerShell modules, container runtimes, compilers, embedded systems — everything.

ZERO AI SLOP:
- NO DoS, ReDoS, resource exhaustion
- NO theoretical missing checks, security headers
- NO findings requiring attacker to already have system access
- NO findings where precondition grants more power than exploit
- ONLY report concrete, exploitable, traceable vulnerabilities

{methodology}

CVE PATTERNS (most relevant known exploits for this technology):
{cve_text}

Output valid JSON:
{{"hypotheses": [
  {{"vulnerability_class": "e.g. UAF in packet parser, SSRF via webhook, CLI argument injection",
    "component": "affected file/function",
    "entry_point": "how attacker reaches this (syscall, HTTP endpoint, CLI arg, IPC msg, file parse)",
    "entry_point_type": "SYSCALL | HTTP_POST | CLI_ARG | FILE_PARSE | IPC | NETWORK | ENV_VAR | PLUGIN_API",
    "sink": "dangerous operation and file:line",
    "preconditions": ["condition 1", "condition 2"],
    "expected_impact": "concrete impact — RCE, LPE, info leak, auth bypass, code exec",
    "confidence": 0.0-1.0,
    "priority_score": 0.0-1.0,
    "cwe_id": "CWE-XXXX",
    "requires_authentication": true/false
  }}
]}}
"""


def _build_user_prompt(
    classification: dict[str, Any],
    summary: dict[str, Any],
    taint_flows: list[dict],
    sinks: list[dict],
    semgrep_hits: list[dict],
    file_inventory: dict[str, Any],
) -> str:
    primary = classification.get("primary_class", "web_app")
    display = classification.get("display_name", primary)

    lines = [
        f"Target Classification: {display} ({primary})",
        f"Files scanned: {summary.get('files_scanned', 0)}",
        f"Languages: {json.dumps(file_inventory.get('languages', {}))}",
        f"Semgrep hits: {summary.get('semgrep_hits', 0)}",
        f"Sinks detected: {summary.get('sinks_found', 0)}",
        f"Taint flows: {summary.get('taint_flows', 0)}",
        f"High-confidence flows: {summary.get('high_conf_flows', 0)}",
    ]

    if taint_flows:
        lines.append(f"\nHigh-confidence taint flows:")
        for f in taint_flows[:10]:
            if f.get("confidence", 0) >= 0.3:
                lines.append(
                    f"  {f.get('source_type', '?')} @ {f.get('source_file', '?')}:{f.get('source_line', '?')} "
                    f"-> {f.get('sink_type', '?')} @ {f.get('sink_file', '?')}:{f.get('sink_line', '?')} "
                    f"[{f.get('confidence', 0):.2f}]"
                )
    else:
        lines.append("\nNo taint flows detected by static analysis.")
        lines.append("Analyze the code samples directly to identify potential vulnerabilities.")

    if semgrep_hits:
        lines.append(f"\nSemgrep findings:")
        seen: set[str] = set()
        for hit in semgrep_hits[:20]:
            key = f"{hit['file']}:{hit['line']}"
            if key not in seen:
                seen.add(key)
                lines.append(f"  {hit['rule_id']} @ {hit['file']}:{hit['line']} [{hit.get('severity', '?')}]")

    lines.append(
        f"\nGenerate {config.max_hypotheses} highest-priority exploit hypotheses. "
        f"Analyze the provided code samples. Look for: memory safety bugs, injection, "
        f"auth bypass, deserialization, path traversal, command injection, race conditions, "
        f"privilege escalation. Consider the specific threat model for {primary} targets."
    )

    return "\n".join(lines)


def _collect_code_samples(
    repo_path: Path,
    taint_flows: list[dict],
    sinks: list[dict],
    file_inventory: dict[str, Any],
) -> dict[str, str]:
    code_files: dict[str, str] = {}
    candidates: set[Path] = set()
    priority: list[tuple[int, Path]] = []

    # Priority 0: entry point files (highest priority)
    entry_files = _find_entry_files(repo_path, file_inventory)
    for fp in entry_files:
        priority.append((0, fp))

    # Priority 1: files with sinks
    for s in sinks[:30]:
        fp = repo_path / s["file"]
        if fp not in {p for _, p in priority}:
            priority.append((1, fp))

    # Priority 2: files in taint flows
    for f in taint_flows:
        sf, df = f.get("source_file", ""), f.get("sink_file", "")
        for p in [sf, df]:
            if p:
                fp = repo_path / p
                if fp not in {p for _, p in priority}:
                    priority.append((2, fp))

    # Priority 3: sample files from inventory (sorted by size, largest first — likely important)
    samples = file_inventory.get("sample_files", [])
    samples.sort(key=lambda s: -s.get("size", 0))
    for s in samples[:40]:
        fp = repo_path / s["path"]
        if fp not in {p for _, p in priority}:
            priority.append((3, fp))

    priority.sort(key=lambda x: x[0])

    total_chars = 0
    max_chars = 100000
    for _, fp in priority:
        if total_chars >= max_chars:
            break
        if not fp.exists():
            continue
        try:
            content = fp.read_text(errors="replace")
            if len(content) > 15000:
                content = content[:15000] + "\n// ... [truncated]"
            code_files[str(fp.relative_to(repo_path))] = content
            total_chars += len(content)
        except Exception:
            continue

    return code_files


def _find_entry_files(repo_path: Path, file_inventory: dict) -> list[Path]:
    entry_patterns = [
        "**/main.c", "**/main.cpp", "**/main.go", "**/main.rs",
        "**/Program.cs", "**/Program.java", "**/app.py", "**/index.js",
        "**/server.js", "**/manage.py", "**/main.ps1",
        "**/__init__.py", "**/setup.py",
    ]
    files = set()
    for pat in entry_patterns:
        for fp in repo_path.glob(pat):
            if fp.is_file() and fp.stat().st_size > 100:
                files.add(fp)
                if len(files) >= 10:
                    return list(files)
    return list(files)
