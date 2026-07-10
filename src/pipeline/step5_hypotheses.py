"""Step 5: LLM-driven vulnerability hunting.

The LLM is the PRIMARY analysis engine. It receives:
1. CVE exploit pattern catalog (organized by class, with search guidance)
2. Complete codebase structure overview (directory tree, languages, entry points)
3. Initial code samples from entry points and relevant areas

The LLM drives the hunt:
- Strategically selects what to inspect
- Requests files/directories it needs (via iterative deep trace in Step 6)
- Generates hypotheses by REASONING about code, not matching regex

This is NOT a static analyzer. The LLM thinks like an exploit researcher.
"""
from __future__ import annotations

import json
import os
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
    cve_catalog: dict[str, Any],
) -> list[dict[str, Any]]:
    logger.info("Step 5: LLM-driven vulnerability hunting...")

    max_hypotheses = config.max_hypotheses
    catalog_text = cve_catalog.get("catalog_text", "")
    attack_hints = cve_catalog.get("attack_surface_hints", [])
    target_keywords = cve_catalog.get("target_type_keywords", [])
    file_inventory = static_analysis.get("file_inventory", {})
    sinks = static_analysis.get("_sink_matches", [])
    taint_flows = static_analysis.get("_taint_flows", [])
    semgrep_hits = static_analysis.get("semgrep_findings", [])

    primary = classification.get("primary_class", "general_application")
    display = classification.get("display_name", primary)

    codebase_overview = _build_codebase_overview(repo_path, file_inventory, sinks, taint_flows)
    initial_code = _collect_strategic_samples(repo_path, file_inventory, sinks, primary)

    system_prompt = _build_system_prompt(display, primary, catalog_text, attack_hints)

    user_prompt = (
        f"=== CODEBASE OVERVIEW ===\n\n{codebase_overview}\n\n"
        f"=== STATIC ANALYSIS SIGNALS ===\n"
        f"Semgrep hits: {len(semgrep_hits)} | Sinks detected: {len(sinks)} | Taint flows: {len(taint_flows)}\n\n"
        f"=== INITIAL CODE SAMPLES ===\n"
        f"(Entry points and high-priority files — request more via 'files_to_inspect' in your output)\n\n"
    )

    client = LLMClient()
    ctx = ContextManager()
    alloc = ctx.allocate(system_prompt, code_files=initial_code)

    full_prompt = f"{user_prompt}{alloc['code']}"

    try:
        result = client.chat_json(system_prompt, full_prompt, max_tokens=4096)
        hypotheses = result.get("hypotheses", []) if result else []
    except Exception as e:
        logger.warning(f"  LLM hunting failed: {e}")
        hypotheses = []

    if not hypotheses:
        logger.info("  No hypotheses generated after thorough code review.")
        return []

    # Self-consistency for borderline findings
    if any(h.get("confidence", 0) <= 0.7 for h in hypotheses):
        logger.info(f"  Self-consistency: {config.get('pipeline.self_consistency_runs', 3)} runs...")
        consistent = client.self_consistent(
            system_prompt, full_prompt,
            runs=config.get("pipeline.self_consistency_runs", 3),
            temperature=0.3,
        )
        if consistent:
            hypotheses = consistent.get("hypotheses", [])
            logger.info(f"  {len(hypotheses)} hypotheses after self-consistency")

    ranked = sorted(hypotheses, key=lambda h: h.get("priority_score", h.get("confidence", 0)), reverse=True)
    top = ranked[:max_hypotheses]
    logger.info(f"  {len(top)} hypotheses generated ({len(ranked)} total)")

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


def _build_codebase_overview(
    repo_path: Path,
    file_inventory: dict,
    sinks: list[dict],
    taint_flows: list[dict],
) -> str:
    lines = []
    lines.append(f"Repository: {repo_path}")
    lines.append(f"Files: {file_inventory.get('total_files', 0)}")

    langs = file_inventory.get("languages", {})
    lines.append(f"Languages: {json.dumps(dict(list(langs.items())[:10]))}")

    lines.append(f"\nTop-level directory structure:")
    try:
        for item in sorted(repo_path.iterdir()):
            if item.is_dir() and not item.name.startswith("."):
                count = sum(1 for _ in item.rglob("*") if _.is_file())
                lines.append(f"  {item.name}/ ({count} files)")
    except Exception:
        pass

    if sinks:
        by_lang: dict[str, int] = {}
        for s in sinks:
            lang = _ext_from_path(s["file"])
            by_lang[lang] = by_lang.get(lang, 0) + 1
        lines.append(f"\nSinks by language: {json.dumps(by_lang)}")

        hot_files: dict[str, int] = {}
        for s in sinks:
            hot_files[s["file"]] = hot_files.get(s["file"], 0) + 1
        top_hot = sorted(hot_files.items(), key=lambda x: -x[1])[:10]
        lines.append(f"\nHottest files (most sinks):")
        for f, c in top_hot:
            lines.append(f"  {f} ({c} sinks)")

    if taint_flows:
        lines.append(f"\nTaint flows found: {len(taint_flows)}")
        high_conf = [f for f in taint_flows if f.get("confidence", 0) >= 0.5]
        if high_conf:
            lines.append(f"High-confidence flows: {len(high_conf)}")
            for f in high_conf[:5]:
                lines.append(
                    f"  {f.get('source_type')} @ {f.get('source_file')}:{f.get('source_line')} "
                    f"-> {f.get('sink_type')} [{f.get('confidence', 0):.2f}]"
                )

    return "\n".join(lines)


def _collect_strategic_samples(
    repo_path: Path,
    file_inventory: dict,
    sinks: list[dict],
    primary: str,
) -> dict[str, str]:
    code_files: dict[str, str] = {}
    candidates: list[tuple[int, Path]] = []

    # Priority 0: main entry files
    entry_patterns = {
        "kernel": ["**/main.c", "**/init/main.c", "**/kernel/*.c"],
        "powershell": ["**/*.ps1", "**/*.psm1", "**/Program.cs"],
        "dotnet": ["**/Program.cs", "**/*Controller.cs", "**/*Service.cs"],
        "ide_editor": ["**/main.js", "**/main.ts", "**/server.js", "**/electron.js",
                        "**/extension*.js", "**/extension*.ts"],
        "compiler": ["**/main.c", "**/main.cpp", "**/main.rs", "**/driver.cpp"],
        "ai_ml": ["**/*.py", "**/core/**/*.cc", "**/ops/**/*.cc"],
        "web_app": ["**/app.py", "**/server.js", "**/index.js", "**/views.py",
                     "**/routes.py", "**/controllers/*.py"],
        "cli_tool": ["**/main.c", "**/main.rs", "**/cli.py", "**/app.go"],
        "native_memory": ["**/main.c", "**/main.cpp", "**/*.c", "**/src/*.c"],
        "container": ["**/main.go", "**/daemon/*.go", "**/runtime/*.go"],
    }

    patterns = entry_patterns.get(primary, ["**/main.*", "**/*.py", "**/*.js", "**/*.go"])

    for pat in patterns:
        for fp in repo_path.glob(pat):
            if fp.is_file() and fp.stat().st_size > 50:
                candidates.append((0, fp))
                if len(candidates) >= 15:
                    break

    # Priority 1: hot files (most sinks)
    sink_count: dict[str, int] = {}
    for s in sinks:
        sink_count[s["file"]] = sink_count.get(s["file"], 0) + 1
    for fname in sorted(sink_count, key=lambda x: -sink_count[x])[:15]:
        fp = repo_path / fname
        if fp.exists() and fp not in {p for _, p in candidates}:
            candidates.append((1, fp))

    # Priority 2: sample files by size (large files likely important)
    samples = file_inventory.get("all_files", file_inventory.get("sample_files", []))
    samples.sort(key=lambda s: -s.get("size", 0))
    for s in samples[:20]:
        fp = repo_path / s["path"]
        if fp.exists() and fp not in {p for _, p in candidates}:
            candidates.append((2, fp))

    candidates.sort(key=lambda x: x[0])

    total = 0
    for _, fp in candidates:
        if total > 120000:
            break
        try:
            content = fp.read_text(errors="replace")
            if len(content) > 10000:
                content = content[:10000] + "\n// ... [truncated]"
            code_files[str(fp.relative_to(repo_path))] = content
            total += len(content)
        except Exception:
            continue

    return code_files


def _build_system_prompt(display: str, primary: str, catalog_text: str, attack_hints: list[str]) -> str:
    hints_text = "\n".join(f"- {h}" for h in attack_hints)

    return f"""{GUARD_PREAMBLE}

You are an ELITE vulnerability researcher performing a whitebox code audit.
Target: {display} ({primary})

YOUR MISSION:
Find 1-3 real, HIGH/CRITICAL, unconditionally exploitable vulnerabilities.
Do NOT report DoS, informational, or theoretical issues.
Every finding must cite exact file:line from the provided code.

ATTACK SURFACE (focus on these):
{hints_text}

HOW TO HUNT:
1. Study the CVE catalog below — these are REAL exploits found in similar targets
2. For each exploit class, search the provided code for ANALOGOUS patterns
3. Look at entry points. Trace how untrusted input flows through the code.
4. Check ALL mitigations: input validation, sanitization, bounds checking, auth checks
5. If you need to see files NOT provided, list them in 'files_to_inspect'
6. Generate hypotheses ONLY if you can point to specific vulnerable code paths

{catalog_text}

OUTPUT FORMAT (valid JSON):
{{"hypotheses": [
  {{"vulnerability_class": "e.g. UAF in D3D driver ioctl handler",
    "component": "src/foo/bar.c:42 — function_name",
    "entry_point": "how attacker reaches this code",
    "entry_point_type": "SYSCALL|IOCTL|HTTP_POST|CLI_ARG|PS_PARAM|FILE_PARSE|IPC|PLUGIN_API|FFI|NETWORK",
    "sink": "dangerous operation and file:line reference",
    "preconditions": ["what must be true for exploit to work"],
    "expected_impact": "RCE|LPE|info leak|auth bypass|code exec — be specific",
    "confidence": 0.0-1.0,
    "priority_score": 0.0-1.0,
    "cwe_id": "CWE-XXXX",
    "requires_authentication": true/false,
    "files_to_inspect": ["optional: files you want loaded for deep trace"]
  }}
],
"files_to_inspect": ["optional: additional files the LLM wants for next iteration"]}}
"""


def _ext_from_path(path: str) -> str:
    _, ext = os.path.splitext(path)
    return ext or "unknown"
