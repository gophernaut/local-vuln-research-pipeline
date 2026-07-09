"""Step 4: Threat model bootstrap — one careful LLM pass to build the attack surface map.

Outputs a structured JSON that every subsequent fuzz pass consults:
- Entry point inventory (every externally reachable route, CLI arg, file parse, IPC handler)
- Trust boundaries (where data crosses privilege levels)
- Sink inventory (dangerous operations mapped to file:line)
- Data flow overview (how untrusted input moves through the system)
- Architecture overview (directory tree, language breakdown, hot files)

Also builds the CVE exploit pattern catalog for the LLM's hunting guidance.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from src.knowledge.cve_db import CVEDatabase
from src.llm.client import LLMClient
from src.llm.prompts import GUARD_PREAMBLE
from src.config import config
from src.utils.logger import get_logger

logger = get_logger()

EXPLOIT_CLASSES = {
    "command_injection": ["CWE-77", "CWE-78", "CWE-94", "CWE-95"],
    "memory_safety": ["CWE-119", "CWE-120", "CWE-122", "CWE-125", "CWE-416", "CWE-415", "CWE-476", "CWE-787", "CWE-190", "CWE-191"],
    "sql_injection": ["CWE-89", "CWE-943"],
    "deserialization": ["CWE-502", "CWE-913"],
    "ssrf": ["CWE-918", "CWE-441"],
    "auth_bypass": ["CWE-287", "CWE-288", "CWE-289", "CWE-306", "CWE-384", "CWE-613", "CWE-639", "CWE-862", "CWE-863"],
    "path_traversal": ["CWE-22", "CWE-23", "CWE-36", "CWE-73"],
    "xxe": ["CWE-611", "CWE-776"],
    "race_condition": ["CWE-362", "CWE-367"],
    "crypto": ["CWE-327", "CWE-328", "CWE-338", "CWE-347", "CWE-798", "CWE-312"],
    "privilege_escalation": ["CWE-250", "CWE-266", "CWE-269", "CWE-271", "CWE-274", "CWE-276"],
    "format_string": ["CWE-134"],
    "xss": ["CWE-79", "CWE-80"],
    "integer_overflow": ["CWE-190", "CWE-191", "CWE-680"],
}

THREAT_MODEL_PROMPT = """You are building a THREAT MODEL for a codebase audit. This is the foundation 
for all subsequent vulnerability hunting passes. Be thorough. Cite exact file:line references.

BUILD THIS STRUCTURED MAP:

1. ENTRY POINT INVENTORY
   For EVERY externally reachable entry point in this codebase, list:
   - File:line reference
   - Type: HTTP_ROUTE | CLI_ARG | FILE_PARSE | IPC | SYSCALL | IOCTL | PLUGIN_API | FFI | ENV_VAR
   - What data enters the system (query params, body, CLI args, file contents, etc.)
   - Authentication required? (none | user | admin | system)
   - Brief description of what it does

2. TRUST BOUNDARIES
   Every point where data crosses from lower privilege to higher privilege:
   - Untrusted network → application
   - User → admin/superuser functions
   - Plugin/extension → host process
   - Renderer → browser kernel
   - Tenant A → tenant B
   - Config file → code execution
   List file:line for each boundary crossing point.

3. SINK INVENTORY  
   Every dangerous operation found in the code. Group by category:
   - Command/shell execution
   - SQL/database queries
   - Deserialization points
   - File I/O (read, write, delete) with dynamic paths
   - Memory operations (malloc, free, unsafe casts) — native code only
   - HTTP clients (potential SSRF)
   - Template engines / dynamic code evaluation
   - Authentication/authorization checks
   - Cryptographic operations (key storage, encryption)
   For each: file:line, what makes it dangerous, what input could reach it.

4. DATA FLOW OVERVIEW
   How untrusted input moves through the system:
   - Input source → validation/sanitization → processing → output/sink
   - Note where sanitization EXISTS and where it's MISSING on each path
   - Flag "no sanitization" paths explicitly

5. ARCHITECTURE OVERVIEW
   - Key components and how they relate
   - Authentication/authorization mechanism
   - Session management approach
   - Plugin/extension system (if any)
   - Inter-process communication (if any)

OUTPUT AS VALID JSON with these keys:
{
  "entry_points": [{...}],
  "trust_boundaries": [{...}],
  "sinks": [{...}],
  "data_flows": [{...}],
  "architecture": {...},
  "cve_catalog": [...],
  "coverage_plan": [...]  // Ordered list of files/dirs to audit, prioritized by risk
}
"""


def run(
    repo_path: Path,
    fingerprint: dict[str, Any],
    classification: dict[str, Any],
    static_analysis: dict[str, Any],
) -> dict[str, Any]:
    logger.info("Step 4: Building threat model + CVE catalog...")

    primary = classification.get("primary_class", "general_application")
    primary_lang = fingerprint.get("primary_language", "")
    frameworks = fingerprint.get("frameworks", [])
    file_inventory = static_analysis.get("file_inventory", {})
    sinks = static_analysis.get("_sink_matches", [])
    taint_flows = static_analysis.get("_taint_flows", [])

    # Build CVE catalog
    cve_catalog = _build_cve_catalog(primary, primary_lang, frameworks)

    # Build code context for the LLM threat model pass
    code_samples = _collect_threat_model_files(repo_path, file_inventory, sinks, primary)
    codebase_overview = _build_overview(repo_path, file_inventory, sinks, taint_flows)

    client = LLMClient()

    system = f"""{GUARD_PREAMBLE}

You are a security architect building a threat model for a whitebox code audit.
Target: {classification.get('display_name', primary)} ({primary})
Language: {primary_lang}

{cve_catalog["text"]}

{THREAT_MODEL_PROMPT}
"""

    user = (
        f"=== CODEBASE OVERVIEW ===\n\n{codebase_overview}\n\n"
        f"=== CODE SAMPLES (entry points + hot files) ===\n\n"
        f"Build the threat model. Output valid JSON only."
    )

    alloc_code = {}
    for path, content in code_samples.items():
        alloc_code[path] = content

    # Combine user message with code
    code_text = ""
    for path, content in code_samples.items():
        code_text += f"\n--- {path} ---\n{content}\n"

    full_prompt = f"{user}\n\n=== SOURCE CODE ===\n{code_text[:80000]}"

    try:
        result = client.chat_json(system, full_prompt, max_tokens=4096, temperature=0.3)
    except Exception as e:
        logger.warning(f"Threat model LLM call failed: {e}")
        result = {}

    if not result:
        logger.warning("Threat model returned empty. Using static analysis fallback.")
        result = _fallback_threat_model(file_inventory, sinks, taint_flows)

    # Build coverage plan from file inventory + sink hot files
    coverage_plan = _build_coverage_plan(repo_path, file_inventory, sinks, result.get("entry_points", []))

    threat_model = {
        "entry_points": result.get("entry_points", []),
        "trust_boundaries": result.get("trust_boundaries", []),
        "sinks": result.get("sinks", []),
        "data_flows": result.get("data_flows", []),
        "architecture": result.get("architecture", {}),
        "cve_catalog": cve_catalog,
        "coverage_plan": coverage_plan,
        "total_planned_files": len(coverage_plan),
        "classification": classification,
        "fingerprint": {k: v for k, v in fingerprint.items() if k != "dependencies"},
        "built_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    logger.info(f"  Threat model: {len(coverage_plan)} files to audit, "
                f"{len(result.get('entry_points', []))} entry points, "
                f"{cve_catalog['count']} CVEs")

    return threat_model


def _build_cve_catalog(primary: str, language: str, frameworks: list[str]) -> dict[str, Any]:
    db = CVEDatabase()
    catalog: dict[str, list[dict]] = {}
    keywords = _build_keywords(primary, language, frameworks)

    for exploit_class, cwe_ids in EXPLOIT_CLASSES.items():
        results = db.search(
            query=" ".join(keywords[:4]),
            cwe_ids=cwe_ids,
            limit=10,
            min_epss=0.01,
        )
        if not results:
            results = db.search(query=" ".join(keywords[:4]), kev_only=True, limit=5)
        if results:
            catalog[exploit_class] = _format_cves(results)

    # KEV catalog
    kev_all = db.search(query=" ".join(keywords[:4]), kev_only=True, limit=50)
    kev_catalog = _format_cves(kev_all)

    db.close()

    total = sum(len(v) for v in catalog.values())
    text_lines = []

    guidance = {
        "command_injection": "Find all command/shell execution. Check if input reaches without sanitization.",
        "memory_safety": "Audit memory operations: allocations, frees, buffer access, pointer arithmetic. Check bounds, lifetimes.",
        "deserialization": "Find all deserialization. Check type validation, gadget chains.",
        "ssrf": "Find HTTP clients with dynamic URLs. Check URL validation.",
        "auth_bypass": "Audit auth middleware, session management, JWT. Look for missing checks, logic errors.",
        "path_traversal": "Find file paths with user input. Check canonicalization, symlinks.",
        "race_condition": "Find shared mutable state with concurrent access. Check TOCTOU.",
        "privilege_escalation": "Audit permission checks, role assignments. Look for confused deputy.",
    }

    for exploit_class, cves in catalog.items():
        g = guidance.get(exploit_class, "Search for analogous patterns.")
        kevs = sum(1 for c in cves if c.get("kev_member"))
        label = f"### {exploit_class.replace('_', ' ').title()} ({len(cves)} CVEs"
        label += f", {kevs} KEV!)" if kevs else ")"
        text_lines.append(label)
        text_lines.append(f"  HUNT: {g}")
        for cve in cves[:4]:
            k = " [KEV]" if cve.get("kev_member") else ""
            text_lines.append(f"  {cve['cve_id']}: {cve['description'][:150]}{k}")
        text_lines.append("")

    return {
        "classes": catalog,
        "kev": kev_catalog,
        "count": total,
        "kev_count": len(kev_catalog),
        "text": "\n".join(text_lines),
    }


def _build_keywords(primary: str, language: str, frameworks: list[str]) -> list[str]:
    k = [language]
    k.extend(frameworks)
    mapping = {
        "kernel": ["linux kernel", "kernel", "driver", "privilege escalation"],
        "powershell": ["powershell", "automation", "scripting", "command execution"],
        "dotnet": [".net", "csharp", "asp.net", "deserialization"],
        "web_app": ["web", "injection", "authentication", "csrf"],
        "ide_editor": ["code editor", "plugin", "extension", "file parsing"],
        "compiler": ["compiler", "parser", "code generation"],
        "cli_tool": ["cli", "command", "argument injection", "config"],
        "native_memory": ["buffer overflow", "use after free", "memory corruption"],
        "browser_sandbox": ["browser", "chrome", "sandbox", "renderer"],
        "ai_ml": ["tensorflow", "pytorch", "model", "serialization"],
        "container": ["container", "docker", "escape", "privilege"],
    }
    k.extend(mapping.get(primary, []))
    return list(dict.fromkeys(k))[:6]


def _format_cves(rows: list[dict]) -> list[dict]:
    return [
        {
            "cve_id": r.get("cve_id") or r.get("id", ""),
            "description": (r.get("description") or "")[:300],
            "cvss_score": r.get("cvss_score"),
            "epss_score": r.get("epss_score"),
            "kev_member": r.get("kev_member"),
            "cwe_ids": r.get("cwe_ids"),
            "severity": r.get("severity"),
        }
        for r in rows
    ]


def _collect_threat_model_files(
    repo_path: Path, file_inventory: dict, sinks: list, primary: str
) -> dict[str, str]:
    code_files: dict[str, str] = {}
    candidates: list[tuple[int, Path]] = []

    entry_patterns = {
        "powershell": ["**/*.ps1", "**/*.psm1", "**/Program.cs"],
        "dotnet": ["**/Program.cs", "**/*Controller.cs", "**/*Service.cs"],
        "web_app": ["**/app.py", "**/server.js", "**/routes.py", "**/controllers/*.py", "**/*Controller.java"],
        "cli_tool": ["**/main.*", "**/cli.*", "**/app.*"],
        "kernel": ["**/main.c", "**/init/*.c", "**/kernel/*.c"],
        "native_memory": ["**/main.c", "**/src/*.c", "**/lib/*.c"],
        "ide_editor": ["**/main.js", "**/server.js", "**/extension*.js", "**/extension*.ts"],
        "compiler": ["**/main.*", "**/driver.*", "**/parser.*"],
        "ai_ml": ["**/*.py", "**/core/**/*.cc", "**/ops/**/*.cc"],
        "container": ["**/main.go", "**/daemon/*.go", "**/runtime/*.go"],
    }

    for pat in entry_patterns.get(primary, ["**/main.*", "**/*.py", "**/*.js", "**/*.go", "**/src/*.c"]):
        for fp in repo_path.glob(pat):
            if fp.is_file() and fp.stat().st_size > 50:
                candidates.append((0, fp))
                if len(candidates) >= 10:
                    break

    sink_count: dict[str, int] = {}
    for s in sinks:
        sink_count[s["file"]] = sink_count.get(s["file"], 0) + 1
    for fname in sorted(sink_count, key=lambda x: -sink_count[x])[:10]:
        fp = repo_path / fname
        if fp.exists():
            candidates.append((1, fp))

    samples = file_inventory.get("sample_files", [])
    samples.sort(key=lambda s: -s.get("size", 0))
    for s in samples[:10]:
        fp = repo_path / s["path"]
        if fp.exists():
            candidates.append((2, fp))

    candidates.sort(key=lambda x: x[0])
    total = 0
    for _, fp in candidates:
        if total > 100000:
            break
        try:
            content = fp.read_text(errors="replace")
            if len(content) > 8000:
                content = content[:8000] + "\n// ..."
            code_files[str(fp.relative_to(repo_path))] = content
            total += len(content)
        except Exception:
            continue
    return code_files


def _build_overview(
    repo_path: Path, file_inventory: dict, sinks: list, taint_flows: list
) -> str:
    lines = [f"Repository: {repo_path}"]
    lines.append(f"Files: {file_inventory.get('total_files', 0)}")
    langs = file_inventory.get("languages", {})
    lines.append(f"Languages: {json.dumps(dict(list(langs.items())[:8]))}")

    try:
        lines.append("Top-level directories:")
        for item in sorted(repo_path.iterdir()):
            if item.is_dir() and not item.name.startswith("."):
                count = sum(1 for _ in item.rglob("*") if _.is_file())
                lines.append(f"  {item.name}/ ({count} files)")
    except Exception:
        pass

    if sinks:
        hot: dict[str, int] = {}
        for s in sinks:
            hot[s["file"]] = hot.get(s["file"], 0) + 1
        top = sorted(hot.items(), key=lambda x: -x[1])[:15]
        lines.append(f"\nSink density (most dangerous files):")
        for f, c in top:
            lines.append(f"  [{c:4d}] {f}")

    if taint_flows:
        high = [f for f in taint_flows if f.get("confidence", 0) >= 0.4]
        lines.append(f"\nTaint flows: {len(taint_flows)} total, {len(high)} high-confidence")
        for f in high[:5]:
            lines.append(f"  {f.get('source_type')} → {f.get('sink_type')} [{f.get('confidence', 0):.2f}]")

    return "\n".join(lines)


def _build_coverage_plan(
    repo_path: Path, file_inventory: dict, sinks: list, entry_points: list
) -> list[dict[str, Any]]:
    """Build prioritized file list for multi-pass audit coverage."""
    plan = []

    # Priority 0: entry point files
    seen: set[str] = set()
    for ep in entry_points[:20]:
        fname = ep.get("file", "")
        if fname and fname not in seen:
            plan.append({"file": fname, "priority": 0, "reason": "entry_point"})
            seen.add(fname)

    # Priority 1: hot sink files
    sink_count: dict[str, int] = {}
    for s in sinks:
        sink_count[s["file"]] = sink_count.get(s["file"], 0) + 1
    for fname in sorted(sink_count, key=lambda x: -sink_count[x])[:80]:
        if fname not in seen:
            plan.append({"file": fname, "priority": 1, "reason": f"sinks:{sink_count[fname]}"})
            seen.add(fname)

    # Priority 2: all remaining code files
    samples = file_inventory.get("sample_files", [])
    for s in samples:
        if s["path"] not in seen:
            plan.append({"file": s["path"], "priority": 2, "reason": "remaining"})
            seen.add(s["path"])

    return plan


def _fallback_threat_model(file_inventory: dict, sinks: list, taint_flows: list) -> dict[str, Any]:
    return {
        "entry_points": [],
        "trust_boundaries": [],
        "sinks": [],
        "data_flows": [],
        "architecture": {"note": "Fallback — LLM threat model failed, using static analysis only"},
        "note": "LLM call failed. Proceeding with static analysis signals.",
    }
