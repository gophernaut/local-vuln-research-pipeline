"""Step 4d: Blind Spot Coverage — file-by-file LLM review sweep.

Project Black methodology: send every source file through the LLM with context.
Catches what path enumeration misses: logic bugs, misconfigurations, auth gaps,
weak patterns the sink tagger doesn't recognize, commented-out dangerous code.

Complements the deterministic path enumeration (which finds data-flow vulns)
with pure code-review intelligence for everything else.
"""
from __future__ import annotations

import concurrent.futures
import time
from pathlib import Path
from typing import Any

from src.llm.client import LLMClient
from src.llm.prompts import GUARD_PREAMBLE
from src.config import config
from src.utils.logger import get_logger

logger = get_logger()

MAX_FILES_PER_BATCH = 1
MAX_FILE_SIZE = 15000

BLIND_SPOT_PROMPT = """You are a red-team operator who found a zero-day in {target_name} last week. Now you're hunting for the next one.

Target: {target_name}
Language: {primary_lang}
Frameworks: {frameworks}

The team has been hit by these CVEs in similar products recently — use them as attack inspiration, not a checklist:
{cve_context}

You will receive 1 source file. Study it like an attacker would.

THINK LIKE THIS: If I were exploiting this codebase right now, how would I break THIS file? What input does it receive? Where does that input go? What happens if I send something unexpected — null bytes, format strings, path separators, shell metacharacters, serialized objects, prototype pollution payloads, extremely long strings, negative numbers, type mismatches?

FOCUS ON THESE ATTACK CLASSES (in order of lethality):
1. Remote Code Execution — anything that lets me run commands or code
2. File read/write — path traversal to read /etc/passwd or write a webshell
3. Auth bypass — getting admin without credentials
4. Information disclosure — leaking secrets, tokens, internal state
5. Privilege escalation — user → admin, admin → system

DO NOT report:
- Missing input validation that isn't dangerous (e.g., no length check on a safe operation)
- "Theoretical" issues with no concrete exploit path
- Anything that requires already having root/system access
- Issues you're not confident about

If you find a real vulnerability: describe the EXACT attack. What request/command would you send? What would happen? Be specific enough that a junior pentester could reproduce it.

If the file is genuinely clean: say so in one sentence. Don't pad.

OUTPUT FORMAT (valid JSON):
{{
  "has_vulnerability": true,
  "findings": [
    {{
      "line": 42,
      "category": "command_injection",
      "cwe": "CWE-78",
      "severity": "CRITICAL",
      "description": "What makes this exploitable at this exact line",
      "exploit_scenario": "Step-by-step attack: the request/input, the data flow, the impact",
      "remediation": "Concrete code fix"
    }}
  ]
}}

If no vulnerability found:
{{
  "has_vulnerability": false,
  "findings": []
}}
"""


def _build_blind_spot_batch(
    file_batch: list[dict],
    threat_model: dict,
    cve_catalog: dict,
    repo_path: Path,
) -> str:
    classification = threat_model.get("classification", {})
    fingerprint = threat_model.get("fingerprint", {})

    target_name = classification.get("display_name", str(repo_path))
    primary_lang = fingerprint.get("primary_language", "unknown")
    frameworks = ", ".join(fingerprint.get("frameworks", []) or ["none detected"])

    cve_text = (cve_catalog.get("text") or "")[:1200]

    prompt = BLIND_SPOT_PROMPT.format(
        target_name=target_name,
        primary_lang=primary_lang,
        frameworks=frameworks,
        cve_context=cve_text or "(no CVE data available)",
    )

    f = file_batch[0]
    prompt += "\n=== SOURCE FILE TO REVIEW ===\n\n"
    prompt += f"FILE: {f['path']} ({f['language']})\n\n"
    content = (f.get("content") or "")[:MAX_FILE_SIZE]
    prompt += content
    prompt += "\n"

    return prompt


def _collect_covered_files(path_analysis: dict) -> set[str]:
    covered = set()
    results = path_analysis.get("results", [])
    for r in results:
        fp = r.get("file_path", "")
        if fp:
            covered.add(fp.replace("\\", "/"))
    return covered


def _batch_files(
    uncovered: list[dict],
    batch_size: int = MAX_FILES_PER_BATCH,
) -> list[list[dict]]:
    batches = []
    for i in range(0, len(uncovered), batch_size):
        batches.append(uncovered[i : i + batch_size])
    return batches


def _should_skip_file(filepath: str) -> bool:
    skip_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv",
                  "target", "build", "dist", "vendor", ".next", ".nuxt",
                  ".idea", ".vscode", "bin", "obj", "Debug", "Release",
                  "packages", "TestResults", ".deps", ".libs", "test", "tests"}
    parts = Path(filepath).parts
    return any(d.lower() in (p.lower() for p in parts) for d in skip_dirs)


def run(
    repo_path: Path,
    threat_model: dict,
    path_analysis: dict,
    file_inventory: dict,
) -> dict[str, Any]:
    logger.info("Step 4d: File-by-file blind spot coverage (Project Black methodology)...")

    t0 = time.time()

    covered_files = _collect_covered_files(path_analysis)
    logger.info(f"  Files covered by path analysis: {len(covered_files)}")

    cve_catalog = threat_model.get("cve_catalog", {})

    uncovered = []
    total_skipped = 0
    for f in file_inventory.get("all_files", []):
        fpath = f.get("path", "")
        norm_path = fpath.replace("\\", "/")
        if norm_path in covered_files:
            continue
        if _should_skip_file(norm_path):
            total_skipped += 1
            continue
        fp = repo_path / fpath
        if not fp.exists() or not fp.is_file():
            continue
        ext = fp.suffix.lower()
        if ext in (".md", ".rst", ".txt", ".json", ".xml", ".yml", ".yaml",
                    ".svg", ".png", ".jpg", ".gif", ".ico", ".ttf", ".woff"):
            total_skipped += 1
            continue
        try:
            size = fp.stat().st_size
            if size < 50 or size > MAX_FILE_SIZE * 2:
                total_skipped += 1
                continue
            lang = f.get("language", ext)
            content = fp.read_text(encoding="utf-8", errors="replace")
            uncovered.append({
                "path": fpath,
                "language": lang,
                "content": content,
            })
        except Exception:
            total_skipped += 1
            continue

    logger.info(f"  Uncovered files to review: {len(uncovered)} ({total_skipped} skipped)")

    if not uncovered:
        logger.info("  No uncovered files — full coverage achieved.")
        return {
            "findings": [],
            "summary": {
                "files_reviewed": 0,
                "findings_found": 0,
                "covered_by_paths": len(covered_files),
                "uncovered_files": 0,
                "skipped": total_skipped,
            },
            "elapsed_seconds": time.time() - t0,
        }

    batches = _batch_files(uncovered)
    logger.info(f"  {len(batches)} files to review (1 per LLM call)")

    max_batches = config.get("scaling.llm_priority_top_n", 1000)
    if len(batches) > max_batches:
        logger.warning(f"  Capping at {max_batches} files ({max_batches * MAX_FILES_PER_BATCH})")
        batches = batches[:max_batches]

    client = LLMClient()
    all_findings = []
    errors = 0

    system = f"""{GUARD_PREAMBLE}

You are a red-team penetration tester. You have access to the source code of a target you're assessing. Review this file for real, exploitable vulnerabilities. Think like an attacker. Report only what you're confident about.
"""

    for i, batch in enumerate(batches):
        prompt = _build_blind_spot_batch(batch, threat_model, cve_catalog, repo_path)
        file_info = batch[0]

        try:
            result = client.chat_json(system, prompt, temperature=0.4, max_tokens=4096)
        except Exception as e:
            logger.warning(f"  File {i + 1}/{len(batches)} LLM call failed: {e}")
            errors += 1
            continue

        if not result:
            errors += 1
            continue

        if result.get("has_vulnerability") and result.get("findings"):
            for finding in result["findings"]:
                all_findings.append({
                    "file": file_info.get("path", ""),
                    "line": finding.get("line", 0),
                    "category": finding.get("category", "unknown"),
                    "cwe": finding.get("cwe", ""),
                    "severity": finding.get("severity", "MEDIUM"),
                    "description": finding.get("description", ""),
                    "exploit_scenario": finding.get("exploit_scenario", ""),
                    "remediation": finding.get("remediation", ""),
                    "source": "file_review",
                })

        if (i + 1) % 50 == 0:
            logger.info(f"  Reviewed {i + 1}/{len(uncovered)} files ({len(all_findings)} findings)")

    elapsed = time.time() - t0
    logger.info(
        f"  File review complete: {len(uncovered)} files in {len(batches)} batches, "
        f"{len(all_findings)} findings ({errors} errors)"
    )

    return {
        "findings": all_findings,
        "summary": {
            "files_reviewed": len(uncovered),
            "findings_found": len(all_findings),
            "covered_by_paths": len(covered_files),
            "uncovered_files": len(uncovered),
            "skipped": total_skipped,
            "batches": len(batches),
            "errors": errors,
        },
        "elapsed_seconds": elapsed,
    }
