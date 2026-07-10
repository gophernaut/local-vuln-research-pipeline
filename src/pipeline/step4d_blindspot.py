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

MAX_FILES_PER_BATCH = 5
MAX_FILE_SIZE = 15000

BLIND_SPOT_PROMPT = """You are a senior security engineer doing a focused code review.

The codebase you're reviewing is: {target_name}
Primary language: {primary_lang}
Frameworks: {frameworks}

KNOWN CVE PATTERNS for this tech stack:
{cve_context}

You will receive {file_count} source file(s). For EACH file, review it for:

CRITICAL CHECKS:
- Hardcoded credentials, API keys, tokens, secrets
- Command execution with dynamic arguments (exec, system, popen, process.start, invoke-expression)
- SQL/NoSQL injection: dynamic queries with string concatenation
- Path traversal: file paths built from user input (read/write/include/require)
- Deserialization of untrusted data (pickle, yaml.load, ObjectInputStream, BinaryFormatter)
- Server-Side Request Forgery: HTTP calls with user-controlled URLs
- Authentication bypass: missing auth checks on sensitive endpoints

IMPORTANT CHECKS (often missed):
- Weak cryptography (MD5, SHA1 for security, static IV, ECB mode)
- Weak/absent random for security tokens (Math.random, predictable seeds)
- Race conditions / TOCTOU: file check then file use
- Missing access controls: sensitive operations without permission checks
- Insecure defaults: debug mode enabled, verbose errors, disabled TLS verification
- Dangerous config: admin endpoints exposed, default credentials, CORS misconfiguration
- Template injection: user data in templates without escaping
- Commented-out dangerous code: old vulnerable code left as comments
- Unsafe native calls: JNI, FFI, P/Invoke with user data

For EACH file, report ANY vulnerability found. Be specific: cite the exact line, explain
what makes it dangerous, and describe how an attacker would exploit it.

If a file has NO vulnerabilities, say so explicitly. Don't invent issues.

OUTPUT FORMAT (valid JSON):
{
  "files": [
    {
      "file": "relative/path/to/file.ps1",
      "has_vulnerability": true,
      "findings": [
        {
          "line": 42,
          "category": "command_injection",
          "cwe": "CWE-78",
          "severity": "CRITICAL",
          "description": "What the issue is at that line",
          "exploit_scenario": "How an attacker would exploit it",
          "remediation": "How to fix it"
        }
      ]
    },
    {
      "file": "relative/path/to/safe_file.cs",
      "has_vulnerability": false,
      "findings": []
    }
  ]
}
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

    cve_text = (cve_catalog.get("text") or "")[:1500]

    prompt = BLIND_SPOT_PROMPT.format(
        target_name=target_name,
        primary_lang=primary_lang,
        frameworks=frameworks,
        cve_context=cve_text or "(no CVE data available)",
        file_count=len(file_batch),
    )

    prompt += "\n=== SOURCE FILES TO REVIEW ===\n\n"
    for f in file_batch:
        prompt += f"--- FILE: {f['path']} ({f['language']}) ---\n"
        content = (f.get("content") or "")[:MAX_FILE_SIZE]
        prompt += content
        prompt += "\n\n"

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
    logger.info(f"  {len(batches)} batches ({len(uncovered)} files, "
                f"{MAX_FILES_PER_BATCH} per LLM call)")

    max_batches = config.get("scaling.llm_priority_top_n", 1000)
    if len(batches) > max_batches:
        logger.warning(f"  Capping at {max_batches} batches ({max_batches * MAX_FILES_PER_BATCH} files)")
        batches = batches[:max_batches]

    client = LLMClient()
    all_findings = []
    errors = 0

    system = f"""{GUARD_PREAMBLE}

You are reviewing source code files for security vulnerabilities.
Focus on real, exploitable issues. Don't flag things that are clearly safe.
For each file, report findings in the exact JSON format requested.
"""

    for i, batch in enumerate(batches):
        prompt = _build_blind_spot_batch(batch, threat_model, cve_catalog, repo_path)

        try:
            result = client.chat_json(system, prompt, temperature=0.3, max_tokens=4096)
        except Exception as e:
            logger.warning(f"  Batch {i + 1}/{len(batches)} LLM call failed: {e}")
            errors += 1
            continue

        if not result:
            errors += 1
            continue

        files_section = result.get("files", [])
        for fdata in files_section:
            if fdata.get("has_vulnerability") and fdata.get("findings"):
                for finding in fdata["findings"]:
                    all_findings.append({
                        "file": fdata.get("file", ""),
                        "line": finding.get("line", 0),
                        "category": finding.get("category", "unknown"),
                        "cwe": finding.get("cwe", ""),
                        "severity": finding.get("severity", "MEDIUM"),
                        "description": finding.get("description", ""),
                        "exploit_scenario": finding.get("exploit_scenario", ""),
                        "remediation": finding.get("remediation", ""),
                        "source": "file_review",
                    })

        if (i + 1) % 20 == 0:
            logger.info(f"  Reviewed {min((i + 1) * MAX_FILES_PER_BATCH, len(uncovered))}/{len(uncovered)} files")

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
