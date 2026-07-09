"""Step 5: N-pass clean-context fuzz audit.

Each pass starts with fresh context, picks 3-5 files from uncovered areas,
receives the threat model + CVE catalog, and reports any plausible vulnerability.
Coverage tracker ensures passes explore the full attack surface.
Candidates are pooled to disk for later triage.

This is recall-first. Noise is expected. Precision comes in Step 5b (triage).
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from src.llm.client import LLMClient
from src.llm.prompts import GUARD_PREAMBLE
from src.config import config
from src.utils.logger import get_logger

logger = get_logger()

PASSES_DEFAULT = 20
FILES_PER_PASS = 4

FUZZ_PASS_PROMPT = """You are auditing source code for security vulnerabilities.

RULES:
- Be THOROUGH. Read every line of the provided files.
- Report ANY plausible vulnerability, even if you're not 100% sure.
- Do NOT self-censor. False positives in this pass are EXPECTED.
- Every finding MUST cite exact file:line references from the provided code.
- Trace the path from attacker-controlled input to dangerous sink.
- Check if any validation/sanitization/auth check exists that would block the path.
- If blocked, note it but still report — triage will verify.

FOR EACH CANDIDATE FINDING, output:
{
  "candidates": [
    {
      "vulnerability_class": "e.g. Command injection via pipeline parameter",
      "component": "file:line — function name",
      "entry_point": "how attacker reaches this",
      "entry_point_type": "HTTP_POST|CLI_ARG|PS_PARAM|FILE_PARSE|IPC|SYSCALL|...",
      "sink": "dangerous operation and file:line",
      "trace_hops": [
        {"hop": 1, "file": "...", "line": N, "function": "...",
         "description": "...", "data_controlled": true/false, "mitigation": null/"..."}
      ],
      "preconditions": ["what must be true"],
      "expected_impact": "RCE|LPE|info_leak|auth_bypass|...",
      "confidence": 0.0-1.0,
      "cwe_id": "CWE-XXXX",
      "requires_authentication": true/false
    }
  ],
  "next_files_wanted": ["paths to files you want to see next pass"]
}

THE THREAT MODEL AND CVE CATALOG BELOW TELLS YOU WHAT TO HUNT FOR.
READ EVERY LINE OF THE PROVIDED CODE. REPORT EVERYTHING SUSPICIOUS."""


def run(
    repo_path: Path,
    threat_model: dict[str, Any],
    checkpoint_dir: Path,
) -> list[dict[str, Any]]:
    logger.info("Step 5: N-pass clean-context fuzz audit...")

    coverage_plan = threat_model.get("coverage_plan", [])
    if not coverage_plan:
        logger.warning("No coverage plan in threat model. Cannot fuzz.")
        return []

    num_passes = _determine_pass_count(len(coverage_plan))

    progress = _load_progress(checkpoint_dir)
    start_pass = progress.get("completed_passes", 0)
    all_candidates = list(progress.get("all_candidates", []))
    covered_files = progress.get("covered_files", [])
    next_files_wanted = progress.get("next_files_wanted", [])

    threat_text = _format_threat_for_prompt(threat_model)
    cve_text = threat_model.get("cve_catalog", {}).get("text", "")
    classification = threat_model.get("classification", {})

    client = LLMClient()

    system = f"""{GUARD_PREAMBLE}

You are a security vulnerability fuzzer. Your job: find bugs. Do not self-censor.
Report everything suspicious. False positives are expected and OK.

Target: {classification.get('display_name', '?')} ({classification.get('primary_class', '?')})
{cve_text}

{threat_text}

{FUZZ_PASS_PROMPT}
"""

    logger.info(f"  Fuzzing {len(coverage_plan)} files over {num_passes} passes (starting pass {start_pass + 1})")

    for pass_num in range(start_pass, num_passes):
        pass_start = time.time()

        # Pick files for this pass
        batch = _pick_batch(coverage_plan, covered_files, next_files_wanted, pass_num, FILES_PER_PASS)
        if not batch:
            logger.info(f"  All files covered. Done at pass {pass_num + 1}.")
            break

        batch_files = [item["file"] for item in batch]
        logger.info(f"  Pass {pass_num + 1}/{num_passes}: {len(batch_files)} files — "
                    f"{batch_files[0]}, ... [{len(covered_files)}/{len(coverage_plan)} covered]")

        # Read files
        code_samples = {}
        for item in batch:
            fp = repo_path / item["file"]
            if fp.exists():
                try:
                    content = fp.read_text(errors="replace")
                    if len(content) > 10000:
                        content = content[:10000] + "\n// ... [truncated]"
                    code_samples[f"{item['file']} (priority:{item['priority']} — {item['reason']})"] = content
                except Exception:
                    continue
            covered_files.append(item["file"])

        if not code_samples:
            continue

        # Build prompt with code
        code_text = ""
        for path, content in code_samples.items():
            code_text += f"\n--- {path} ---\n{content}\n"

        user = f"AUDIT THESE FILES. Report every plausible vulnerability. Output valid JSON.\n\n{code_text}"

        try:
            result = client.chat_json(system + f"\n\nAudit pass {pass_num + 1}/{num_passes}.", user, max_tokens=3072, temperature=0.4)
        except Exception as e:
            logger.warning(f"    LLM call failed: {e}")
            result = {}

        candidates = result.get("candidates", []) if result else []
        next_files_wanted = result.get("next_files_wanted", [])

        for c in candidates:
            c["_pass"] = pass_num + 1
            c["_audited_files"] = batch_files
        all_candidates.extend(candidates)

        elapsed = time.time() - pass_start
        logger.info(f"    {len(candidates)} candidates found ({elapsed:.1f}s)")

        # Save checkpoint after every pass
        progress = {
            "completed_passes": pass_num + 1,
            "total_passes": num_passes,
            "all_candidates": all_candidates,
            "covered_files": covered_files,
            "next_files_wanted": next_files_wanted,
            "score": _coverage_score(covered_files, coverage_plan),
        }
        _save_progress(checkpoint_dir, progress)

        # Early termination: if 3+ candidates found after pass 5, consider done
        if pass_num >= 4 and len(all_candidates) >= 3:
            logger.info(f"    {len(all_candidates)} candidates found. Continuing for completeness...")

    logger.info(f"  Fuzz complete: {len(all_candidates)} candidates from {len(covered_files)} files "
                f"({_coverage_score(covered_files, coverage_plan):.0%} coverage)")

    # Strip internal fields
    clean = []
    for c in all_candidates:
        clean_c = {k: v for k, v in c.items() if not k.startswith("_")}
        clean_c["_audited_files"] = c.get("_audited_files", [])
        clean_c["_pass"] = c.get("_pass", 0)
        clean.append(clean_c)

    return clean


def _pick_batch(coverage_plan, covered_files, next_files_wanted, pass_num, batch_size):
    batch = []

    # If LLM requested specific files, prioritize them
    if next_files_wanted and pass_num > 0:
        for wanted in next_files_wanted[:batch_size]:
            for item in coverage_plan:
                if item["file"] not in covered_files and wanted in item["file"]:
                    batch.append(item)
                    if len(batch) >= batch_size:
                        return batch

    # Otherwise pick from uncovered files, prioritizing priority order
    for priority in range(3):
        if len(batch) >= batch_size:
            break
        for item in coverage_plan:
            if item["file"] not in covered_files and item["priority"] == priority:
                batch.append(item)
                if len(batch) >= batch_size:
                    break

    return batch[:batch_size]


def _format_threat_for_prompt(threat_model: dict) -> str:
    parts = []
    eps = threat_model.get("entry_points", [])
    if eps:
        parts.append(f"### Entry Points ({len(eps)})")
        for ep in eps[:10]:
            parts.append(f"  {ep.get('file','')}:{ep.get('line','')} [{ep.get('type','')}] — {ep.get('description','')}")

    sinks = threat_model.get("sinks", [])
    if sinks:
        parts.append(f"\n### Sink Inventory ({len(sinks)})")
        for s in sinks[:15]:
            parts.append(f"  {s.get('file','')}:{s.get('line','')} [{s.get('category','')}] — {s.get('description','')}")

    bounds = threat_model.get("trust_boundaries", [])
    if bounds:
        parts.append(f"\n### Trust Boundaries ({len(bounds)})")
        for b in bounds[:5]:
            parts.append(f"  {b.get('description','')} @ {b.get('file','')}:{b.get('line','')}")

    return "\n".join(parts) if parts else "Threat model details not available."


def _determine_pass_count(plan_size: int) -> int:
    if plan_size <= 50: return min(plan_size // 2 + 2, 15)
    if plan_size <= 200: return PASSES_DEFAULT
    if plan_size <= 500: return 30
    if plan_size <= 2000: return 50
    return 80


def _coverage_score(covered, plan) -> float:
    if not plan: return 0.0
    return len(covered) / len(plan)


def _save_progress(checkpoint_dir: Path, progress: dict):
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    path = checkpoint_dir / "fuzz_progress.json"
    with open(path, "w") as f:
        json.dump(progress, f, indent=2, default=str)
    # Write human-readable progress
    md = checkpoint_dir / "fuzz_progress.md"
    md.write_text(
        f"# Fuzz Audit Progress\n\n"
        f"Pass: {progress['completed_passes']}/{progress['total_passes']}\n"
        f"Coverage: {progress['score']:.0%}\n"
        f"Files covered: {len(progress['covered_files'])}\n"
        f"Candidates found: {len(progress['all_candidates'])}\n"
    )


def _load_progress(checkpoint_dir: Path) -> dict:
    path = checkpoint_dir / "fuzz_progress.json"
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {
        "completed_passes": 0,
        "total_passes": 0,
        "all_candidates": [],
        "covered_files": [],
        "next_files_wanted": [],
        "score": 0.0,
    }
