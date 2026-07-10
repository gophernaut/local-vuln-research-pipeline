"""Step 5: N-pass exhaustive fuzz audit.

Every file in the coverage plan is sent to the LLM, no exceptions.
Passes are packed dynamically to fill the context window — larger files get
fewer companions, smaller files get bundled together.

This is recall-first. Noise is expected. Precision comes in Step 5b (triage).
Time is not a constraint — the goal is finding every real vulnerability.
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

MAX_CODE_CHARS_PER_PASS = 60000

FUZZ_PASS_PROMPT = """You are an elite offensive security researcher performing a whitebox code audit.
Your target is the code below. Your mission: find every exploitable vulnerability in these files.

THINK LIKE AN ATTACKER. For each file, mentally walk through:
  "If I control this input, what happens at runtime? Where does my data go?
   What checks does it pass through? What can I overwrite, inject, or bypass?"

COVER EVERY VULNERABILITY CLASS. Explicitly check each file for:
  COMMAND INJECTION: Any shell/process execution with user-controlled parts.
    - PowerShell::Create().AddScript(), Process.Start(), system(), exec(), popen()
    - String interpolation into commands, argument injection, shell metacharacters
  PATH TRAVERSAL / FILE MANIPULATION: User input in file paths.
    - Path.Combine() with user data, File.Read*/Write*, Directory operations
    - Symlink races (TOCTOU between check and use), zip-slip in archives
  DESERIALIZATION: Any deserialization of untrusted data.
    - BinaryFormatter, JSON.NET TypeNameHandling, XML serialization, YAML
    - Check for type validation, SerializationBinder, SafeSerialization
  CODE INJECTION: Dynamic code evaluation with user input.
    - Invoke-Expression, ScriptBlock.Create(), AddScript(), eval()
    - Template injection, expression language evaluation
  AUTH BYPASS / PRIVILEGE ESCALATION: Missing or flawed access checks.
    - Direct object references without ownership checks
    - Role checks that can be bypassed, missing authorization on sensitive operations
    - Token/session manipulation, JWT flaws, hardcoded credentials
  RACE CONDITIONS: Shared mutable state accessed concurrently.
    - Static fields, singletons, shared caches without locking
    - File system TOCTOU, multi-threaded access to non-thread-safe resources
  INFORMATION DISCLOSURE: Leaking sensitive data through error messages or outputs.
    - Stack traces, internal paths, secrets in responses
    - Timing side-channels, debug endpoints exposed
  MEMORY / NATIVE ISSUES: For C/C++/Rust unsafe code.
    - Buffer overflows, use-after-free, double-free, integer overflow
    - Unsafe pointer arithmetic, missing bounds checks
  CRYPTO WEAKNESSES: Insecure cryptographic usage.
    - Hardcoded keys/IVs, weak algorithms (MD5, SHA1, DES, RC4)
    - Missing authentication, predictable randomness, key leakage
  LOGIC FLAWS: Application-specific logic that can be exploited.
    - Integer overflow in calculations, negative values passed where positives expected
    - Type confusion, unexpected null handling, state machine flaws

HOW TO ANALYZE EACH FILE:
1. Scan for dangerous sinks first (see catalog below) — mark every one
2. For each sink, trace BACKWARDS: where does the data come from?
3. Check if data passes through any validator, sanitizer, or access check
4. If none: REPORT. If there is one: try to find a bypass.
5. Consider INDIRECT data flows: can a different entry point influence this variable?
6. Check error handling: does an exception expose the sink without the validator?
7. Consider encoding tricks: Unicode normalization, null bytes, path separator confusion
8. Check for TYPE CONFUSION: could a string become an object, or int become a path?

FOR EACH FINDING YOU MUST:
- QUOTE the exact vulnerable lines from the file
- Explain step-by-step how attacker data reaches the sink
- State what validation EXISTS (if any) and why it's insufficient
- Describe what a working exploit would look like at runtime
- Rate confidence based on how certain you are the path is exploitable
  (0.9+ = I can see the exact exploit, 0.7 = likely exploitable but needs verification,
   0.5 = suspicious pattern but path may be constrained, below 0.5 = worth noting)

COMPARE AGAINST THE CVE CATALOG: For each finding, check if it resembles a known CVE
pattern from the catalog. Reference the CVE ID if it does.

OUTPUT FORMAT — valid JSON only:
{
  "candidates": [
    {
      "vulnerability_class": "specific class name with CWE reference",
      "component": "file:line — function name",
      "entry_point": "exactly how attacker reaches this code",
      "entry_point_type": "HTTP_POST|CLI_ARG|PS_PARAM|FILE_PARSE|IPC|SYSCALL|ENV_VAR|CONFIG_FILE",
      "sink": "exact dangerous operation and file:line",
      "source_reasoning": "DETAILED. Quote the actual lines. Show the missing validation. Explain the runtime exploit path. Why is this NOT a false positive? What makes the existing mitigations insufficient?",
      "similar_cve": "CVE-XXXX-YYYYY if a known pattern matches, or null",
      "trace_hops": [
        {"hop": 1, "file": "...", "line": N, "function": "...",
         "description": "what happens in this hop",
         "data_controlled": true/false,
         "mitigation": null/"what check exists and why it fails",
         "code_snippet": "the actual vulnerable line(s)"}
      ],
      "preconditions": ["exactly what must be true for exploitation"],
      "expected_impact": "RCE|LPE|info_leak|auth_bypass|file_write|file_read|privilege_escalation|...",
      "confidence": 0.0-1.0,
      "cwe_id": "CWE-XX",
      "requires_authentication": true/false
    }
  ],
  "next_files_wanted": ["specific file paths you want to see to verify or extend findings"],
  "files_fully_analyzed": true/false
}

DO NOT hold back. DO NOT self-censor. DO NOT dismiss findings because "it might be handled elsewhere."
If you see a dangerous pattern, REPORT IT. Triage happens later.
Every false negative is WORSE than every false positive here.
BE EXHAUSTIVE. Every single line of these files must be mentally traced for vulnerabilities."""

FILES_FOLLOWUP_PROMPT = """You previously analyzed these files but marked them as incomplete.
RE-ANALYZE with full attention. You must find every issue this time.
Previous context is gone — this is a fresh pass. Be MORE thorough, not less.

Look for:
- Vulnerabilities you may have missed on first pass
- Deeper traces: what happens AFTER the sink? Can you chain to higher impact?
- Subtle bugs: off-by-one, integer overflow, Unicode issues, TOCTOU
- Implicit trust: does this code assume data from other components is already validated?

EVERY FILE MUST BE MARKED files_fully_analyzed: true THIS TIME."""


def run(
    repo_path: Path,
    threat_model: dict[str, Any],
    checkpoint_dir: Path,
) -> list[dict[str, Any]]:
    logger.info("Step 5: N-pass exhaustive fuzz audit...")

    coverage_plan = threat_model.get("coverage_plan", [])
    if not coverage_plan:
        logger.warning("No coverage plan in threat model. Cannot fuzz.")
        return []

    progress = _load_progress(checkpoint_dir)
    all_candidates = list(progress.get("all_candidates", []))
    covered_files: list[str] = progress.get("covered_files", [])
    existing_followup = progress.get("files_needing_followup", [])
    next_files_wanted = progress.get("next_files_wanted", [])
    pass_num = progress.get("completed_passes", 0)

    threat_text = _format_threat_for_prompt(threat_model)
    cve_text = threat_model.get("cve_catalog", {}).get("text", "")
    classification = threat_model.get("classification", {})

    client = LLMClient()

    system = f"""{GUARD_PREAMBLE}

You are an elite offensive security researcher performing a whitebox audit.
Find every vulnerability. Be exhaustive. Do not self-censor. False positives are expected.

TARGET: {classification.get('display_name', '?')}
CLASS: {classification.get('primary_class', '?')}
LANGUAGE: {classification.get('key_signals', {}).get('language', '?')}

HUNTING GUIDANCE — Known exploit patterns for this target type:
{cve_text}

THREAT SURFACE MAP:
{threat_text}

{FUZZ_PASS_PROMPT}
"""

    total_files = len(coverage_plan)
    covered_set = set(covered_files)
    files_needing_followup: set[str] = set(existing_followup)
    est_passes = _estimate_passes(coverage_plan, repo_path)

    logger.info(f"  Exhaustive mode: {total_files} files, ~{est_passes} passes estimated")
    logger.info(f"  Already covered: {len(covered_files)}, resuming from pass {pass_num + 1}")

    while len(covered_files) < total_files or files_needing_followup:
        pass_start = time.time()
        pass_num += 1

        if files_needing_followup:
            batch = _pick_followup_batch(coverage_plan, files_needing_followup, repo_path, MAX_CODE_CHARS_PER_PASS)
            if batch:
                files_needing_followup.difference_update(item["file"] for item in batch)
                is_followup = True
            else:
                files_needing_followup.clear()
                continue
        else:
            batch = _pick_budget_batch(coverage_plan, covered_set, next_files_wanted,
                                        repo_path, pass_num, MAX_CODE_CHARS_PER_PASS)
            is_followup = False

        if not batch:
            if not files_needing_followup:
                logger.info(f"  All {total_files} files covered. Done at pass {pass_num}.")
                break
            files_needing_followup.clear()
            continue

        batch_files = [item["file"] for item in batch]
        pct = len(covered_files) / total_files * 100
        label = "FOLLOWUP" if is_followup else f"{pct:.1f}%"
        logger.info(f"  Pass {pass_num} [{label}]: {len(batch_files)} files, "
                    f"{total_files - len(covered_files)} remaining — "
                    f"{batch_files[0]}, ...")

        code_samples = {}
        for item in batch:
            fp = repo_path / item["file"]
            if fp.exists():
                try:
                    content = fp.read_text(errors="replace")
                    code_samples[f"{item['file']} (priority:{item['priority']} — {item['reason']})"] = content
                except Exception:
                    continue
            if not is_followup:
                covered_set.add(item["file"])

        if not code_samples:
            continue

        code_text = ""
        for path, content in code_samples.items():
            code_text += f"\n--- {path} ---\n{content}\n"
        if len(code_text) > MAX_CODE_CHARS_PER_PASS:
            code_text = code_text[:MAX_CODE_CHARS_PER_PASS] + "\n// ... [truncated at context limit]"

        audit_prompt = FILES_FOLLOWUP_PROMPT if is_followup else "AUDIT THESE FILES EXHAUSTIVELY."
        user = f"{audit_prompt} Report every plausible vulnerability. Output valid JSON.\n\n{code_text}"

        try:
            result = client.chat_json(system, user, max_tokens=4096, temperature=0.4)
        except Exception as e:
            logger.warning(f"    LLM call failed: {e}")
            result = {}

        candidates = result.get("candidates", []) if result else []
        next_files_wanted = result.get("next_files_wanted", [])

        # Track files needing follow-up (flagged as not fully analyzed)
        if not is_followup and not result.get("files_fully_analyzed", True):
            for item in batch:
                files_needing_followup.add(item["file"])

        for c in candidates:
            c["_pass"] = pass_num
            c["_audited_files"] = batch_files
        all_candidates.extend(candidates)

        elapsed = time.time() - pass_start
        covered_files = sorted(covered_set)
        logger.info(f"    {len(candidates)} candidates found ({elapsed:.1f}s) "
                    f"[{len(all_candidates)} total]")

        progress = {
            "completed_passes": pass_num,
            "total_passes": est_passes,
            "all_candidates": all_candidates,
            "covered_files": covered_files,
            "next_files_wanted": next_files_wanted,
            "score": len(covered_files) / total_files if total_files else 0,
            "files_needing_followup": list(files_needing_followup),
        }
        _save_progress(checkpoint_dir, progress)

    final_covered = len(covered_files)
    logger.info(f"  Fuzz complete: {final_covered}/{total_files} files "
                f"({final_covered / total_files * 100:.1f}%), "
                f"{len(all_candidates)} candidates over {pass_num} passes")

    clean = []
    for c in all_candidates:
        clean_c = {k: v for k, v in c.items() if not k.startswith("_")}
        clean_c["_audited_files"] = c.get("_audited_files", [])
        clean_c["_pass"] = c.get("_pass", 0)
        clean.append(clean_c)

    return clean


def _pick_budget_batch(coverage_plan, covered_set, next_files_wanted,
                        repo_path, pass_num, max_chars):
    """Greedily pack uncovered files into the budget, priority-ordered."""
    batch = []
    char_budget = max_chars

    # If LLM requested specific files, try those first
    if next_files_wanted and pass_num > 1:
        for wanted in next_files_wanted:
            for item in coverage_plan:
                if item["file"] not in covered_set and wanted in item["file"]:
                    fp = repo_path / item["file"]
                    size = fp.stat().st_size if fp.exists() else 0
                    if size <= char_budget:
                        batch.append(item)
                        char_budget -= size
                        if char_budget < 500:
                            return batch

    # Fill remaining budget with uncovered files, priority order
    for priority in range(3):
        if char_budget < 200:
            break
        for item in coverage_plan:
            if item["file"] in covered_set:
                continue
            if item["priority"] != priority:
                continue
            fp = repo_path / item["file"]
            if not fp.exists():
                continue
            size = fp.stat().st_size
            if size <= char_budget or len(batch) == 0:
                batch.append(item)
                char_budget -= size
            if char_budget < 500:
                break

    return batch


def _pick_followup_batch(coverage_plan, files_needing_followup, repo_path, max_chars):
    """Pick files that were flagged as not fully analyzed for a re-audit."""
    batch = []
    char_budget = max_chars
    for item in coverage_plan:
        if item["file"] in files_needing_followup:
            fp = repo_path / item["file"]
            if fp.exists():
                size = fp.stat().st_size
                if size <= char_budget or len(batch) == 0:
                    batch.append(item)
                    char_budget -= size
                if char_budget < 500:
                    break
    return batch


def _estimate_passes(coverage_plan, repo_path) -> int:
    total_chars = 0
    for item in coverage_plan:
        fp = repo_path / item.get("file", "")
        if fp.exists():
            total_chars += fp.stat().st_size
    return max(1, total_chars // MAX_CODE_CHARS_PER_PASS + 1)


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
