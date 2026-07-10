"""Step 5b: Triage — LLM verifies all candidate findings against source code.

The local model acts as a skeptical reviewer:
- Re-opens referenced files
- Confirms code really says what the finding claims
- Traces the path independently
- Checks: is there already a sanitizer, parameterized query, access check?
- Discards hallucinations, duplicates, unreachable paths
- Returns ONLY verified findings
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.llm.client import LLMClient
from src.llm.prompts import GUARD_PREAMBLE
from src.utils.logger import get_logger

logger = get_logger()

TRIAGE_PROMPT = """You are a skeptical vulnerability verifier. Your default position: DISTRUST every claim.
The fuzzer that found these is known to hallucinate. Your job is to determine what's REAL.

VERIFICATION METHOD (apply to EVERY candidate):

STEP 1 — READ THE ACTUAL CODE
  Open the referenced file at the cited line. Read the surrounding function.
  Does the code actually exist? Does it do what the candidate claims?
  If the file:line is wrong, or the code is different from the claim → DISCARD.

STEP 2 — TRACE THE DATA FLOW YOURSELF
  Do not trust the trace hops. Follow the data yourself.
  Start from the claimed entry point. Follow every assignment, every function call.
  Do you end up at the claimed sink? Is the path continuous?
  If the trace has gaps, imaginary functions, or jumps → DISCARD.

STEP 3 — CHECK EVERY MITIGATION
  Between entry and sink, look for:
  - Input validation (whitelists, regex, type checks, length checks)
  - Sanitization (encoding, escaping, stripping, normalization)
  - Access control (auth checks, role verification, ownership checks)
  - Parameterization (prepared statements, safe APIs that prevent injection)
  - Error handling (try/catch that prevents the exploit path)
  - Bounds checking (array length checks, size validation)
  - Canonicalization (Path.GetFullPath, realpath, URI normalization)
  If ANY of these effectively blocks the path → DISCARD with explanation.

STEP 4 — ASSESS EXPLOITABILITY HONESTLY
  Even if the path is real, ask:
  - Can an EXTERNAL attacker trigger this? Or does it require local access?
  - Is the attacker's input COMPLETELY controlled, or partially constrained?
  - What preconditions must the attacker satisfy? Are they realistic?
  - What is the ACTUAL impact? Don't inflate — a file read is not always RCE.
  - Does exploitation require a race condition with a very narrow window?
  - Can the vulnerability be reached through NORMAL application usage?
  Be honest. LOW severity is better than an inflated MEDIUM that gets ignored.

STEP 5 — PROVIDE EVIDENCE
  For KEPT findings, you MUST include:
  - The exact vulnerable lines quoted from the source
  - Your independent trace from entry to sink
  - Why each mitigation you found is insufficient
  - A concrete scenario showing how exploitation works at runtime
  - What a fix would look like (e.g., "validate with regex X", "use Parameterized API Y")

OUTPUT valid JSON:
{
  "verified": [
    {
      "candidate_index": 0,
      "kept": true,
      "reason": "DETAILED reason for decision — cite code, explain trace, discuss mitigations",
      "adjusted_confidence": 0.0-1.0,
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "is_exploitable_by_external_attacker": true/false,
      "requires_authentication": true/false,
      "vulnerability_class": "confirmed class name",
      "entry_point": "confirmed entry file:line and how data enters",
      "sink": "confirmed sink file:line and what dangerous operation",
      "source_reasoning": "EXACT code evidence. Quote vulnerable lines. Show YOUR independent trace. Explain why mitigations fail. Describe exploitation scenario. Suggest fix.",
      "confirmed_trace": [
        {"hop": 1, "file": "...", "line": N, "function": "...",
         "description": "...", "code_snippet": "..."}
      ],
      "notes": "any additional context about reliability, prerequisites, CVSS guess"
    }
  ],
  "summary": {
    "total_candidates": N,
    "kept": N,
    "discarded": N,
    "top_finding_severity": "CRITICAL|HIGH|MEDIUM|LOW|NONE",
    "most_confident_kept_reason": "brief description of strongest finding"
  }
}"""


def run(
    repo_path: Path,
    candidates: list[dict[str, Any]],
    checkpoint_dir: Path,
) -> list[dict[str, Any]]:
    logger.info("Step 5b: Triaging candidate findings...")

    if not candidates:
        logger.info("  No candidates to triage.")
        return []

    # Deduplicate by vulnerability class + file
    deduped = _deduplicate(candidates)
    logger.info(f"  {len(candidates)} raw → {len(deduped)} deduplicated candidates")

    # Group into batches (5 candidates per batch to keep context manageable)
    verified = []
    client = LLMClient()

    system = f"""{GUARD_PREAMBLE}

{TRIAGE_PROMPT}
"""

    for batch_start in range(0, len(deduped), 5):
        batch = deduped[batch_start:batch_start + 5]
        batch_num = batch_start // 5 + 1
        total_batches = (len(deduped) + 4) // 5

        logger.info(f"  Triage batch {batch_num}/{total_batches}: {len(batch)} candidates")

        # Build candidate descriptions + collect referenced files
        candidates_text = ""
        code_files = {}
        def _cf(level: str) -> float:
            return {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.3}.get(str(level).upper(), 0.5)

        for i, c in enumerate(batch):
            idx = deduped.index(c) if c in deduped else i
            candidates_text += (
                f"\nCANDIDATE {idx}: {c.get('vulnerability_class', '?')}\n"
                f"  Component: {c.get('component', '?')}\n"
                f"  Entry: {c.get('entry_point', '?')} [{c.get('entry_point_type', '?')}]\n"
                f"  Sink: {c.get('sink', '?')}\n"
                f"  Severity: {c.get('severity', '?')}  Confidence: {c.get('confidence', '?')}\n"
                f"  Description: {c.get('description', c.get('source_reasoning', ''))[:200]}\n"
                f"  CWE: {c.get('cwe_id', '')}  Auth: {c.get('requires_authentication', False)}\n"
            )

            # Collect referenced files for verification
            comp = c.get("component", "")
            for part in comp.split():
                part = part.strip(".,;:()[]{}'\"")
                if "." in part and len(part) > 3:
                    fname = Path(part).name if "/" in part or "\\" in part else part
                    for fp in repo_path.rglob(f"*{fname}*"):
                        rp = str(fp.relative_to(repo_path))
                        if rp not in code_files and fp.exists():
                            try:
                                code_files[rp] = fp.read_text(errors="replace")
                            except Exception:
                                continue

        code_text = ""
        for fname, content in code_files.items():
            code_text += f"\n--- {fname} ---\n{content}\n"

        max_code = 350000
        if len(code_text) > max_code:
            code_text = code_text[:max_code] + "\n// ... [truncated at context limit]"

        user = (
            f"VERIFY these {len(batch)} candidate findings against the source code below.\n\n"
            f"{candidates_text}\n\n=== SOURCE CODE ===\n{code_text}"
        )

        try:
            result = client.chat_json(system, user, max_tokens=4096, temperature=0.2)
        except Exception as e:
            logger.warning(f"    Triage batch failed: {e}")
            continue

        batch_verified = result.get("verified", []) if result else []

        for v in batch_verified:
            if v.get("kept"):
                # Merge with original candidate data
                c_idx = v.get("candidate_index", -1)
                if 0 <= c_idx < len(deduped):
                    original = deduped[c_idx]
                    v["original_component"] = original.get("component", "")
                    v["original_confidence"] = str(original.get("confidence", ""))
                    v["original_severity"] = str(original.get("severity", ""))
                    v["_fuzz_pass"] = original.get("_pass", 0)

                verified.append(v)
                logger.info(f"    VERIFIED: {v.get('vulnerability_class', '?')} "
                            f"({v.get('severity', '?')})")
            else:
                logger.info(f"    DISCARDED: {v.get('reason', '?')[:100]}")

        # Save checkpoint
        _save_triage_checkpoint(checkpoint_dir, verified)

    critical = sum(1 for v in verified if v.get("severity") == "CRITICAL")
    high = sum(1 for v in verified if v.get("severity") == "HIGH")
    logger.info(f"  Triage complete: {len(verified)} verified ({critical} CRITICAL, {high} HIGH)")

    return verified


def _deduplicate(candidates: list[dict]) -> list[dict]:
    seen: set[str] = set()
    unique = []
    for c in candidates:
        key = f"{c.get('vulnerability_class', '')}|{c.get('component', '')}|{c.get('entry_point', '')}"
        key_simple = key.lower().replace(" ", "")
        if key_simple not in seen:
            seen.add(key_simple)
            unique.append(c)
    return unique


def _save_triage_checkpoint(checkpoint_dir: Path, verified: list[dict]):
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    (checkpoint_dir / "triage_verified.json").write_text(
        json.dumps(verified, indent=2, default=str)
    )
