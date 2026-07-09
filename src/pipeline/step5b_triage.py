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

TRIAGE_PROMPT = """You are a skeptical security reviewer verifying candidate vulnerability findings.

Your job: TRUST NOTHING. Verify everything against the actual source code.

FOR EACH CANDIDATE:
1. Re-read the referenced file. Does the code REALLY say what the finding claims?
2. Is the claimed trace path REAL? Can you follow each hop from entry to sink?
3. Check for mitigations the fuzzer may have missed:
   - Input validation/sanitization
   - Parameterized queries
   - Auth/access checks
   - Bounds checking
   - Encoding/escaping
   - Error handling that prevents exploit
4. If a mitigation exists that blocks the path → DISCARD with explanation
5. If the code is missing or the file:line is wrong → DISCARD
6. If the path is real and unmitigated → KEEP, rate severity honestly

OUTPUT valid JSON:
{
  "verified": [
    {
      "candidate_index": N (matches input array index),
      "kept": true/false,
      "reason": "why kept or why discarded",
      "adjusted_confidence": 0.0-1.0,
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "is_exploitable_by_external_attacker": true/false,
      "requires_authentication": true/false,
      "vulnerability_class": "confirmed class name",
      "entry_point": "confirmed entry point",
      "sink": "confirmed sink file:line",
      "confirmed_trace": [array of verified hops],
      "notes": "any additional context"
    }
  ],
  "summary": {
    "total_candidates": N,
    "kept": N,
    "discarded": N,
    "top_finding_severity": "CRITICAL|HIGH|MEDIUM|LOW|NONE"
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
        for i, c in enumerate(batch):
            idx = deduped.index(c) if c in deduped else i
            candidates_text += (
                f"\nCANDIDATE {idx}: {c.get('vulnerability_class', '?')}\n"
                f"  Component: {c.get('component', '?')}\n"
                f"  Entry: {c.get('entry_point', '?')} [{c.get('entry_point_type', '?')}]\n"
                f"  Sink: {c.get('sink', '?')}\n"
                f"  Confidence: {c.get('confidence', 0):.2f}\n"
                f"  Impact: {c.get('expected_impact', '?')}\n"
                f"  Preconditions: {c.get('preconditions', [])}\n"
                f"  Trace hops: {json.dumps(c.get('trace_hops', []))[:500]}\n"
            )

            # Collect referenced files for verification
            for hop in c.get("trace_hops", []):
                fname = hop.get("file", "")
                if fname and fname not in code_files:
                    fp = repo_path / fname
                    if fp.exists():
                        try:
                            code_files[fname] = fp.read_text(errors="replace")[:8000]
                        except Exception:
                            continue

        code_text = ""
        for fname, content in code_files.items():
            code_text += f"\n--- {fname} ---\n{content}\n"

        user = (
            f"VERIFY these {len(batch)} candidate findings against the source code below.\n\n"
            f"{candidates_text}\n\n=== SOURCE CODE ===\n{code_text[:60000]}"
        )

        try:
            result = client.chat_json(system, user, max_tokens=3072, temperature=0.2)
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
                    v["original_confidence"] = original.get("confidence", 0)
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
