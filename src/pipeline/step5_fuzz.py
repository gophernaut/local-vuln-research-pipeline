"""Step 5: Exhaustive file-by-file vulnerability review.

Matches the Project Black approach (projectblack.io/blog):
  - One focused batch per pass, clean context each time
  - Short prompt — not a 120-line monster
  - Single pass per batch: find vulns + assess reachability in one call
  - Limited files per batch so each file gets proper attention

Exhaustive: every non-test source file. Per-batch checkpointing.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from src.llm.client import LLMClient
from src.llm.prompts import audit_single_pass
from src.config import config
from src.utils.logger import get_logger

logger = get_logger()

_context = config.get("server.context_length", 32768)
MAX_CODE_CHARS_PER_PASS = max(20000, int((_context - 8000) * 3.5))
MAX_FILES_PER_BATCH = 10


def run(
    repo_path: Path,
    threat_model: dict[str, Any],
    checkpoint_dir: Path,
) -> list[dict[str, Any]]:
    logger.info("Step 5: Exhaustive file-by-file vulnerability review...")

    coverage_plan = threat_model.get("coverage_plan", [])
    if not coverage_plan:
        logger.warning("No coverage plan. Cannot scan.")
        return []

    progress = _load_progress(checkpoint_dir)
    all_candidates = list(progress.get("all_candidates", []))
    covered_files: list[str] = progress.get("covered_files", [])
    pass_num = progress.get("completed_passes", 0)

    classification = threat_model.get("classification", {})
    cve_text = threat_model.get("cve_catalog", {}).get("text", "")

    client = LLMClient()
    total_files = len(coverage_plan)
    covered_set = set(covered_files)

    target = classification.get("display_name", "?")
    lang = classification.get("key_signals", {}).get("language", "?")
    system = audit_single_pass(target, lang, cve_text)

    est_passes = _estimate_passes(coverage_plan, repo_path)
    logger.info(f"  Exhaustive: {total_files} files, ~{est_passes} batches")
    logger.info(f"  Max {MAX_FILES_PER_BATCH} files/batch, "
                f"~{MAX_CODE_CHARS_PER_PASS:,} chars/batch")
    logger.info(f"  {len(covered_files)} already covered, resuming")

    while len(covered_files) < total_files:
        pass_start = time.time()
        pass_num += 1

        batch = _pick_batch(coverage_plan, covered_set, repo_path,
                            MAX_CODE_CHARS_PER_PASS, MAX_FILES_PER_BATCH)
        if not batch:
            logger.info(f"  All {total_files} files covered.")
            break

        batch_files = [item["file"] for item in batch]
        pct = len(covered_files) / total_files * 100
        file_names = ", ".join(f.split("/")[-1] for f in batch_files[:3])
        logger.info(f"  Batch {pass_num} [{pct:.1f}%]: "
                    f"{len(batch_files)} files — {file_names}...")

        code_text = ""
        for item in batch:
            fp = repo_path / item["file"]
            if fp.exists():
                try:
                    content = fp.read_text(errors="replace")
                    code_text += f"\n=== {item['file']} ===\n{content}\n"
                except Exception:
                    continue
            covered_set.add(item["file"])

        if not code_text:
            continue

        user = code_text[:MAX_CODE_CHARS_PER_PASS]

        try:
            result = client.chat_json(system, user, max_tokens=3072, temperature=0.4)
        except Exception as e:
            logger.warning(f"    LLM call failed: {e}")
            result = {}

        candidates = result.get("candidates", result.get("findings", []))
        if isinstance(candidates, dict):
            candidates = candidates.get("candidates", candidates.get("findings", []))
        if not isinstance(candidates, list):
            candidates = []

        for c in candidates:
            c["_pass"] = pass_num
            c["_audited_files"] = batch_files
        all_candidates.extend(candidates)

        elapsed = time.time() - pass_start
        covered_files = sorted(covered_set)
        logger.info(f"    {len(candidates)} candidates ({elapsed:.1f}s) "
                    f"[{len(all_candidates)} total]")

        _checkpoint(checkpoint_dir, pass_num, est_passes,
                    covered_files, total_files, all_candidates)

    logger.info(f"  Complete: {len(covered_files)}/{total_files} files, "
                f"{len(all_candidates)} candidates over {pass_num} batches")

    clean = []
    for c in all_candidates:
        clean_c = {k: v for k, v in c.items() if not k.startswith("_")}
        clean_c["_audited_files"] = c.get("_audited_files", [])
        clean_c["_pass"] = c.get("_pass", 0)
        clean.append(clean_c)
    return clean


def _pick_batch(coverage_plan, covered_set, repo_path, max_chars, max_files):
    batch = []
    char_budget = max_chars
    for priority in range(3):
        if char_budget < 500 or len(batch) >= max_files:
            break
        for item in coverage_plan:
            if item["file"] in covered_set:
                continue
            if item["priority"] != priority:
                continue
            if len(batch) >= max_files:
                break
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


def _estimate_passes(coverage_plan, repo_path):
    total_chars = 0
    for item in coverage_plan:
        fp = repo_path / item.get("file", "")
        if fp.exists():
            total_chars += fp.stat().st_size
    avg_chars_per_batch = MAX_CODE_CHARS_PER_PASS * 0.7
    return max(1, int(total_chars / avg_chars_per_batch) + 1)


def _checkpoint(checkpoint_dir, pass_num, est_passes, covered_files, total_files, candidates):
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    progress = {
        "completed_passes": pass_num,
        "total_passes": est_passes,
        "all_candidates": candidates,
        "covered_files": covered_files,
        "score": len(covered_files) / total_files if total_files else 0,
    }
    (checkpoint_dir / "fuzz_progress.json").write_text(json.dumps(progress, indent=2, default=str))
    (checkpoint_dir / "fuzz_progress.md").write_text(
        f"# Review Progress\n\n"
        f"Batch: {pass_num}/{est_passes}\n"
        f"Coverage: {len(covered_files)}/{total_files} ({progress['score']:.0%})\n"
        f"Candidates: {len(candidates)}\n"
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
        "score": 0.0,
    }
