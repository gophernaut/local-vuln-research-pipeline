"""Step 5: Exhaustive file-by-file vulnerability pattern scan.

Architecture validated by Project Black research (projectblack.io/blog):
  - One focused file batch per pass, clean context each time
  - Short, specific prompt — not a 120-line monster
  - 3 stages per batch: pattern scan → reachability filter → structured finding
  - Simple tasks any model can handle; complex reasoning deferred to triage/deep-trace

Exhaustive: every non-test source file. No sampling. Per-pass checkpointing.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from src.llm.client import LLMClient
from src.llm.prompts import GUARD_PREAMBLE, pattern_scan_system, reachability_system, document_system
from src.config import config
from src.utils.logger import get_logger

logger = get_logger()

MAX_CODE_CHARS_PER_PASS = 400000


def run(
    repo_path: Path,
    threat_model: dict[str, Any],
    checkpoint_dir: Path,
) -> list[dict[str, Any]]:
    logger.info("Step 5: Exhaustive file-by-file pattern scan...")

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

    est_passes = _estimate_passes(coverage_plan, repo_path)
    logger.info(f"  Exhaustive: {total_files} files, ~{est_passes} batches")
    logger.info(f"  {len(covered_files)} already covered, resuming")

    scan_sys, reach_sys, doc_sys = _build_system_prompts(classification, cve_text)

    while len(covered_files) < total_files:
        pass_start = time.time()
        pass_num += 1

        batch = _pick_budget_batch(coverage_plan, covered_set, repo_path, MAX_CODE_CHARS_PER_PASS)
        if not batch:
            logger.info(f"  All {total_files} files covered.")
            break

        batch_files = [item["file"] for item in batch]
        pct = len(covered_files) / total_files * 100
        logger.info(f"  Batch {pass_num} [{pct:.1f}% running]: "
                    f"{len(batch_files)} files — {batch_files[0].split('/')[-1]}, ...")

        code_samples = {}
        for item in batch:
            fp = repo_path / item["file"]
            if fp.exists():
                try:
                    code_samples[item["file"]] = fp.read_text(errors="replace")
                except Exception:
                    continue
            covered_set.add(item["file"])

        if not code_samples:
            continue

        code_text = ""
        for path, content in code_samples.items():
            code_text += f"\n=== {path} ===\n{content}\n"

        # ---- Stage 1: Pattern Scan ----
        patterns = _run_stage(client, scan_sys, code_text, "Pattern scan", pass_num)
        if not patterns:
            elapsed = time.time() - pass_start
            _checkpoint(checkpoint_dir, pass_num, est_passes,
                        sorted(covered_set), total_files, all_candidates)
            logger.info(f"    no patterns ({elapsed:.1f}s)")
            continue

        logger.info(f"    {len(patterns)} patterns found, checking reachability...")

        # ---- Stage 2: Reachability Filter ----
        reachable = _run_stage_reachability(client, reach_sys, code_text, patterns, pass_num)

        if reachable is None:
            elapsed = time.time() - pass_start
            _checkpoint(checkpoint_dir, pass_num, est_passes,
                        sorted(covered_set), total_files, all_candidates)
            logger.info(f"    reachability check failed")
            continue

        kept = [r for r in reachable if r.get("reachable")]
        logger.info(f"    {len(kept)}/{len(patterns)} reachable")

        if not kept:
            elapsed = time.time() - pass_start
            _checkpoint(checkpoint_dir, pass_num, est_passes,
                        sorted(covered_set), total_files, all_candidates)
            logger.info(f"    no reachable patterns ({time.time() - pass_start:.1f}s)")
            continue

        # ---- Stage 3: Document Findings ----
        candidates = _run_stage_document(client, doc_sys, code_text, kept, pass_num)

        if candidates:
            for c in candidates:
                c["_pass"] = pass_num
                c["_audited_files"] = batch_files
            all_candidates.extend(candidates)

        elapsed = time.time() - pass_start
        covered_files = sorted(covered_set)
        logger.info(f"    {len(candidates or [])} candidates ({elapsed:.1f}s) [{len(all_candidates)} total]")

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


# ---- Stage runners ----

def _run_stage(client, system, code_text, label, pass_num):
    user = "Scan the code below for dangerous patterns. Output JSON.\n\n" + code_text[:MAX_CODE_CHARS_PER_PASS]
    try:
        result = client.chat_json(system, user, max_tokens=1024, temperature=0.3)
    except Exception as e:
        logger.warning(f"    {label} failed: {e}")
        return []
    return result.get("patterns", result if isinstance(result, list) else [])


def _run_stage_reachability(client, system, code_text, patterns, pass_num):
    patterns_text = json.dumps(patterns, indent=2)
    user = (
        f"For each pattern below, determine if a low-privileged attacker can reach it.\n\n"
        f"PATTERNS:\n{patterns_text[:8000]}\n\n"
        f"SOURCE CODE:\n{code_text[:MAX_CODE_CHARS_PER_PASS]}"
    )
    try:
        result = client.chat_json(system, user, max_tokens=2048, temperature=0.3)
    except Exception as e:
        logger.warning(f"    reachability failed: {e}")
        return None
    return result.get("patterns", result.get("results", []))


def _run_stage_document(client, system, code_text, reachable, pass_num):
    reachable_text = json.dumps(reachable, indent=2)
    user = (
        f"Document these reachable findings as structured vulnerability candidates.\n\n"
        f"REACHABLE PATTERNS:\n{reachable_text[:6000]}\n\n"
        f"SOURCE CODE:\n{code_text[:MAX_CODE_CHARS_PER_PASS]}"
    )
    try:
        result = client.chat_json(system, user, max_tokens=2048, temperature=0.3)
    except Exception as e:
        logger.warning(f"    documentation failed: {e}")
        return []
    return result.get("candidates", [])


# ---- Prompt builders ----

def _build_system_prompts(classification, cve_text):
    target = classification.get("display_name", "?")
    lang = classification.get("key_signals", {}).get("language", "?")
    primary = classification.get("primary_class", "?")

    cve_short = cve_text[:2000] if cve_text else ""

    scan_sys = pattern_scan_system(target, lang, primary, cve_short)
    reach_sys = reachability_system(target, lang)
    doc_sys = document_system(target, lang)

    return scan_sys, reach_sys, doc_sys


# ---- Batch packing ----

def _pick_budget_batch(coverage_plan, covered_set, repo_path, max_chars):
    batch = []
    char_budget = max_chars
    for priority in range(3):
        if char_budget < 500:
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


def _estimate_passes(coverage_plan, repo_path):
    total_chars = 0
    for item in coverage_plan:
        fp = repo_path / item.get("file", "")
        if fp.exists():
            total_chars += fp.stat().st_size
    return max(1, total_chars // MAX_CODE_CHARS_PER_PASS + 1)


# ---- Checkpointing ----

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
        f"# Pattern Scan Progress\n\n"
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
