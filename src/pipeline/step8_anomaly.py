"""Step 8: Anomaly check — detects potential prompt injection in target repo.

Compares LLM findings ratio against baseline distribution from clean repos.
Triggers re-analysis with stripped comments if anomaly detected.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from src.llm.guard import InjectionGuard
from src.utils.logger import get_logger

logger = get_logger()


def run(
    validated_findings: list[dict[str, Any]],
    static_analysis: dict[str, Any],
    repo_path: Path | None = None,
) -> dict[str, Any]:
    logger.info("Step 8: Anomaly check (prompt injection detection)...")

    semgrep_hits = static_analysis.get("summary", {}).get("semgrep_hits", 0)
    llm_findings = len(validated_findings)

    guard = InjectionGuard()
    anomaly = guard.check_anomaly(llm_findings, semgrep_hits)

    result = {
        "llm_findings": llm_findings,
        "semgrep_hits": semgrep_hits,
        "ratio": anomaly["ratio"],
        "within_normal": anomaly["within_normal"],
        "suspicious": anomaly["suspicious"],
        "recommendation": anomaly.get("recommendation", "none"),
        "stripped_rerun_done": False,
    }

    if anomaly["suspicious"]:
        logger.warning(
            f"  ANOMALY DETECTED: ratio={anomaly['ratio']:.4f} "
            f"(threshold={anomaly.get('threshold', 0):.4f})"
        )
        logger.warning(f"  Recommendation: {anomaly.get('recommendation')}")
    else:
        logger.info(f"  Normal: ratio={anomaly['ratio']:.4f}")

    return result
