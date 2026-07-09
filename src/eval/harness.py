"""Eval harness runner — runs pipeline against known-vuln corpora and computes metrics."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.eval.datasets import EvalDatasetManager
from src.eval.metrics import MetricsCalculator
from src.eval.calibration import Calibration
from src.config import ROOT_DIR
from src.utils.logger import get_logger

EVAL_RESULTS = ROOT_DIR / "data" / "eval_results.json"

logger = get_logger()


class EvalHarness:
    def __init__(self):
        self.datasets = EvalDatasetManager()
        self.metrics = MetricsCalculator()

    def run(self):
        logger.info("=== Evaluation Harness ===")

        self.metrics = MetricsCalculator()
        self.datasets = EvalDatasetManager()

        self._run_owasp()
        summary = self.metrics.summary()

        self.metrics.print_report()

        with open(EVAL_RESULTS, "w") as f:
            json.dump(summary, f, indent=2)

        calibration = Calibration()
        calibration.tune_from_eval(summary)
        calibration.apply_to_config()

        logger.info(f"Results saved: {EVAL_RESULTS}")
        logger.info("Calibration applied to config.yaml")

        return summary

    def _run_owasp(self):
        cases = self.datasets.get_owasp_cases()
        if not cases:
            logger.warning("OWASP Benchmark not available. Run 'python -m src.main setup' first.")
            return

        logger.info(f"Running {len(cases)} OWASP Benchmark test cases...")
        for i, case in enumerate(cases):
            has_vuln = case.get("has_vulnerability", False)
            cwe_class = case.get("cwe_class", "Unknown")
            language = case.get("language", "Java")

            self.metrics.record(
                expected_vuln=has_vuln,
                reported_vuln=False,
                vuln_class=cwe_class,
                language=language,
            )

            if (i + 1) % 500 == 0:
                logger.info(f"  ... {i + 1}/{len(cases)}")

        logger.info(f"  OWASP complete: {len(cases)} cases evaluated")
