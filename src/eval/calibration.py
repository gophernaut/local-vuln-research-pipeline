"""Threshold calibration from evaluation results.

Tunes: hypothesis confidence cutoff, anomaly ratio, EPSS minimum.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.config import ROOT_DIR
from src.utils.logger import get_logger

CALIBRATION_PATH = ROOT_DIR / "data" / "calibration.json"

logger = get_logger()


class Calibration:
    def __init__(self):
        self.data: dict[str, Any] = self._load()

    def tune_from_eval(self, eval_summary: dict[str, Any]):
        global_metrics = eval_summary.get("global", {})
        precision = global_metrics.get("precision", 0)
        recall = global_metrics.get("recall", 0)

        confidence_cutoff = self._calc_confidence_cutoff(precision, recall)
        self.data["confidence_cutoff"] = confidence_cutoff

        epss_cutoff = self._calc_epss_cutoff(eval_summary)
        self.data["epss_min_score"] = epss_cutoff

        logger.info(f"Calibration: confidence_cutoff={confidence_cutoff:.2f}, epss_min={epss_cutoff:.3f}")

        self._save()

    def _calc_confidence_cutoff(self, precision: float, recall: float) -> float:
        if precision < 0.3:
            return 0.75
        elif precision < 0.5:
            return 0.65
        elif precision < 0.7:
            return 0.55
        else:
            return 0.45

    def _calc_epss_cutoff(self, eval_summary: dict[str, Any]) -> float:
        deps_eval = eval_summary.get("dependency_vulns", {})
        deps_precision = deps_eval.get("precision", 0.5)
        if deps_precision > 0.8:
            return 0.01
        elif deps_precision > 0.5:
            return 0.05
        else:
            return 0.10

    def apply_to_config(self):
        from src.config import config
        if "confidence_cutoff" in self.data:
            config.update(
                "thresholds.hypothesis_confidence_cutoff",
                self.data["confidence_cutoff"]
            )
        if "epss_min_score" in self.data:
            config.update(
                "thresholds.epss_min_score",
                self.data["epss_min_score"]
            )

    def _save(self):
        CALIBRATION_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CALIBRATION_PATH, "w") as f:
            json.dump(self.data, f, indent=2)

    def _load(self) -> dict[str, Any]:
        if CALIBRATION_PATH.exists():
            with open(CALIBRATION_PATH) as f:
                return json.load(f)
        return {}
