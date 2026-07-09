"""LLM guard — prompt injection detection + anomaly monitoring.

- Injects guard instructions into every system prompt
- Detects anomalies between LLM findings and deterministic SAST results
- Triggers re-analysis with stripped comments if injection suspected
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from src.config import ROOT_DIR, config
from src.utils.logger import get_logger

logger = get_logger()

ANOMALY_BASELINE = ROOT_DIR / "data" / "anomaly_baseline.json"


class InjectionGuard:
    def __init__(self):
        self.baseline = self._load_baseline()

    def check_anomaly(
        self,
        llm_findings_count: int,
        semgrep_hits_count: int,
    ) -> dict[str, Any]:
        if semgrep_hits_count == 0:
            return {
                "ratio": 0,
                "within_normal": True,
                "suspicious": False,
                "recommendation": "none",
            }

        ratio = llm_findings_count / semgrep_hits_count

        if not self.baseline:
            # No baseline yet - can't detect anomalies
            return {
                "ratio": ratio,
                "within_normal": True,
                "suspicious": False,
                "recommendation": "none",
            }

        vuln_class_stats = self.baseline.get("per_class", {})
        all_ratios = []
        for stats in vuln_class_stats.values():
            all_ratios.extend(stats.get("ratios", []))

        if not all_ratios:
            return {"ratio": ratio, "within_normal": True, "suspicious": False, "recommendation": "none"}

        import statistics
        mu = statistics.mean(all_ratios)
        sigma = statistics.stdev(all_ratios) if len(all_ratios) > 1 else mu * 0.5
        threshold = mu - (config.get("thresholds.anomaly_ratio_sigma", 3.0) * sigma)

        within_normal = ratio >= threshold
        suspicious = not within_normal

        return {
            "ratio": round(ratio, 4),
            "mean": round(mu, 4),
            "sigma": round(sigma, 4),
            "threshold": round(threshold, 4),
            "within_normal": within_normal,
            "suspicious": suspicious,
            "recommendation": "re-run without comments" if suspicious else "none",
        }

    def strip_comments(self, repo_path: Path) -> dict[str, str]:
        stripped = {}
        comment_patterns = {
            ".py": [(r"#.*$", ""), (r'"""(?:.|\n)*?"""', ""), (r"'''(?:.|\n)*?'''", "")],
            ".js": [(r"//.*$", ""), (r"/\*(?:.|\n)*?\*/", "")],
            ".ts": [(r"//.*$", ""), (r"/\*(?:.|\n)*?\*/", "")],
            ".java": [(r"//.*$", ""), (r"/\*(?:.|\n)*?\*/", "")],
            ".c": [(r"//.*$", ""), (r"/\*(?:.|\n)*?\*/", "")],
            ".cpp": [(r"//.*$", ""), (r"/\*(?:.|\n)*?\*/", "")],
            ".go": [(r"//.*$", ""), (r"/\*(?:.|\n)*?\*/", "")],
            ".rb": [(r"#.*$", ""), (r"=begin(?:.|\n)*?=end", "")],
        }

        text_exts = set(comment_patterns.keys())
        for filepath in repo_path.rglob("*"):
            if filepath.suffix not in text_exts:
                continue
            try:
                with open(filepath, encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue

            for pattern, replacement in comment_patterns.get(filepath.suffix, []):
                content = re.sub(pattern, replacement, content, flags=re.MULTILINE)

            stripped[str(filepath)] = content

        return stripped

    def save_baseline(self, stats: dict[str, Any]):
        self.baseline = stats
        ANOMALY_BASELINE.parent.mkdir(parents=True, exist_ok=True)
        with open(ANOMALY_BASELINE, "w") as f:
            json.dump(stats, f, indent=2)
        logger.info(f"Anomaly baseline saved: {len(stats.get('per_class', {}))} vuln classes")

    def _load_baseline(self) -> dict[str, Any]:
        if ANOMALY_BASELINE.exists():
            with open(ANOMALY_BASELINE) as f:
                return json.load(f)
        return {}
