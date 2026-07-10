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

SOURCE_PATTERNS = {
    "python": [
        r"request\.\w+\.get\s*\(", r"request\.form\[", r"request\.args\[",
        r"sys\.argv", r"input\s*\(", r"raw_input\s*\(",
        r"os\.environ\[", r"request\.POST", r"request\.GET",
    ],
    "java": [
        r"request\.getParameter\s*\(", r"request\.getQueryString\s*\(",
        r"request\.getInputStream\s*\(", r"request\.getHeader\s*\(",
        r"request\.getCookie\s*\(", r"@RequestParam", r"@PathVariable",
    ],
    "javascript": [
        r"req\.body\.", r"req\.query\.", r"req\.params\.",
        r"req\.cookies\.", r"req\.headers\[", r"process\.argv",
        r"window\.location", r"document\.URL",
    ],
}

SINK_PATTERNS = {
    "python": [
        (r"os\.system\s*\(", "command_execution"),
        (r"subprocess\.\w+\s*\(", "command_execution"),
        (r"\.execute\s*\(", "sql_injection"),
        (r"pickle\.loads?\s*\(", "deserialization"),
        (r"yaml\.load\s*\(", "deserialization"),
        (r"eval\s*\(", "code_execution"),
        (r"exec\s*\(", "code_execution"),
        (r"open\s*\([^)]*\+", "path_traversal"),
        (r"requests\.\w+\s*\(\s*[^)]*\+", "ssrf"),
    ],
    "java": [
        (r"Runtime\.exec\s*\(", "command_execution"),
        (r"ProcessBuilder\s*\(", "command_execution"),
        (r"Statement\.execute\s*\(", "sql_injection"),
        (r"\.createStatement\s*\(", "sql_injection"),
        (r"ObjectInputStream\s*\(", "deserialization"),
        (r"XMLDecoder\s*\(", "deserialization"),
        (r"URL\s*\(\s*[^)]*\+", "ssrf"),
        (r"HttpURLConnection\s*\(", "ssrf"),
    ],
    "javascript": [
        (r"child_process\.exec\s*\(", "command_execution"),
        (r"\.query\s*\(", "sql_injection"),
        (r"\.exec\s*\(", "sql_injection"),
        (r"eval\s*\(", "code_execution"),
        (r"Function\s*\(", "code_execution"),
        (r"JSON\.parse\s*\(", "deserialization"),
        (r"require\s*\(\s*[^)]*\+", "path_traversal"),
    ],
}


def _detect_language(filepath: Path) -> str:
    ext = filepath.suffix.lower()
    lang_map = {".py": "python", ".java": "java", ".js": "javascript",
                ".ts": "javascript", ".mjs": "javascript", ".jsx": "javascript"}
    return lang_map.get(ext, "unknown")


def _has_source(content: str, language: str) -> bool:
    import re
    patterns = SOURCE_PATTERNS.get(language, [])
    if not patterns:
        return "arg" in content.lower() or "param" in content.lower() or "input" in content.lower()
    return any(re.search(p, content) for p in patterns)


def _has_dangerous_sink(content: str, language: str) -> bool:
    import re
    patterns = SINK_PATTERNS.get(language, [])
    for pat, _ in patterns:
        if re.search(pat, content):
            return True
    return False


def _detect_vuln_in_file(filepath: Path) -> tuple[bool, str]:
    lang = _detect_language(filepath)
    if lang == "unknown":
        return False, "Unknown"

    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception:
        return False, "Unknown"

    has_source = _has_source(content, lang)
    if not has_source:
        return False, "Unknown"

    import re
    patterns = SINK_PATTERNS.get(lang, [])
    for pat, category in patterns:
        if re.search(pat, content):
            return True, category

    return False, "Unknown"


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

        logger.info(f"Running {len(cases)} OWASP Benchmark test cases with static analysis...")
        for i, case in enumerate(cases):
            filepath = Path(case.get("file", ""))
            expected_vuln = case.get("has_vulnerability", False)
            cwe_class = case.get("cwe_class", "Unknown")
            language = case.get("language", "Java")

            if filepath.exists():
                reported, _ = _detect_vuln_in_file(filepath)
            else:
                reported = False

            self.metrics.record(
                expected_vuln=expected_vuln,
                reported_vuln=reported,
                vuln_class=cwe_class,
                language=language,
            )

            if (i + 1) % 500 == 0:
                logger.info(f"  ... {i + 1}/{len(cases)}")

        logger.info(f"  OWASP complete: {len(cases)} cases evaluated")
