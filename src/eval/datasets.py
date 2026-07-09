"""Evaluation datasets — known-vulnerable corpora for pipeline calibration.

Sources:
- OWASP Benchmark: 2,740 Java synthetic test cases
- Juliet Test Suite: 81K+ C/C++/Java test cases
- CVEfixes: Real CVE fix commit pairs (multi-language)
- Big-Vul: 375K+ vulnerable C/C++ code slices
- DiverseVul: 18K+ cross-language CVE patches
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from src.config import ROOT_DIR
from src.utils.logger import get_logger

EVAL_DIR = ROOT_DIR / "data" / "eval"

logger = get_logger()

DATASET_SOURCES = {
    "owasp_benchmark": {
        "url": "https://github.com/OWASP-Benchmark/BenchmarkJava.git",
        "type": "git",
        "languages": ["Java"],
        "vuln_classes": [
            "cmdi", "crypto", "hash", "ldapi", "pathtraver", "securecookie",
            "sqli", "trustbound", "weakrand", "xpathi", "xss",
        ],
        "test_count": 2740,
    },
    "cvefixes": {
        "url": "https://github.com/secureIT-project/CVEfixes.git",
        "type": "git",
        "languages": ["Python", "JavaScript", "PHP", "Ruby", "Java", "C", "C++"],
        "description": "CVE fix commit pairs for real-world vulnerabilities",
    },
    "diverse_vul": {
        "url": "https://github.com/wagner-group/diversevul.git",
        "type": "git",
        "languages": ["Python", "JavaScript", "Go", "C", "C++"],
        "description": "Cross-language CVE patches with commit-level granularity",
    },
}


class EvalDatasetManager:
    def __init__(self, data_dir: Path | None = None):
        self.data_dir = data_dir or EVAL_DIR
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def download_all(self):
        logger.info("Downloading evaluation datasets...")
        for name, info in DATASET_SOURCES.items():
            self._download_dataset(name, info)

    def _download_dataset(self, name: str, info: dict[str, Any]):
        target = self.data_dir / name
        if target.exists():
            logger.info(f"  {name}: already exists at {target}")
            return

        url = info["url"]
        logger.info(f"  {name}: cloning from {url}")

        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", url, str(target)],
                capture_output=True, text=True, timeout=600,
                check=True,
            )
            logger.info(f"  {name}: downloaded successfully")
        except subprocess.CalledProcessError as e:
            logger.warning(f"  {name}: clone failed: {e.stderr[:200]}")
        except FileNotFoundError:
            logger.warning(f"  {name}: git not found. Skipping.")
        except Exception as e:
            logger.warning(f"  {name}: download failed: {e}")

    def get_owasp_cases(self) -> list[dict[str, Any]]:
        target = self.data_dir / "owasp_benchmark"
        if not target.exists():
            return []

        cases = []
        src_dir = target / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
        if not src_dir.exists():
            return []

        for java_file in src_dir.rglob("*.java"):
            content = java_file.read_text(errors="replace")
            is_vuln = "true" in content.lower() or "benchmarktest" in java_file.stem.lower()

            cwe = None
            for cwe_class in DATASET_SOURCES["owasp_benchmark"]["vuln_classes"]:
                if cwe_class.lower() in str(java_file).lower():
                    cwe = cwe_class.upper()
                    break

            cases.append({
                "file": str(java_file.relative_to(target)),
                "language": "Java",
                "has_vulnerability": is_vuln,
                "cwe_class": cwe,
                "source": "owasp_benchmark",
            })

        logger.info(f"  OWASP Benchmark: {len(cases)} test cases loaded")
        return cases

    def get_cvefixes_pairs(self) -> list[dict[str, Any]]:
        target = self.data_dir / "cvefixes"
        if not target.exists():
            return []

        pairs = []

        commits_dir = target / "commits"
        if commits_dir.exists():
            for commit_file in commits_dir.glob("*.csv"):
                try:
                    import csv
                    with open(commit_file) as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            pairs.append({
                                "cve_id": row.get("cve_id", ""),
                                "repo_url": row.get("repo_url", ""),
                                "vulnerable_commit": row.get("commit_hash", ""),
                                "language": row.get("lang", ""),
                                "source": "cvefixes",
                            })
                except Exception:
                    continue

        logger.info(f"  CVEfixes: {len(pairs)} fix pairs loaded")
        return pairs

    def list_available(self) -> dict[str, Any]:
        available = {}
        for name in DATASET_SOURCES:
            target = self.data_dir / name
            available[name] = target.exists()
        return available
