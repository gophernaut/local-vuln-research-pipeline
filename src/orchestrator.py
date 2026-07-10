"""Pipeline orchestrator: runs all steps with the new exhaustive architecture.

Replaces the old LLM-batched file review with deterministic source-to-sink
path enumeration + per-path LLM validation.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from src.config import ROOT_DIR, config
from src.utils.file_utils import repo_checkpoint_key
from src.utils.logger import get_logger, log_step

CHECKPOINT_DIR = ROOT_DIR / "data" / "checkpoints"
AUTH_WARNING = """
[!] Only audit code you own or are authorized to test.
[!] Generated PoCs are for authorized security research only.
[!] Unauthorized use may violate computer fraud laws.
"""

STEP_NAMES = {
    0: "Fingerprint + SBOM",
    1: "Classification",
    2: "Dependency Vulns",
    "2b": "Secrets Scan",
    3: "Static Analysis",
    "3b": "Code Graph Construction",
    4: "Threat Model",
    "4b": "Path Enumeration",
    "4c": "Per-Path LLM Analysis",
    5: "Memory Corruption Analysis",
    6: "Chain Synthesis",
    7: "Validation",
    8: "Anomaly Check",
    9: "Report Generation",
}

STEP_ORDER = {
    "0": 0, "1": 1, "2": 2, "2b": 3, "3": 4, "3b": 5, "4": 6,
    "4b": 7, "4c": 8, "5": 9, "6": 10, "7": 11, "8": 12, "9": 13,
}


def _safe_write(path: Path, content: str):
    for attempt in range(3):
        try:
            path.write_text(content, encoding="utf-8")
            return
        except PermissionError:
            if attempt < 2:
                time.sleep(0.5 + attempt * 0.5)
            else:
                logger.warning(f"Could not write {path.name} after retries (file locked)")


def _step_key(num) -> int:
    return STEP_ORDER.get(str(num), 99)


logger = get_logger()


class Orchestrator:
    def __init__(self, repo_path: Path, resume: bool = False):
        self.repo_path = repo_path.resolve()
        self.resume = resume
        self.checkpoint_key = ""
        self.checkpoint_dir: Path | None = None
        self.progress: dict[str, Any] = {}
        self.state: dict[str, Any] = {}
        self.start_time = time.time()

    def run(self) -> int:
        print(AUTH_WARNING)
        try:
            input("Press Enter to confirm authorization, or Ctrl+C to cancel...")
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            return 1

        if not self.repo_path.exists():
            logger.error(f"Repository path does not exist: {self.repo_path}")
            return 1

        self._init_checkpoint()

        if self.resume:
            resume_step = self._find_resume_step()
            if resume_step is None:
                logger.info("No checkpoint found. Starting from beginning.")
            else:
                logger.info(f"Resuming from step {resume_step}")
        else:
            resume_step = None

        pipeline = [
            (0, self._step0, [], "fingerprint.json"),
            (1, self._step1, ["fingerprint"], "classification.json"),
            (2, self._step2, ["fingerprint"], "deps_vulns.json"),
            ("2b", self._step2b, [], "secrets.json"),
            (3, self._step3, [], "static_analysis.json"),
            ("3b", self._step3b, [], "code_graph.json"),
            (4, self._step4, ["fingerprint", "classification", "static_analysis"], "threat_model.json"),
            ("4b", self._step4b, ["code_graph"], "path_enum.json"),
            ("4c", self._step4c, ["path_enum"], "path_analysis.json"),
            (5, self._step5_memory, ["code_graph"], "memory_findings.json"),
            (6, self._step6_chains, ["path_analysis"], "chains.json"),
            (7, self._step7_validate, ["path_analysis", "memory_findings"], "validated_findings.json"),
            (8, self._step8, ["validated_findings", "static_analysis"], "anomaly.json"),
            (9, self._step9, ["code_graph", "path_enum", "path_analysis", "chains", "memory_findings"], "report.md"),
        ]

        for step_num, func, deps, output_file in pipeline:
            if resume_step is not None and _step_key(step_num) < resume_step:
                continue

            if self._is_step_done(step_num, output_file):
                logger.info(f"Step {step_num} already complete. Skipping.")
                continue

            self._check_deps(deps)

            t0 = time.time()
            logger.info(f"{'=' * 50}")
            logger.info(f"Step {step_num}: {STEP_NAMES.get(step_num, 'Unknown')}")

            try:
                result = func()
                elapsed = time.time() - t0
                self._save_checkpoint(step_num, output_file, result)
                self._update_progress(step_num, "done", elapsed)
                log_step(step_num, STEP_NAMES.get(step_num, ""), "DONE", elapsed)
            except Exception as e:
                elapsed = time.time() - t0
                logger.error(f"Step {step_num} FAILED: {e}")
                self._update_progress(step_num, "failed", elapsed)
                import traceback
                traceback.print_exc()
                return 1

        total_time = time.time() - self.start_time
        logger.info(f"\n{'=' * 50}")
        logger.info(f"Audit complete in {total_time:.1f}s")
        self._update_progress("_final", "done", total_time)

        report_path = self.checkpoint_dir / "report.md"
        if report_path.exists():
            logger.info(f"Report: {report_path}")

        return 0

    def _init_checkpoint(self):
        self.checkpoint_key = repo_checkpoint_key(self.repo_path)
        self.checkpoint_dir = CHECKPOINT_DIR / self.checkpoint_key
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        progress_path = self.checkpoint_dir / "progress.md"
        if progress_path.exists():
            self._load_progress()
        else:
            self.progress = {
                "repo_path": str(self.repo_path),
                "checkpoint_key": self.checkpoint_key,
                "started": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "status": "IN_PROGRESS",
                "steps": {},
            }

    def _find_resume_step(self) -> int | None:
        steps = self.progress.get("steps", {})
        for step_num in range(20):
            if str(step_num) not in steps or steps[str(step_num)].get("status") != "done":
                return step_num
        return None

    def _is_step_done(self, step_num: int | str, output_file: str) -> bool:
        step_key = str(step_num)
        steps = self.progress.get("steps", {})
        if step_key in steps and steps[step_key].get("status") == "done":
            output_path = self.checkpoint_dir / output_file
            return output_path.exists()
        return False

    def _check_deps(self, deps: list[str]):
        for dep in deps:
            if dep not in self.state:
                dep_file = self.checkpoint_dir / f"{dep}.json"
                if dep_file.exists():
                    with open(dep_file) as f:
                        self.state[dep] = json.load(f)
                else:
                    raise RuntimeError(f"Missing dependency: {dep}")

    def _save_checkpoint(self, step_num: int | str, filename: str, result: Any):
        output_path = self.checkpoint_dir / filename
        if filename.endswith(".json"):
            _safe_write(output_path, json.dumps(result, indent=2, default=str))
        elif isinstance(result, str):
            _safe_write(output_path, result)

        self.state[str(step_num)] = result
        self.state[
            filename.replace(".json", "").replace(".md", "")
        ] = result

    def _update_progress(self, step_num: int | str, status: str, duration: float):
        step_key = str(step_num)
        steps = self.progress.setdefault("steps", {})
        steps[step_key] = {
            "name": STEP_NAMES.get(step_num, str(step_num)),
            "status": status,
            "duration_seconds": round(duration, 1),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        self.progress["last_updated"] = datetime.now(timezone.utc).isoformat()
        self.progress["status"] = "DONE" if step_num == "_final" else "IN_PROGRESS"

        self._write_progress_md()

    def _write_progress_md(self):
        steps = self.progress.get("steps", {})
        lines = [
            f"# Audit Progress: {self.repo_path}",
            "",
            f"**Repo hash**: {self.checkpoint_key[:16]}...",
            f"**Started**: {self.progress.get('started', '?')}",
            f"**Last updated**: {self.progress.get('last_updated', '?')}",
            f"**Status**: {self.progress.get('status', '?')}",
            "",
            "| Step | Name | Status | Duration |",
            "|------|------|--------|----------|",
        ]

        for sn in ["0", "1", "2", "2b", "3", "3b", "4", "4b", "4c", "5", "6", "7", "8", "9"]:
            step = steps.get(sn, {})
            name = step.get("name", STEP_NAMES.get(sn, "?"))
            status = step.get("status", "pending")
            dur = step.get("duration_seconds", 0)

            icons = {"done": "Done", "failed": "FAILED", "pending": "Pending", "running": "Running..."}
            icon = icons.get(status, status)

            if status == "done":
                lines.append(f"| {sn} | {name} | {icon} | {dur:.1f}s |")
            else:
                lines.append(f"| {sn} | {name} | {icon} | - |")

        lines.append("")
        progress_md = "\n".join(lines)
        _safe_write(self.checkpoint_dir / "progress.md", progress_md)

    def _load_progress(self):
        progress_path = self.checkpoint_dir / "progress.md"
        if progress_path.exists():
            self.progress = {
                "repo_path": str(self.repo_path),
                "checkpoint_key": self.checkpoint_key,
                "steps": {},
            }

            for f in self.checkpoint_dir.glob("*.json"):
                step_name = f.stem
                self.progress["steps"][step_name] = {
                    "status": "done",
                }

    def _step0(self):
        from src.pipeline.step0_fingerprint import run
        return run(self.repo_path)

    def _step1(self):
        fp = self.state.get("fingerprint", {})
        from src.pipeline.step1_classify import run
        return run(fp)

    def _step2(self):
        fp = self.state.get("fingerprint", {})
        from src.pipeline.step2_deps import run
        return run(fp)

    def _step2b(self):
        from src.pipeline.step2_secrets import run
        return run(self.repo_path)

    def _step3(self):
        from src.pipeline.step3_static import run
        result = run(self.repo_path)
        return result

    def _step3b(self):
        from src.pipeline.step3b_codegraph import run
        return run(self.repo_path)

    def _step4(self):
        fp = self.state.get("fingerprint", {})
        cl = self.state.get("classification", {})
        sa = self.state.get("static_analysis", {})
        from src.pipeline.step4_threat_model import run
        return run(self.repo_path, fp, cl, sa)

    def _step4b(self):
        from src.pipeline.step4b_path_enum import run
        return run(self.repo_path, self.state.get("code_graph", {}))

    def _step4c(self):
        from src.pipeline.step4c_path_analyze import run
        return run(self.repo_path, self.state.get("path_enum", {}))

    def _step5_memory(self):
        code_graph = self.state.get("code_graph", {})
        memory_findings = code_graph.get("memory_findings", [])
        return {"findings": memory_findings, "summary": {"total": len(memory_findings)}}

    def _step6_chains(self):
        from src.pipeline.step7_chains import run
        return run(self.state.get("path_analysis", {}))

    def _step7_validate(self):
        path_analysis = self.state.get("path_analysis", {})
        memory_findings = self.state.get("memory_findings", {}).get("findings", [])

        verified = [r for r in path_analysis.get("results", [])
                    if r.get("verdict") == "VERIFIED_EXPLOITABLE"]
        memory_verified = [
            f for f in memory_findings
            if f.get("severity") in ("CRITICAL", "HIGH") and f.get("confidence", 0) >= 0.6
        ]

        return {
            "verified_findings": verified,
            "memory_findings": memory_verified,
            "summary": {
                "total_verified": len(verified) + len(memory_verified),
                "verified_paths": len(verified),
                "verified_memory": len(memory_verified),
            },
        }

    def _step8(self):
        from src.pipeline.step8_anomaly import run
        valid = self.state.get("validated_findings", {})
        sa = self.state.get("static_analysis", {})
        return run(valid, sa, self.repo_path)

    def _step9(self):
        from src.pipeline.step9_report import run
        code_graph = self.state.get("code_graph", {})
        path_data = self.state.get("path_enum", {})
        path_analysis = self.state.get("path_analysis", {})
        chain_data = self.state.get("chains", {})
        memory_findings = code_graph.get("memory_findings", [])

        output_path = self.checkpoint_dir / "report.md"
        return run(code_graph, path_data, path_analysis, chain_data,
                   self.repo_path, output_path)
