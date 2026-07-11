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
    "4d": "Blind Spot Coverage",
    5: "Memory Corruption Analysis",
    6: "Chain Synthesis",
    7: "Validation",
    8: "Anomaly Check",
    9: "Report Generation",
}

STEP_ORDER = {
    "0": 0, "1": 1, "2": 2, "2b": 3, "3": 4, "3b": 5, "4": 6,
    "4b": 7, "4c": 8, "4d": 9, "5": 10, "6": 11, "7": 12, "8": 13, "9": 14,
}

ALL_STEP_KEYS = ["0", "1", "2", "2b", "3", "3b", "4", "4b", "4c", "4d", "5", "6", "7", "8", "9"]

logger = get_logger()


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


class Orchestrator:
    def __init__(self, repo_path: Path, resume: bool = False):
        self.repo_path = repo_path.resolve()
        self.resume = resume
        self.checkpoint_key = ""
        self.checkpoint_dir: Path | None = None
        self.progress: dict[str, Any] = {}
        self.state: dict[str, Any] = {}
        self.start_time = time.time()
        self.scale_config = self._adapt_to_repo_size()

    def _adapt_to_repo_size(self) -> Any:
        try:
            from src.analysis.scaling import LargeCodebaseAdapter, ChunkedFileProcessor
            adapter = LargeCodebaseAdapter()
            processor = ChunkedFileProcessor(adapter.config)
            files = processor.list_files(self.repo_path)
            file_count = len(files)
            total_size = sum(
                f.stat().st_size for f in files
            ) / (1024 * 1024) if files else 0.0

            logger.info(f"Repository size: {file_count} files, {total_size:.1f} MB")
            return adapter.get_adaptive_config(total_size, file_count)
        except Exception:
            from src.analysis.scaling import ScaleConfig
            return ScaleConfig()

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
            ("4c", self._step4c, ["path_enum", "threat_model"], "path_analysis.json"),
            ("4d", self._step4d, ["path_analysis", "threat_model", "static_analysis"], "blindspot_findings.json"),
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
        for step_key in ALL_STEP_KEYS:
            if step_key not in steps or steps[step_key].get("status") != "done":
                return STEP_ORDER.get(step_key, 99)
        return None

    def _is_step_done(self, step_num: int | str, output_file: str) -> bool:
        step_key = str(step_num)
        steps = self.progress.get("steps", {})
        output_path = self.checkpoint_dir / output_file
        if step_key in steps and steps[step_key].get("status") == "done":
            return output_path.exists()
        if output_path.exists() and step_key not in steps:
            return True
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
            try:
                serialized = json.dumps(result, indent=2, default=str)
                _safe_write(output_path, serialized)
            except MemoryError:
                logger.warning(f"  Result too large for single JSON write ({filename}). "
                               f"Writing streaming summary instead.")
                if isinstance(result, dict):
                    summary = {}
                    for k, v in result.items():
                        if isinstance(v, list) and len(v) > 50000:
                            summary[k + "_count"] = len(v)
                            summary[k + "_sample"] = v[:1000]
                        else:
                            summary[k] = v
                    _safe_write(output_path, json.dumps(summary, indent=2, default=str))
                    logger.warning(f"  Full paths saved to: {output_path.with_suffix('.jsonl')}")
                    if "paths" in result and isinstance(result["paths"], list):
                        with open(output_path.with_suffix(".jsonl"), "w", encoding="utf-8") as f:
                            for p in result["paths"]:
                                f.write(json.dumps(p, default=str) + "\n")
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

        for sn in ALL_STEP_KEYS:
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
        self.progress = {
            "repo_path": str(self.repo_path),
            "checkpoint_key": self.checkpoint_key,
            "steps": {},
        }

        json_to_step = {
            "fingerprint": "0", "classification": "1", "deps_vulns": "2",
            "secrets": "2b", "static_analysis": "3", "code_graph": "3b",
            "threat_model": "4", "path_enum": "4b", "path_analysis": "4c",
            "blindspot_findings": "4d", "memory_findings": "5", "chains": "6",
            "validated_findings": "7", "anomaly": "8",
        }
        json_status = {}
        for f in self.checkpoint_dir.glob("*.json"):
            step_num = json_to_step.get(f.stem, f.stem)
            json_status[step_num] = "done"

        if progress_path.exists():
            try:
                lines = progress_path.read_text(encoding="utf-8").split("\n")
                in_table = False
                for line in lines:
                    if line.startswith("| ") and "|" in line[2:]:
                        in_table = True
                        parts = [p.strip() for p in line.split("|")]
                        if len(parts) >= 4:
                            step_key = parts[1]
                            status_text = parts[3] if len(parts) > 3 else "pending"
                            if step_key in ALL_STEP_KEYS:
                                status = "done" if status_text.startswith("Done") else "failed" if "FAILED" in status_text else "pending"
                                self.progress["steps"][step_key] = {
                                    "name": STEP_NAMES.get(step_key, step_key),
                                    "status": status,
                                }
                    elif in_table and not line.strip():
                        in_table = False
            except Exception:
                pass

        if not self.progress["steps"]:
            self.progress["steps"] = {k: {"status": v} for k, v in json_status.items()}

        completed = sum(1 for s in self.progress["steps"].values() if s.get("status") == "done")
        self.progress["last_updated"] = datetime.now(timezone.utc).isoformat()
        self.progress["status"] = "COMPLETE" if completed >= len(ALL_STEP_KEYS) else "IN_PROGRESS"

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
        threat_model = self.state.get("threat_model", {})
        cve_catalog = threat_model.get("cve_catalog", {})
        return run(self.repo_path, self.state.get("path_enum", {}),
                   cve_catalog=cve_catalog, checkpoint_dir=self.checkpoint_dir)

    def _step4d(self):
        from src.pipeline.step4d_blindspot import run
        threat_model = self.state.get("threat_model", {})
        path_analysis = self.state.get("path_analysis", {})
        static_analysis = self.state.get("static_analysis", {})
        file_inventory = static_analysis.get("file_inventory", {})
        return run(self.repo_path, threat_model, path_analysis, file_inventory)

    def _step5_memory(self):
        code_graph = self.state.get("code_graph", {})
        memory_findings = code_graph.get("memory_findings", [])
        if not memory_findings:
            return {"findings": memory_findings, "summary": {"total": 0, "llm_validated": 0}}

        high_sev = [f for f in memory_findings if f.get("severity") in ("CRITICAL", "HIGH")]
        if not high_sev:
            return {"findings": memory_findings, "summary": {"total": len(memory_findings), "llm_validated": 0}}

        from src.llm.client import LLMClient
        client = LLMClient()
        validated = []
        llm_checked = 0

        system = """You are a C/C++/Rust memory safety expert. Validate whether a reported memory corruption finding is a real exploitable vulnerability or a false positive.

A REAL finding means: attacker-controlled data reaches the dangerous operation, and there is no effective bounds check, overflow guard, or safe API in the immediate context.

A FALSE POSITIVE means: the operation is guarded by a nearby bounds check, the expression is provably safe, the language construct is memory-safe (Rust without unsafe), or the allocation size cannot overflow to a dangerous value.

Be brutally honest. Don't keep a finding just because the regex says so. If the context shows it's safe, mark it as FALSE_POSITIVE."""

        for f in high_sev:
            filepath = Path(self.repo_path) / f.get("file", "")
            if not filepath.exists():
                validated.append(f)
                continue
            try:
                source = filepath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                validated.append(f)
                continue

            lines = source.split("\n")
            line_num = f.get("line", 0)
            start = max(0, line_num - 8)
            end = min(len(lines), line_num + 5)
            context = "\n".join(
                f"{start + j + 1}: {l}"
                for j, l in enumerate(lines[start:end])
            )

            prompt = f"""Validate this memory corruption finding:

FINDING: {f.get('vulnerability_class', '')}
DESCRIPTION: {f.get('description', '')}
CWE: {f.get('cwe_id', '')}
CONFIDENCE: {f.get('confidence', 0)}

SOURCE CONTEXT:
{context}

Is this a REAL exploitable vulnerability or a FALSE POSITIVE? Check for bounds guards, safe APIs, language safety, and whether input is actually attacker-controlled.

Output valid JSON:
{{"verdict": "REAL" | "FALSE_POSITIVE", "confidence": 0.0-1.0, "reasoning": "why"}}"""

            try:
                result = client.chat_json(system, prompt, temperature=0.3, max_tokens=1024)
                llm_checked += 1
                if result and isinstance(result, dict):
                    v = result.get("verdict", "")
                    if v == "REAL":
                        f_copy = dict(f)
                        f_copy["llm_validated"] = True
                        f_copy["llm_confidence"] = result.get("confidence", f.get("confidence"))
                        validated.append(f_copy)
                    else:
                        logger.info(f"  LLM filtered FP: {f.get('file')}:{line_num} — {result.get('reasoning', '')[:120]}")
                else:
                    validated.append(f)
            except Exception:
                validated.append(f)

        logger.info(f"  Memory LLM validation: {llm_checked} checked, "
                    f"{len(validated)} passed ({len(high_sev) - len(validated)} FPs filtered)")

        low_sev = [f for f in memory_findings if f.get("severity") not in ("CRITICAL", "HIGH")]
        return {"findings": validated + low_sev, "summary": {"total": len(validated) + len(low_sev), "llm_validated": llm_checked}}

    def _step6_chains(self):
        from src.pipeline.step6_chains import run
        return run(self.state.get("path_analysis", {}))

    def _step7_validate(self):
        path_analysis = self.state.get("path_analysis", {})
        code_graph = self.state.get("code_graph", {})
        memory_findings = code_graph.get("memory_findings", [])

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
