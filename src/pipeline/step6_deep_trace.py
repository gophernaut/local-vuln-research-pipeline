"""Step 6: Iterative deep code tracing.

LLM traces attack path. If it needs a file not yet provided, it requests it.
System loads it and continues. Repeats until trace is complete or dead end reached.
Per-hypothesis checkpointing for long repos (kernel, VS Code, etc.).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.llm.client import LLMClient
from src.llm.prompts import deep_trace_system
from src.llm.context import ContextManager
from src.config import config, ROOT_DIR
from src.utils.logger import get_logger

logger = get_logger()

_context = config.get("server.context_length", 32768)
MAX_CODE = max(30000, int((_context - 8000) * 3.5))

MAX_ITERATIONS = 5
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv",
              "target", "build", "dist", "vendor", ".next", ".nuxt",
              ".idea", ".vscode", "bin", "obj", "Debug", "Release"}


def run(
    repo_path: Path,
    classification: dict[str, Any],
    hypotheses: list[dict[str, Any]],
    static_analysis: dict[str, Any],
    checkpoint_dir: Path | None = None,
) -> list[dict[str, Any]]:
    logger.info("Step 6: Iterative deep code tracing...")

    if not hypotheses:
        logger.info("  No hypotheses to trace.")
        return []

    client = LLMClient()
    ctx = ContextManager()

    methodology = _methodology_for(classification.get("primary_class", "general_application"))
    system = deep_trace_system(methodology)

    results = []
    max_trace = min(len(hypotheses), 10)

    for i, hyp in enumerate(hypotheses[:max_trace]):
        hyp_class = hyp.get("vulnerability_class", "?")
        hyp_id = f"hyp_{i}"
        logger.info(f"  [{i + 1}/{min(len(hypotheses), max_trace)}] {hyp_class}")

        # Try resume from per-hypothesis checkpoint
        trace_result = _load_hyp_checkpoint(checkpoint_dir, hyp_id) if checkpoint_dir else None
        iteration_start = trace_result.get("_iteration", 0) if trace_result else 0
        loaded_files: set[str] = set(trace_result.get("_loaded_files", []) if trace_result else [])

        if trace_result and trace_result.get("exploitable") is not None:
            logger.info(f"    Resumed from checkpoint: exploitable={trace_result.get('exploitable')}")
            trace_result["hypothesis_index"] = i
            trace_result["hypothesis_class"] = hyp_class
            trace_result["hypothesis_confidence"] = hyp.get("confidence")
            results.append(trace_result)
            continue

        for iteration in range(iteration_start, MAX_ITERATIONS):
            if iteration == 0 and not trace_result:
                initial_files = _find_initial_files(repo_path, hyp, static_analysis)
                for fp in initial_files:
                    loaded_files.add(str(fp.relative_to(repo_path)))
                code_bundle = _read_files(initial_files, repo_path, loaded_files)
                user = _build_initial_prompt(hyp, code_bundle)
            else:
                missing_files = _resolve_requested_files(repo_path, trace_result or {}, loaded_files)
                if not missing_files:
                    break
                logger.info(f"    Iter {iteration + 1}: loading {len(missing_files)} requested files")
                code_bundle = _read_files(missing_files, repo_path, loaded_files)
                user = (
                    "CONTINUE tracing. New files loaded:\n\n"
                    f"{_assemble_code(loaded_files, code_bundle)}\n\n"
                    "Continue the trace. Output same JSON format with 'needs_more_files': true if you still need files."
                )

            alloc = ctx.allocate(system, code_files={})
            full_prompt = f"{user}\n\n=== Source Code ===\n{_assemble_code(loaded_files, code_bundle)}"

            try:
                result = client.chat_json(system, full_prompt, max_tokens=4096, temperature=0.3)
            except Exception as e:
                logger.warning(f"    Trace error: {e}")
                result = {"error": str(e), "reachable": False, "exploitable": False}

            if not result:
                result = {"reachable": False, "exploitable": False}

            trace_result = result
            trace_result["_iteration"] = iteration
            trace_result["_loaded_files"] = list(loaded_files)

            if iteration == 0:
                trace_result["hypothesis_index"] = i
                trace_result["hypothesis_class"] = hyp_class
                trace_result["hypothesis_confidence"] = hyp.get("confidence")
                trace_result["entry_point_type"] = hyp.get("entry_point_type", "")
                trace_result["requires_authentication"] = hyp.get("requires_authentication", False)

            # Save checkpoint after each iteration
            if checkpoint_dir:
                _save_hyp_checkpoint(checkpoint_dir, hyp_id, trace_result)

            if _needs_more_files(result):
                continue
            else:
                break

        if trace_result:
            if trace_result.get("exploitable") and trace_result.get("reachable"):
                logger.info(f"    EXPLOITABLE — {trace_result.get('summary', '')[:120]}")
            elif trace_result.get("blocked_by"):
                logger.info(f"    BLOCKED: {trace_result['blocked_by'][:120]}")
            else:
                logger.info(f"    Result: {trace_result.get('summary', '')[:120]}")
            trace_result["files_traced"] = list(loaded_files)
            results.append(trace_result)
        else:
            results.append({"hypothesis_index": i, "error": "no result", "reachable": False, "exploitable": False})

        ctx.reset_dedup()

    return results


def _save_hyp_checkpoint(checkpoint_dir: Path, hyp_id: str, result: dict):
    if not checkpoint_dir:
        return
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    path = checkpoint_dir / f"trace_{hyp_id}.json"
    try:
        with open(path, "w") as f:
            json.dump(result, f, indent=2, default=str)
    except Exception:
        pass


def _load_hyp_checkpoint(checkpoint_dir: Path, hyp_id: str) -> dict | None:
    if not checkpoint_dir:
        return None
    path = checkpoint_dir / f"trace_{hyp_id}.json"
    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    return None


def _needs_more_files(result: dict) -> bool:
    need = result.get("needs_more_files", False)
    if need:
        return True
    trace = result.get("trace", [])
    for hop in trace:
        desc = str(hop.get("description", "")).lower()
        if "need" in desc and ("file" in desc or "code" in desc or "source" in desc):
            return True
    return False


def _resolve_requested_files(
    repo_path: Path, result: dict, loaded: set[str]
) -> list[Path]:
    files = set()
    for field in ["missing_file", "needs_file", "_requested_files"]:
        val = result.get(field, "")
        if isinstance(val, list):
            for v in val:
                for fp in repo_path.rglob(str(v)):
                    if fp.is_file() and not _skip(fp):
                        files.add(fp)
        elif val:
            for fp in repo_path.rglob(str(val)):
                if fp.is_file() and not _skip(fp):
                    files.add(fp)

    trace = result.get("trace", [])
    for hop in trace:
        if isinstance(hop, dict):
            for v in hop.values():
                for fp in repo_path.rglob(str(v)):
                    if fp.is_file() and not _skip(fp):
                        files.add(fp)

    # Fallback: search for file paths mentioned in trace descriptions
    for hop in trace:
        desc = str(hop.get("description", "")) + " " + str(hop.get("file", ""))
        import re as _re
        for match in _re.finditer(r'[\w/\-]+\.\w+', desc):
            name = match.group(0)
            for fp in repo_path.rglob(name):
                if fp.is_file() and not _skip(fp):
                    files.add(fp)

    return [f for f in files if str(f.relative_to(repo_path)) not in loaded][:10]


def _find_initial_files(
    repo_path: Path, hyp: dict[str, Any], static_analysis: dict[str, Any]
) -> list[Path]:
    files: set[Path] = set()
    loaded_names: set[str] = set()

    def _try_add(fp: Path):
        if fp.exists() and fp.is_file() and not _skip(fp):
            rel = str(fp.relative_to(repo_path))
            if rel not in loaded_names:
                files.add(fp)
                loaded_names.add(rel)

    # PRIORITY 1: Exact file references from the hypothesis
    for field in ["component", "entry_point", "sink"]:
        val = str(hyp.get(field, ""))
        for part in val.split():
            part = part.strip(".,;:()[]{}'\"")
            if "." in part and len(part) > 3:
                for fp in repo_path.rglob(part):
                    _try_add(fp)
                for fp in repo_path.rglob(f"**/{part}"):
                    _try_add(fp)

    # PRIORITY 2: Files referenced in trace hops
    for hop in hyp.get("trace_hops", []):
        fname = hop.get("file", "")
        if fname:
            for fp in repo_path.rglob(fname):
                _try_add(fp)
            for fp in repo_path.rglob(f"**/{Path(fname).name}"):
                _try_add(fp)

    # PRIORITY 3: Files containing the component name
    comp = hyp.get("component", "")
    for part in comp.replace(":", "/").replace("\\", "/").split("/"):
        part = part.strip().rstrip(".)]}>")
        name_part = Path(part).name if "/" in part or "\\" in part else part
        if len(name_part) > 3 and name_part not in loaded_names:
            for fp in repo_path.rglob(f"*{name_part}*"):
                _try_add(fp)

    # PRIORITY 4: Top sink files from static analysis
    sink_count: dict[str, int] = {}
    for s in static_analysis.get("_sink_matches", []):
        sink_count[s["file"]] = sink_count.get(s["file"], 0) + 1
    for fname in sorted(sink_count, key=lambda x: -sink_count[x])[:10]:
        _try_add(repo_path / fname)

    # PRIORITY 5: Entry point files
    entry_names = ["Program.cs", "main.c", "main.cpp", "main.go", "main.rs",
                   "main.ps1", "index.js", "app.py"]
    for name in entry_names:
        for fp in repo_path.rglob(name):
            _try_add(fp)

    return list(files)[:30]


def _read_files(paths: list[Path], repo_root: Path, loaded: set[str]) -> dict[str, str]:
    code_files: dict[str, str] = {}
    total = 0
    for f in paths:
        if total > MAX_CODE:
            break
        rel = str(f.relative_to(repo_root))
        if rel in loaded:
            continue
        try:
            content = f.read_text(errors="replace")
            code_files[rel] = content
            loaded.add(rel)
            total += len(content)
        except Exception:
            continue
    return code_files


def _assemble_code(loaded: set[str], bundle: dict[str, str]) -> str:
    parts = []
    for fname in sorted(loaded):
        if fname in bundle:
            parts.append(f"--- {fname} ---\n{bundle[fname]}\n")
    return "\n".join(parts) if parts else "(no code available)"


def _build_initial_prompt(hyp: dict, code_bundle: dict) -> str:
    return (
        f"Trace the full exploit path:\n\n"
        f"Class: {hyp.get('vulnerability_class', '?')}\n"
        f"Component: {hyp.get('component', '?')}\n"
        f"Entry: {hyp.get('entry_point', '?')} [{hyp.get('entry_point_type', '?')}]\n"
        f"Sink: {hyp.get('sink', '?')}\n"
        f"Preconditions: {hyp.get('preconditions', [])}\n"
        f"Impact: {hyp.get('expected_impact', '?')}\n\n"
        f"REQUIREMENTS:\n"
        f"1. Each hop MUST cite exact file:line from provided code\n"
        f"2. If you NEED a file not provided, include 'needs_more_files: true' and list filenames\n"
        f"3. Check ALL mitigations: sanitization, auth, bounds, validation, parameterization"
    )


def _methodology_for(primary: str) -> str:
    """Universal methodology — no shortcutting by classification. Check everything."""
    return (
        "UNIVERSAL METHODOLOGY — check ALL of the following, regardless of target type:\n\n"
        "COMMAND INJECTION: Trace user input to Process.Start, PowerShell.Create, system(), exec(). "
        "Check if any shell metacharacters survive sanitization. Check argument vs command injection separately.\n\n"
        "PATH TRAVERSAL: Trace user input to File.Read/Write, Directory operations, Path.Combine. "
        "Check canonicalization, symlink races, zip-slip, alternate data streams.\n\n"
        "DESERIALIZATION: Find all deserialization points. Trace type resolution — can the attacker "
        "control the type? Check SerializationBinder, TypeNameHandling, allowed types.\n\n"
        "CODE INJECTION: Find eval(), Invoke-Expression, ScriptBlock.Create, AddScript, expression languages. "
        "Check if any part of the evaluated code is attacker-controlled.\n\n"
        "AUTH BYPASS: Trace auth middleware, session validation, JWT verification, role checks. "
        "Look for missing checks on specific endpoints, direct object references, privilege escalation paths.\n\n"
        "SSRF: Find HttpClient/WebRequest with dynamic URLs. Check URL validation — can attacker "
        "point it at internal services, cloud metadata, file:// schemes?\n\n"
        "SQL/NoSQL INJECTION: Find all database queries. Check parameterization vs concatenation. "
        "For NoSQL, check $where, $expr, and other evaluation operators.\n\n"
        "RACE CONDITIONS: Find shared mutable state (static fields, singletons, caches). "
        "Check locking, TOCTOU between check and use, multi-threaded access patterns.\n\n"
        "CRYPTO: Find hardcoded keys, weak algorithms (MD5/SHA1/DES/RC4), predictable IVs, "
        "missing MAC/signature verification, key leakage through errors or timing.\n\n"
        "MEMORY (if C/C++/unsafe Rust): Check all allocations, buffer accesses, pointer arithmetic. "
        "Look for missing bounds checks, use-after-free, double-free, integer overflow.\n\n"
        "INFORMATION DISCLOSURE: Check error messages, debug endpoints, stack traces in responses, "
        "path disclosure, timing side channels, sensitive data in logs.\n\n"
        "LOGIC FLAWS: Check business logic for exploitable edge cases — negative quantities, "
        "integer overflow in calculations, type confusion, state machine bypass, race windows.\n\n"
        "Trace the FULL data flow from attacker-controlled entry point through EVERY "
        "function call, variable assignment, and transformation to the dangerous sink. "
        "At each step, check: is there a validator? Can it be bypassed? Is there an indirect path?"
    )


def _skip(p: Path) -> bool:
    return any(d in p.parts for d in SKIP_DIRS)
