# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

LVRP (Local Vuln Research Pipeline) is a local-first, LLM-driven whitebox vulnerability research tool. It builds a deterministic code graph (AST parse + call graph + source/sink/sanitizer tagging) for a target repository, exhaustively enumerates every source-to-sink path through that graph, and uses a locally-hosted LLM (served via `llama.cpp`, OpenAI-compatible API) only to validate exploitability of pre-traced paths — never for discovery. Output is a Markdown report with PoCs, root causes, and exploit chains.

This repo is the tool itself, not a target being audited. There is no local test suite (no pytest/unit tests) — correctness is checked via `python -m src.main eval` against known-vuln corpora (OWASP Benchmark, Juliet, CVEfixes, etc.) and via `python -m src.main estimate <repo>` / a real `run_audit.py` run against a sample target.

## Commands

```bash
# Install deps
pip install -r requirements.txt

# Start the local LLM server (reads model path from config.yaml)
python start_server.py
python start_server.py --no-speculative      # disable draft-model speculative decoding

# One-time setup instructions (model download, DB init)
python -m src.main setup

# Benchmark the running server to tune AUTO values in config.yaml (writes data/benchmark_results.json)
python run_benchmark.py                       # or: python -m src.main benchmark

# Download/refresh the CVE knowledge base (NVD + EPSS + KEV, ~45 min, needs NVD_API_KEY)
python -m src.main update-cve

# Estimate scope/time for a target before running a full audit
python -m src.main estimate /path/to/target-repo

# Run a full audit against a target repo (creates data/checkpoints/<hash>/)
python run_audit.py /path/to/target-repo
python run_audit.py /path/to/target-repo --resume    # resume from last completed step/path

# Run the evaluation harness against known-vuln corpora, then auto-calibrate thresholds
python -m src.main eval
```

There is no lint/format/test tooling configured in this repo (no pytest config, no ruff/flake8/black/mypy config) — don't assume one exists.

## Architecture

### The core idea: deterministic graph, LLM only validates

Everything upstream of LLM calls is deterministic Python analysis on an AST/call graph. The LLM is invoked only in steps 4c (per-path exploitability), 4d (blind-spot file review), and part of step 5 (memory-finding false-positive filtering). This split matters when debugging: if a bug is about *what paths exist*, look in `src/analysis/` (graph/taint/enum code); if it's about *how a path is judged*, look in `src/llm/` and the relevant `step4*` file.

### Pipeline (`src/orchestrator.py`)

`Orchestrator.run()` executes a fixed, ordered list of steps (`0, 1, 2, 2b, 3, 3b, 4, 4b, 4c, 4d, 5, 6, 7, 8, 9`), each implemented as a `run(...)` function in `src/pipeline/step*.py`. Key mechanics:

- **Checkpointing is step-granular and file-based.** Every step writes a JSON (or `.md` for the final report) into `data/checkpoints/<repo-hash>/`. `--resume` re-derives progress from `progress.md` + presence of the JSON files and skips any step already done — there's no in-memory-only state that survives a restart.
- **Step 4c has an additional *intra-step* checkpoint**: `path_analysis_progress.jsonl`, appended one line per analyzed path. This is what makes `--resume` cheap even mid-way through a long LLM-analysis run — it does not restart step 4c from path 0.
- **`self.state` is a dict of step outputs**, keyed by both the JSON filename stem and step number; later steps declare `deps` (e.g. step 4c depends on `["path_enum", "threat_model"]`) and `_check_deps` lazily loads a dep's JSON off disk if it isn't already in memory. When adding a new step, follow this same `(step_num, func, deps, output_file)` tuple pattern in the `pipeline` list.
- `self.scale_config` is computed once at construction via `LargeCodebaseAdapter.get_adaptive_config()` (see Scaling below) based on file count/size, and pipeline steps read `config.yaml` (`src/config.py`) plus this scale config to decide worker counts, chunk sizes, and path limits.

### Code graph construction (Step 3b → `src/analysis/`)

This is the deterministic foundation everything else depends on:
- `ast_parser.py` — multi-language parsing: 9 languages via tree-sitter, remaining via regex fallback. Reused across analyzers (single-pass).
- `call_graph.py` — every function → every callee, direct + virtual dispatch, cross-file resolved via imports.
- `source_tag.py` / `sink_tag.py` / `sanitizer_tag.py` — tag every untrusted entry point, dangerous operation, and validator/encoder/auth-check respectively. Sanitizers carry a `protected_against` taxonomy used later to cross-reference against sink categories (`SINK_TO_SANITIZER_TAXONOMY` in `path_enum.py`).
- `intra_taint.py` / `inter_taint.py` — taint tracking within a function and propagated across function boundaries (accumulated, not overwritten, as taint crosses calls).
- `memory/` — five independent analyzers (`alloc_tracker.py`, `buffer_analyzer.py`, `lifetime.py`, `int_overflow.py`, `format_string.py`) run inline for C/C++/Rust, coordinated by `memory/orchestrator.py`.

### Path enumeration and analysis (Steps 4b–4d)

- **4b** (`path_enum.py` / `analysis/path_enum.py`): for every compatible source↔sink pair, enumerate all call-graph paths, trace taint per-path, and cross-reference sanitizers against sink categories. This step is *always exhaustive* — never sampled.
- **4c** (`step4c_path_analyze.py` / `analysis/path_analyze.py`, the largest analysis module at ~975 lines): deduplicates paths by `(source, sink, category)`, resolves clear-cut cases deterministically (sanitizer-taxonomy match → auto-BLOCKED, unreachable sink → auto-BLOCKED) without touching the LLM, and sends only ambiguous paths to the LLM. **Smart prioritization** (`smart_limit_max` in `config.yaml`, default 2000, `0` = unlimited/exhaustive) caps LLM calls while guaranteeing every CRITICAL/HIGH path and at least one path per sink category is still analyzed — the cap only trims lower-priority ambiguous paths. Uncertain/low-confidence verdicts get 3 self-consistency runs at temp 0.4 (`LLMClient.self_consistent`).
- **4d** (`step4d_blindspot.py`): file-by-file adversarial LLM review of every source file *not* touched by any enumerated path (the "Project Black" blind-spot sweep) — catches what static path enumeration structurally can't reach.

### Chain synthesis (Step 6 → `analysis/attack_graph.py`)

Confirmed findings are classified by role (`code_exec`, `file_access`, `information_theft`, `access_escalation`, ...); valid role transitions define an attack graph, and `networkx` transitive closure surfaces multi-step chains (e.g. LFI → RCE) even when no single finding spans the whole chain.

### Scaling for large codebases (`src/analysis/scaling.py`)

`LargeCodebaseAdapter` picks a config profile (`minimal`/`standard`/`large`/`enterprise`) from file count, driving chunk size (default 500 files/chunk), worker count, and `smart_limit_max`. `ChunkedFileProcessor` does the actual file listing/filtering (skips files >10MB, test/vendor dirs). This is what lets the same pipeline run on a 200-file repo and on the Linux kernel — always check here before changing anything file-count- or memory-related in the pipeline steps.

### LLM client (`src/llm/client.py`)

Thin wrapper around the OpenAI SDK pointed at a local `llama-server` (`http://127.0.0.1:<port>/v1`, no real API key). Handles Qwen `<|think_start|>...<|think_end|>` thinking-token stripping, JSON extraction with brace-matching repair (`_parse_json`) for when the model doesn't return clean JSON, and retry/backoff on connection errors. `chat_json` is the primary entry point used throughout the pipeline; `self_consistent` runs multiple samples and requires majority agreement on `vulnerability_class` before accepting a result.

### Config (`src/config.py`, `config.yaml`)

`config.yaml` is the single source of truth for model paths, server settings (context length, speculative decoding), pipeline knobs (`smart_limit_max`, `parallel_analyzers`, `max_path_depth`), and scaling defaults. Values can be the literal string `"AUTO"`, which `Config.get()` resolves to the caller-supplied default unless overridden — `run_benchmark.py` and the eval/calibration flow (`src/eval/calibration.py`) write `data/benchmark_results.json` / `data/calibration.json`, which `Config._apply_overrides()` layers on top of the YAML on every reload. Don't hardcode values that should come through `config.get(...)`; follow this AUTO-override pattern for new tunables.

### Knowledge base (`src/knowledge/`)

Local SQLite CVE database (`data/cve/nvd.sqlite`, gitignored) built from NVD + EPSS + KEV via `downloader.py` → `importer.py`, with optional sentence-transformer embeddings (`embeddings.py`) for semantic search. `cve_db.py` is the query interface used by step 4 (threat model) and step 4c (per-path CVE context injection) to pull product-specific CVEs into LLM prompts.

### Evaluation (`src/eval/`)

`EvalHarness` runs regex-based source/sink detection (not the full pipeline) against known-vuln corpora (OWASP Benchmark, Juliet, CVEfixes, etc. — see `datasets.py`) to compute precision/recall (`metrics.py`), then `calibration.py` tunes confidence thresholds from those results and writes them back into `config.yaml`'s AUTO fields. This is the closest thing to a regression test in this repo.
