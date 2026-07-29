# project.md — LVRP (Local Vuln Research Pipeline)

Companion doc to `CLAUDE.md`. That file is operational (commands, code map); this one is about *what the project is, why it's built this way, and where it's strong or fragile*.

## 1. What it is

LVRP is a whitebox vulnerability research tool: point it at a source repository and it produces a Markdown report of verified, exploitable vulnerabilities with PoCs, root causes, and remediation — using only a locally-hosted LLM (no cloud API calls, no data leaves the machine).

Its defining design choice is separating **discovery** from **judgment**:
- Discovery (finding candidate vulnerable data flows) is 100% deterministic: AST parsing → call graph → tagged sources/sinks/sanitizers → exhaustive path enumeration. No sampling, no LLM guessing about "where to look."
- Judgment (deciding whether a given, already-traced path is actually exploitable) is where the LLM is used, one path at a time, with a short focused prompt and relevant CVE context.

This is the opposite of the more common "hand the LLM the whole file/repo and ask it to find bugs" approach, and it's the project's core bet: LLMs are good at judging a well-scoped question ("is this specific flow exploitable given this specific code?") and bad at exhaustively searching a large codebase from scratch.

## 2. Problem it's solving

Traditional SAST tools (Semgrep, CodeQL) are deterministic and fast but pattern-matching — they miss anything not covered by a rule and produce false positives that require manual triage. Pure LLM-driven review (paste code, ask "find bugs") is exploitable-context-aware but non-exhaustive and non-reproducible — the model samples what it looks at, and coverage isn't guaranteed. LVRP tries to get both properties: an SAST-style deterministic engine handles graph construction, tagging, and path enumeration exhaustively (so coverage is provable — every file, every function, every source-to-sink pair), and the LLM only validates outcomes that were guaranteed to be found first.

It also explicitly integrates threat intelligence: every LLM validation prompt is enriched with product-specific CVE examples from a local NVD/EPSS/KEV database, so the model has real-world pattern precedent rather than reasoning from scratch.

## 3. Architecture

```
                     ┌─────────────────────────────────────────────┐
                     │              DETERMINISTIC LAYER              │
                     │                                               │
[Target Repo] ──▶  Step 0  Fingerprint + SBOM (file inventory)       │
                     Step 1  Classify target (16+ types)             │
                     Step 2  Dependency vuln scan (NVD/EPSS/KEV)      │
                     Step 2b Secrets scan (gitleaks rules)            │
                     Step 3  Semgrep static analysis                  │
                     Step 3b Code graph: AST + call graph +           │
                             source/sink/sanitizer tags +             │
                             memory analysis (C/C++/Rust)             │
                     Step 4b Exhaustive path enumeration              │
                             (every source ↔ every compatible sink)   │
                     └───────────────────┬───────────────────────────┘
                                          │ pre-traced paths
                     ┌────────────────────▼──────────────────────────┐
                     │               LLM LAYER (local)                │
                     │  Step 4  Threat model + CVE catalog (1 pass)   │
                     │  Step 4c Per-path exploitability validation    │
                     │          (deterministic auto-verdicts first;   │
                     │           LLM only for ambiguous paths;        │
                     │           self-consistency on low confidence)  │
                     │  Step 4d Blind-spot file sweep (uncovered      │
                     │          files, adversarial red-team prompt)   │
                     │  Step 5  Memory-finding FP filtering (LLM      │
                     │          validates CRITICAL/HIGH regex hits)   │
                     └───────────────────┬──────────────────────────┘
                                          │ verified findings
                     ┌────────────────────▼──────────────────────────┐
                     │              SYNTHESIS + OUTPUT                │
                     │  Step 6  Attack-graph chain synthesis (networkx)│
                     │  Step 7  Confidence-based validation/filtering  │
                     │  Step 8  Prompt-injection anomaly check         │
                     │  Step 9  Report + PoC generation                │
                     └─────────────────────────────────────────────────┘
```

Everything is checkpointed to `data/checkpoints/<repo-hash>/` at the granularity of individual pipeline steps, plus an intra-step checkpoint for the slowest step (4c, per-path LLM analysis) so a killed process resumes without redoing completed work.

### Component layers (maps to `src/`)

| Layer | Directory | Role |
|---|---|---|
| Pipeline orchestration | `src/orchestrator.py`, `src/pipeline/` | Step sequencing, checkpointing, dependency wiring |
| Static analysis engine | `src/analysis/` | AST parsing, call graph, taint tracking, path enumeration, memory analysis, scaling |
| LLM integration | `src/llm/` | Local model client, prompt construction, context building, prompt-injection guard |
| Threat intel | `src/knowledge/` | Local CVE database (NVD/EPSS/KEV), embeddings for semantic CVE search, SBOM |
| Evaluation | `src/eval/`, `src/benchmark/` | Accuracy calibration against known-vuln corpora; model/hardware benchmarking |

### The model itself

Not a hosted API — a quantized local model (default: Qwen2.5-Coder-14B-Abliterated, GGUF, served via `llama.cpp` with an OpenAI-compatible endpoint) plus an optional smaller draft model for speculative decoding. "Abliterated" (safety-refusal-stripped) is a deliberate choice: the tool needs the model to write exploit PoCs and reason about attack techniques without triggering safety refusals, which is why the README's license explicitly restricts use to authorized security research.

## 4. Strengths

- **Provable coverage.** Because path enumeration and file coverage tracking are deterministic, the tool can state exactly what was and wasn't analyzed (coverage statistics in every report), unlike LLM-only tools where "did it actually look at that function?" is unanswerable.
- **No sampling in discovery.** Every source-to-sink pair with a compatible taxonomy gets enumerated; this eliminates the "LLM got bored and moved on" failure mode of large-context whole-repo review.
- **Deterministic fast-path reduces LLM load and hallucination risk.** Clear-cut sanitizer matches or unreachable sinks are resolved without ever asking the model, which both saves compute and removes a class of LLM misjudgment.
- **Hardware-adaptive by design**, not as an afterthought — `smart_limit_max`, chunking, and worker counts scale from a 4-core laptop to a 32-worker multi-GPU rig via one config change, with an explicit "exhaustive vs smart" mode tradeoff exposed to the user rather than hidden.
- **Resumability that actually works mid-step**, not just between pipeline stages — the JSONL incremental checkpoint in step 4c means a crash after path 8,000 of 10,000 loses nothing.
- **Privacy/cost**: fully local, no per-token API billing, no third-party data exposure — meaningful for auditing proprietary or sensitive codebases.
- **Cross-references sanitizers against sink categories via an explicit taxonomy** (`SINK_TO_SANITIZER_TAXONOMY`) rather than trusting sanitizer presence blindly — the LLM still verifies effectiveness, so a sanitizer tag is a signal, not an auto-clear.
- **Attack-chain synthesis** goes beyond single-finding reports — networkx transitive closure surfaces multi-step exploit paths (e.g., LFI chained into RCE) that no single deterministic rule or single LLM call would produce alone.

## 5. Weaknesses / risks

- **No automated test suite.** There is no pytest/unit-test coverage over the analysis engine itself (call graph, taint tracking, path enumeration) — correctness relies on the eval harness (regex-based precision/recall against corpora like OWASP Benchmark) and manual runs. Regressions in core graph logic could go undetected.
- **Eval harness is shallow.** `src/eval/harness.py`'s `_detect_vuln_in_file` is itself simple regex source/sink matching, not a run of the actual pipeline — it validates general precision/recall trends, not the AST/call-graph/LLM pipeline end-to-end. It's a calibration signal, not a regression test for the real system.
- **Hardware dependency for meaningful runs.** "Exhaustive" mode (`smart_limit_max: 0`) is explicitly gated behind having strong GPU hardware; on consumer hardware the tool runs in "smart" mode with a path cap, meaning the 100%-coverage claim only fully holds under `smart_limit_max: 0` — on default settings some ambiguous paths are never sent to the LLM (though CRITICAL/HIGH and per-category coverage are still guaranteed).
- **Known static-analysis blind spots acknowledged in the README**: function-pointer/vtable dynamic dispatch (conservative resolution), reflection, C macro expansion (not expanded), assembly (not analyzed), cross-TU inlining. These are inherent to static analysis generally, not unique to this tool, but they bound the "exhaustive" claim.
- **Local-model quality ceiling.** Exploitability judgments and PoC quality are bounded by a 14B-parameter local model — meaningfully weaker reasoning than frontier hosted models, especially on subtle exploitability judgments (e.g., whether a bounds check is actually sufficient). Self-consistency (3 runs, majority vote) mitigates but doesn't eliminate this.
- **Single point of failure in JSON parsing robustness.** `LLMClient._parse_json`'s brace-matching repair is a reasonable fallback but is regex/heuristic-based; malformed model output that doesn't match its heuristics silently degrades to an empty result (`{}`) rather than a raised error, which could mask analysis failures as "nothing found" in downstream steps.
- **Abliterated/uncensored model dependency.** The project's threat-modeling use case requires a model with safety training removed, which narrows the pool of usable models and puts the burden of misuse-prevention entirely on the "authorized use only" license/social contract rather than any technical control.
- **Scaling to true enterprise codebases (Linux kernel, 30M LOC) is asserted but resource-intensive** — the README's own time estimates put enterprise-scale exhaustive runs at 4-6+ hours even with 8 workers, and correspondingly longer without a capable GPU.
- **No CI/lint/type-checking configuration present** in the repo — no ruff/flake8/mypy/pytest config — so code-quality regressions aren't caught automatically; contributions rely on manual review.

## 6. Who this is for / when to reach for it

- Security researchers or red teams doing **authorized** whitebox review of a codebase they have legal access to, especially when they want reproducible, provable coverage over an entire repo rather than spot-checks.
- Situations where **data cannot leave the machine** (sensitive/proprietary code, air-gapped environments, cost-sensitive high-volume analysis).
- Large or unfamiliar codebases where the goal is systematic triage (attack surface mapping, coverage-guaranteed sweep) rather than deep expert review of one already-suspected function.

Not a fit for: quick single-file "is this snippet vulnerable" questions (too much setup/fixed cost — path enumeration + code graph construction is a whole-repo operation), or teams needing a zero-maintenance hosted SaaS scanner (this requires standing up and maintaining a local GPU + model server).

## 7. Notable implementation details worth knowing before making changes

- Path prioritization under `smart_limit_max` is **not** naive top-N: it guarantees ≥1 path per unique sink category and always includes all CRITICAL/HIGH paths, so lowering the limit trims mid/low-severity redundancy first, not coverage breadth.
- Context-aware vulnerability-class weighting (Python repos boost SSTI/deserialization, C boosts memory corruption, Java boosts deserialization/SpEL) means the *same* path-count budget is spent differently depending on detected stack — this logic lives in the scaling/prioritization code, not hardcoded per pipeline step.
- The memory-corruption analyzers (`src/analysis/memory/`) are pattern-based detectors, not a real dataflow/points-to analysis — the LLM validation pass in step 5 exists specifically to catch the resulting false positives (e.g., a bounds-checked `memcpy` that regex alone would flag).
- Config `"AUTO"` values are resolved at runtime from `data/benchmark_results.json` / `data/calibration.json`, which are themselves generated by `run_benchmark.py` and `python -m src.main eval` respectively — editing `config.yaml`'s AUTO fields directly has no effect until those generator flows are re-run, or the value is replaced with a literal.
