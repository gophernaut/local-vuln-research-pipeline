# improvements.md

Concrete improvement opportunities found while reading the pipeline (`src/orchestrator.py`), the code-graph layer (`src/analysis/ast_parser.py`, `call_graph.py`), and the path/taint engine (`src/analysis/path_enum.py`, `intra_taint.py`, `inter_taint.py`). Grouped by implementation difficulty; within each group, ordered by impact on the tool's core usefulness (finding real vulnerabilities, with few false positives, without wasting LLM budget). Every item below is grounded in something actually observed in the code, not a generic best-practice suggestion.

## Summary matrix

| Item | Difficulty | Impact |
|---|---|---|
| LLM JSON-parse failure silently returns `{}` | Low | High |
| Regex taint-match runs over raw text, matches inside strings/comments | Low | Medium-High |
| Two independent, unreconciled "is this a sanitizer" definitions | Low | Medium |
| `class_methods` dead code — method-call edges never resolved via class hierarchy | Low | Medium |
| No lint/type-checking config | Low | Low-Medium |
| Name-only call resolution creates false-positive call-graph edges | Medium | High |
| No regression tests for the deterministic core | Medium | High |
| Eval harness bypasses the real pipeline | Medium | Medium-High |
| `inter_taint._resolve_callee` — first-name-match, no same-file preference | Medium | Medium-High |
| Per-language precision/recall breakdown in eval | Medium | Medium |
| Replace regex-substring taint with real expression-aware dataflow | High | High |
| Symbol/type-resolved call graph (real scoping, not global name index) | High | High |
| Pluggable LLM backend abstraction | High | Medium |
| CI pipeline (needs mock LLM server) | High | Medium |

---

## Low difficulty (small, localized changes)

**1. LLM JSON-parse failure silently returns `{}`** — Impact: High
`LLMClient.chat_json` (`src/llm/client.py`) falls back to `{}` when `_parse_json` can't extract valid JSON from either the JSON-mode or plain retry. Every caller across step 4c (per-path verdicts), step 4d (blind-spot findings), and step 5 (memory FP filtering) then treats `{}` the same as a genuine "nothing wrong here" result. A malformed model response is indistinguishable from a real negative — this can silently suppress findings with no signal in the report or logs that it happened. Fix: have `chat_json` return `None` (not `{}`) on total parse failure, and have callers log/count a `parse_failure` distinct from a real empty verdict, so a run's summary can report "N paths had unparseable LLM output" instead of quietly counting them as clean.

**2. Taint-match regex runs over raw, unstripped source text** — Impact: Medium-High
Both `intra_taint.py`'s `_handle_assignment`/`_handle_call`/`_handle_return` decide "does this expression reference a tainted variable" via `re.search(r'\b' + re.escape(var) + r'\b', text)` against the raw slice of source text for that node — including string literals and any trailing comment on the line. A tainted variable named e.g. `user_id` will "taint" `msg = "invalid user_id supplied"` even though the string is a literal, not a reference. This is a real, easy-to-trigger false-positive source that inflates both path counts and the ambiguous-path pool sent to the LLM. Fix: when computing whether an RHS/argument node references taint, walk its identifier subtree (already have the AST at this point) instead of running regex over `source[start:end]`, or at minimum strip string/comment nodes before the regex pass.

**3. Two independent, unreconciled sanitizer definitions** — Impact: Medium
`intra_taint.py` has its own hardcoded `SANITIZER_FUNCTIONS` set (checked via `_is_sanitizer_call`, substring/suffix match) used to set `sink_reach["is_sanitized"]` inside a single function. Separately, `sanitizer_tag.py` produces `SanitizerTag` objects with a `protected_against` taxonomy that `path_enum.py`'s `_is_blocked_by_sanitizer` cross-references against `SINK_TO_SANITIZER_TAXONOMY` at the path level. These two systems can disagree — a call recognized as a sanitizer by one and not the other produces an intra-function taint state that says "sanitized" while the path-level verdict says "not blocked" (or vice versa), and nothing reconciles them before the LLM sees the path. Fix: derive `SANITIZER_FUNCTIONS` from the same source as `sanitizer_tag.py`'s patterns (or have `sanitizer_tag.py` export a lookup `intra_taint.py` calls), so there's one sanitizer catalog, not two.

**4. `CallGraph.class_methods` is declared but never populated** — Impact: Medium
`call_graph.py` defines `class_methods: dict[str, dict[str, str]]` on the `CallGraph` dataclass and `_resolve_method_calls()` reads from it to link `obj.method()` calls to the right class's method — but nothing in `CallGraphBuilder` ever writes to `class_methods`. `_resolve_method_calls` currently iterates an always-empty dict and is a no-op; all method-call edges are actually created earlier in `_build_edges` via the global name index instead. This means the "resolve by receiver/class" mechanism that the code was clearly designed to have doesn't run. Fix: populate `class_methods[class_name][method_name] = func_key` when functions are added (class name is already extracted per-function in `ast_parser.py`), then use it in `_build_edges` to prefer a class-scoped match over the global name index when `call.object_name` is available.

**5. No lint/type-checking configuration** — Impact: Low-Medium
No `ruff.toml`, `.flake8`, or `mypy.ini` exists. Given how much of this codebase relies on broad `except Exception: pass`/`except Exception: return` swallows (by design, to keep one bad file from killing a whole-repo parse), a linter that flags bare excepts and a type checker that catches dataclass-field typos would catch a meaningful class of bugs cheaply, especially given there's no test suite yet (see below) to catch them another way.

---

## Medium difficulty (touches core logic, but localized to 1-2 modules)

**1. Name-only call resolution creates false-positive call-graph edges** — Impact: High
`CallGraphBuilder._build_edges` resolves every call site by function name alone via `_func_name_index`: `foo()` called anywhere links to *every* function named `foo` in the entire repo, regardless of imports or scope. This is a deliberate sound-over-approximation (never miss a real edge), but on any codebase with common utility names (`validate`, `process`, `handle`, `parse`) it multiplies both the call-graph edge count and the number of enumerated source-to-sink paths with edges that don't actually exist — directly inflating the pool of "ambiguous" paths competing for the `smart_limit_max` LLM budget, and occasionally putting an implausible function chain in a report. The `import_map` this same file already builds (`_resolve_imports`) is currently unused at edge-building time. Fix: in `_build_edges`, when a caller's file has an import resolving that name to a specific target, prefer that edge; fall back to the global name index only when no import-resolved candidate exists.

**2. `inter_taint.InterTaintPropagator._resolve_callee` is even cruder than the call graph's resolution** — Impact: Medium-High
This is a second, separate, and weaker name-resolution implementation used only for the inter-procedural taint fixed-point loop: it iterates `functions.items()` (dict insertion order) and returns the first function whose name matches, only checking same-file *after* finding a match rather than as a real preference across all candidates. Combined with item 1, there are now two different, inconsistent call-resolution algorithms in the codebase producing potentially different answers to "which function does this call reach." Fix: have `inter_taint.py` consume the same resolved edges the call graph already computed (pass `CallGraph` in, or the resolved `caller→callee` key pairs) instead of re-deriving resolution from scratch.

**3. No regression tests for the deterministic core** — Impact: High
There is no pytest suite (confirmed: no test files, no pytest config anywhere in the repo) covering `ast_parser.py`, `call_graph.py`, `path_enum.py`, or the taint trackers — roughly 8,000+ lines that the entire pipeline's coverage guarantees depend on. A silent regression here (e.g., a tree-sitter query that stops matching after a grammar version bump) would not fail any check; it would just quietly reduce coverage while the "exhaustive" framing in the README and reports continues to claim completeness. Fix: a small fixture-based suite — for each supported language, a handful of snippets with known expected functions/calls/entry-points/taint-flow — run in CI. Doesn't need to be exhaustive to catch the class of regression that matters (a query silently returning zero captures).

**4. Eval harness bypasses the real pipeline** — Impact: Medium-High
`src/eval/harness.py`'s `_detect_vuln_in_file` is a standalone regex source/sink matcher, entirely separate from `ast_parser`/`call_graph`/`path_enum`/the LLM client. Running `python -m src.main eval` validates a simplified proxy for the system's precision/recall, not the code path an actual `run_audit.py` invocation uses. This means the auto-calibration (`src/eval/calibration.py`) that writes back into `config.yaml`'s AUTO fields is tuned against a different (simpler, likely more accurate on toy cases) detector than what production runs actually execute. Fix: add a "full-pipeline" eval mode that runs a small labeled corpus (a subset of OWASP Benchmark/Juliet) through the real `Orchestrator` steps 3b/4b/4c and compares against ground truth — even a slow, small-N version of this would be far more representative than the current regex proxy.

**5. Per-language precision/recall breakdown** — Impact: Medium
Coverage quality is structurally uneven: 9 languages get full tree-sitter queries (functions, calls, imports, classes, variables) while 7 (PHP, Ruby, PowerShell, Kotlin, Swift, Scala, Shell) get a much shallower regex-only pass with a heuristic block-end finder. The eval harness and calibration currently produce one global metric, hiding this gap. Breaking eval metrics down per-language would let users (and this project) know that, say, a Ruby-heavy repo has meaningfully less rigorous coverage than a Python one, rather than that being an implicit, undocumented fact discoverable only by reading `ast_parser.py`.

---

## High difficulty (structural investments)

**1. Replace regex-substring taint matching with expression-aware dataflow** — Impact: High
This is the single biggest precision lever in the system. Every "is this tainted" decision in `intra_taint.py` ultimately comes down to a word-boundary regex search over a raw source-text slice, not an actual walk of the expression's AST checking whether a tainted identifier is referenced as an identifier (vs. appearing inside a string/comment, or as a substring of an unrelated longer name that word-boundary alone doesn't fully protect against in all grammars). A real (even lightweight) expression evaluator — walk the RHS/argument AST, resolve identifier nodes, check membership in the tainted set — would cut both false-positive taint propagation (item 2 in Low difficulty is the cheap partial fix; this is the full fix) and, downstream, the number of paths that need expensive LLM disambiguation. This is high-difficulty because it touches the core walking logic across 9 language grammars, each with different expression-node shapes.

**2. Symbol/type-resolved call graph instead of global name-index matching** — Impact: High
The proper fix to the Medium-difficulty item above: real per-language scope resolution (respecting imports, class hierarchies/inheritance, shadowing) instead of a single global `name → [all functions with that name]` index. This would move the call graph from "sound but imprecise over-approximation" to something closer to what a real static analyzer produces, meaningfully reducing both false paths shown to users and paths that burn LLM budget on chains that don't actually exist. Substantially harder than the Medium-difficulty fix (which just prefers import-resolved edges when available) because it requires modeling actual language scoping semantics per grammar rather than opportunistically using data already collected.

**3. Pluggable LLM backend abstraction** — Impact: Medium
`LLMClient` (`src/llm/client.py`) is hardcoded to a local `llama-server` OpenAI-compatible endpoint at `127.0.0.1:<port>`. The local-only, no-data-leaves-the-machine design is a deliberate and valuable property of this project (see `project.md`) and should stay the default — but a thin backend interface would let a user opt a specific step (e.g., step 4d's blind-spot sweep, which is the most "reasoning-heavy" step) into a stronger hosted model when they've explicitly decided the tradeoff is worth it for a given engagement, without restructuring any pipeline step code. Non-trivial mainly because retry/backoff, thinking-token stripping, and JSON-repair behavior are currently written assuming one specific server's quirks.

**4. CI pipeline** — Impact: Medium
No CI configuration exists. Once a test suite exists (Medium-difficulty item above), wiring it into CI is normally easy — the difficulty here specifically is that meaningful pipeline tests need *something* answering LLM calls, and the real dependency is a local GPU-hosted `llama-server`. Getting real coverage in CI means building a small deterministic mock server that fakes `chat`/`chat_json` responses for the fixture inputs used in tests, which is extra infrastructure work beyond the tests themselves.
