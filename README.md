# Local Vuln Research System

LLM-driven exhaustive vulnerability research pipeline using a local uncensored MoE model. Not a SAST tool — the LLM is the primary analyst, every single source file is fed to the model through dynamic context-budgeted passes. N-pass fuzzing architecture adapted from Hacker House's inference fuzzing methodology.

## Architecture

```
[Target Repo]
    |
Step 0  ─ Fingerprint + SBOM              (deterministic, 100% of files)
Step 1  ─ Classify target                 (17+ target types, dual-language detection)
Step 2  ─ Dependency vuln scan            (NVD + EPSS/KEV ranked)
Step 2b ─ Secrets scan                    (gitleaks rules, all text files)
Step 3  ─ Static analysis (signal boost)  (Semgrep + sink finder + taint flow, 11 languages, full file inventory)
Step 4  ─ Threat model + CVE catalog      (1 LLM pass + product-specific CVE search, coverage plan for all files)
Step 5  ─ N-pass exhaustive fuzz          (EVERY file, dynamic batch packing, follow-up passes for incomplete analyses)
Step 5b ─ Triage                          (5-step skeptical verification: read→trace→check→assess→evidence)
Step 6  ─ Iterative deep trace            (exact referenced files loaded first, per-hyp checkpoint, up to 5 iterations)
Step 7  ─ Validation + chain synthesis    (12 filters + LLM chains medium into critical)
Step 8  ─ Anomaly check                   (prompt injection detection)
Step 9  ─ Report + runnable PoC           (root cause, exploit path, steps, impact, remediation)
    |
Output: All verified findings with source-reasoned evidence
```

**Key differentiator from SAST**: Steps 4-9 are LLM-driven. Step 5 runs exhaustive passes — every non-test source file gets its own clean-context review. No sampling, no early termination. Each pass gets fresh context, anchors on different files, and explores different attack surfaces. Step 5b independently verifies every claim against actual source code with a 5-step methodology. Every finding includes concrete source reasoning with quoted vulnerable lines.

## Language & Target Coverage

| Language | Sinks | Entry Points |
|----------|-------|-------------|
| Python | 20 patterns | 14 source types |
| JavaScript/TS | 11 | 6 source types |
| Java | 12 | 9 source types |
| C# | 21 | 13 source types |
| C/C++ | 12 | 17 source types (syscall, ioctl, exported API, kernel) |
| Go | 9 | 10 source types |
| Rust | 9 | 12 source types (unsafe, FFI) |
| PHP | 19 | 14 source types |
| Ruby | 7 | 10 source types |
| PowerShell | 17 | 16 source types (param, args, cmdlet, COM) |

**Target classifications**: kernel, browser/sandbox, PowerShell (dual-language C# + PS detection), AI/ML framework, compiler, embedded/IoT, native C/C++ library, distributed system, container runtime, CLI tool, Java, .NET, web app, IDE/editor, database, protocol handler, general application.

## Hardware

**Tested config:**
- GPU: RTX 4070 Ti SUPER (16GB VRAM)
- CPU: Ryzen 7 7700 (8C/16T)
- RAM: 32GB DDR5 6000MHz
- Model: Qwen3.6-35B-A3B IQ3_M (15GB, fits VRAM fully)
- Performance: 39 tok/s, 100% JSON compliance, 131K context usable
- Server: llama.cpp with `--jinja` (Qwen chat template), flash attention, Q4 KV cache

## Quick Start

### 1. Prerequisites
```
winget install llama.cpp      # Windows
brew install llama.cpp         # macOS / Linux
pip install huggingface_hub
```

### 2. Download model
```
huggingface-cli download HauhauCS/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive \
  Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-IQ3_M.gguf \
  --local-dir models/
```

| Quant | Size | VRAM |
|-------|------|------|
| `IQ3_M` | 15 GB | 16GB — full GPU fit |
| `IQ4_XS` | 19 GB | 24GB |
| `Q4_K_M` | 21 GB | 32GB |

### 3. Install dependencies
```
pip install -r requirements.txt
```

### 4. Start model server
```
python start_server.py
```

### 5. Get free NVD API key
https://nvd.nist.gov/developers/request-an-api-key (30 seconds)

### 6. Download CVE database
```powershell
$env:NVD_API_KEY="your-key-here"
python -m src.main update-cve
```
~45 min with API key. 364K+ CVEs with EPSS + KEV.

### 7. Benchmark (optional)
```
python run_benchmark.py
```

### 8. Audit
```
python run_audit.py /path/to/target-repo
python run_audit.py /path/to/target-repo --resume   # resume from checkpoint
```

---

## Pipeline Deep Dive

### Step 0 — Fingerprinting

Detects languages, frameworks, build systems, and architecture. Framework detection scans only manifest/config files (`.csproj`, `package.json`, etc.) — not every source file — to avoid false signals from test fixtures and comments. Dual-language repos (e.g., C# + PowerShell) are correctly detected.

### Step 1 — Classification

17 target types with ordered rule matching. Dual-language detection handles repos where the primary language is C# but the codebase is fundamentally PowerShell (detected via `System.Management.Automation`, `.ps1`/`.psm1` counts, Cmdlet keywords). Classification order: specialized types (kernel, browser, PowerShell) match before generic types (.NET, web app).

### Step 3 — Static Analysis (Signal Boost, Not Gate)

Runs all deterministic analyzers in parallel. **Full file inventory** — every source file is collected (not just top 50). Zero taint flows does NOT block the pipeline — the LLM gets the full codebase overview and hunts independently.

### Step 4 — Threat Model + CVE Catalog (1 Pass)

One careful LLM pass builds the attack surface map that every fuzz pass consults:
- Entry point inventory (every externally reachable route, CLI arg, file parse, IPC handler)
- Trust boundaries (where data crosses privilege levels)
- Sink inventory (dangerous operations mapped to file:line, organized by category)
- Coverage plan (ALL non-test source files, ranked by priority: entry points > sink-heavy > remaining)
- CVE catalog with **product-specific searches** — PowerShell repos get PowerShell CVEs, .NET gets deserialization CVEs, kernel gets LPE/driver CVEs

If the LLM threat model fails, a robust static analysis fallback builds the coverage plan from sink matches.

**Test directories filtered out** of the coverage plan — `test/`, `tests/`, `spec/`, `fixtures/`, `mocks/`, `benchmarks/`.

### Step 5 — N-Pass Exhaustive Fuzz Audit

**Every single non-test source file** is fed to the LLM. No sampling, no early termination.

**Dynamic batch packing**: files are packed greedily into each pass's 60K char context budget. Large files get a dedicated pass; small files get bundled 8-15 per pass. Priority ordering ensures sink-heavy and entry-point files are audited first.

**Follow-up passes**: if the LLM flags files as `files_fully_analyzed: false`, they're re-scheduled for a second pass with a more aggressive prompt.

**Source reasoning required**: every finding must include `source_reasoning` — concrete code evidence, quoted vulnerable lines, exploit scenario, and explanation of why existing mitigations fail. Generic descriptions like "unsanitized input" are rejected.

**Per-pass checkpointing**: progress saved after every pass. Power cutoff? Resume from exact pass number with `--resume`.

**Prompt quality**: the fuzz prompt is ~120 lines of structured guidance covering:
- 10 vulnerability classes with specific API examples per language
- 8-step per-file analysis methodology (find sinks → trace backwards → check validators → bypass → indirect flows → encoding tricks → type confusion)
- Confidence grading rubric (0.9+ = exact exploit, 0.7 = likely, 0.5 = suspicious pattern)
- CVE pattern matching against the catalog

### Step 5b — Triage

5-step skeptical verification methodology:
1. **Read the actual code** — open file:line, confirm it exists and matches the claim
2. **Trace the data flow independently** — don't trust the candidate's trace hops
3. **Check every mitigation** — validation, sanitization, access control, parameterization, error handling, bounds, canonicalization
4. **Assess exploitability honestly** — external vs local, full vs partial control, realistic preconditions
5. **Provide evidence** — quoted lines, independent trace, why mitigations fail, suggested fix

Full source files loaded (no truncation). Token budget: 4096.

### Step 6 — Iterative Deep Trace

Per-hypothesis checkpointing with methodology-specific tracing. **Fixed file loading**: exact referenced files from the hypothesis are loaded first (component name → rglob for exact file → trace hop files → sink files), not a random sample of inventory files. LLM requests files mid-trace — up to 5 iterations. Full source files, no truncation. Token budget: 4096.

### Step 7 — Validation + Chain Synthesis

12 filters: Precondition Power Test, Reachability Gate, Circular Threat, Trusted Input Reclass, DoS Exclusion, AI Slop Check, and 6 more. LLM-driven chain synthesis: can medium findings chain into critical?

---

## Time Budget (Exhaustive Mode)

| Repo Size | Files in Plan | Est. Passes | Est. Time |
|-----------|---------------|-------------|-----------|
| Small (~200 files) | ~150 | ~20 | ~3-4 min |
| Medium (~800 files) | ~600 | ~80 | ~12-15 min |
| Large (~2000 files) | ~1400 | ~175 | ~25-30 min |
| Very Large (~5000 files) | ~3500 | ~440 | ~60-75 min |
| Kernel (28M lines) | ~8000 | ~1000 | ~4-6 hours |

Time scales linearly with repo size. All times assume 39 tok/s throughput. Checkpoint/resume supported at every pass.

## Checkpointing

Power cut mid-fuzz? Resume from last saved pass. Each pass is independent — zero context dependency between passes.

```
data/checkpoints/<hash>/
├── progress.md              Human-readable: pass 87/175, 23 candidates, 5 verified
├── fuzz_progress.json       Coverage tracker + accumulated candidates + files needing follow-up
├── fuzz_candidates.json     All raw candidates from fuzz passes  
├── triaged.json             Post-triage verified findings
├── triage_verified.json     Triage checkpoint
├── trace_hyp_0.json         Per-hypothesis deep trace checkpoints
├── validated_findings.json
├── report.md
└── threat_model.json
```

---

## Commands

| Command | Description |
|---------|-------------|
| `python start_server.py` | Start llama-server |
| `python run_benchmark.py` | Run model benchmark |
| `python run_audit.py <path>` | Full audit pipeline (exhaustive mode) |
| `python run_audit.py <path> --resume` | Resume from checkpoint |
| `python -m src.main setup` | Print setup instructions |
| `python -m src.main update-cve` | Download/build CVE database |
| `python -m src.main eval` | Run evaluation harness |

## CVE Database

NVD (364K+) + EPSS (exploit probability) + CISA KEV (actively exploited). SQLite with FTS5 + 384-dim embeddings. Hybrid ranking: KEV > EPSS > CVSS. Product-specific CVE searches for PowerShell, .NET, and other target types.

## Configuration

```yaml
model:
  quant: "IQ3_M"
  file: "models/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-IQ3_M.gguf"

server:
  context_length: AUTO   # Benchmark: 131K
  flash_attn: true

pipeline:
  max_hypotheses: AUTO
  self_consistency_runs: 3

thresholds:
  hypothesis_confidence_cutoff: AUTO
  epss_min_score: 0.01

knowledge:
  sources: [nvd, epss, kev]
```

---

## File Structure

```
  models/                              GGUF model files
  src/
    orchestrator.py                    Master pipeline + checkpointing
    pipeline/
      step0_fingerprint.py             Fingerprinting + SBOM (manifest-only framework detection)
      step1_classify.py                17+ target types + dual-language detection
      step2_deps.py                    Dependency vuln scan
      step2_secrets.py                 Secrets scanner
      step3_static.py                  Static analysis (full file inventory)
      step4_threat_model.py            Threat model + product-specific CVE catalog
      step5_fuzz.py                    N-pass exhaustive fuzz (dynamic batch packing)
      step5_hypotheses.py              Hypothesis generation from signals
      step5b_triage.py                 5-step skeptical candidate verification
      step6_deep_trace.py              Iterative deep trace with exact file loading
      step7_validate.py                Filters + LLM chain synthesis
      step8_anomaly.py                 Injection detection
      step9_report.py                  Report + PoC
    analysis/
      sink_finder.py                   200+ patterns, 11 languages
      data_flow.py                     50+ source patterns, all languages
      semgrep_runner.py, secrets_scanner.py, ast_parser.py, call_graph.py
    knowledge/
      downloader.py, importer.py, cve_db.py, embeddings.py, epss.py, kev.py, sbom.py
    llm/
      client.py, prompts.py, context.py, guard.py
    eval/
      harness.py, datasets.py, metrics.py, calibration.py
    benchmark/
      runner.py, report.py
  data/
    cve/nvd.sqlite                     Unified CVE database (364K+ CVEs)
    checkpoints/                       Per-repo audit state + per-hyp trace state
  config.yaml, requirements.txt
  start_server.py, run_benchmark.py, run_audit.py
```

## Design Principles

- **Exhaustive coverage**: Every non-test source file is audited. No sampling. No shortcuts.
- **Source-reasoned findings**: Every vulnerability claim must cite exact file:line and include concrete code evidence. Generic descriptions are rejected at triage.
- **Clean context per pass**: No memory between passes. Each pass walks different attack surface, like a fuzzer randomizing its seed.
- **Skeptic triage**: The triage step assumes every fuzz candidate is wrong until proven otherwise. Independent trace verification, mitigation checking, honesty about exploitability.
- **Product-specific CVE intelligence**: Not generic top-10 CVEs. The CVE catalog is targeted to the actual technology stack.
- **Per-pass resume**: Every pass checkpoints. Resume from exact position after interruption.
- **Time is not a constraint**: Quality over speed. Every file, every pass, every verification.

## Caveats

- Authorized security research only. Confirmation required before every audit.
- Model quality ceiling: IQ3_M at 3B active params may miss complex multi-hop logic. Higher quants improve reasoning.
- False positives in fuzz phase are by design. The 5-step triage phase discards them.
- Local-only model — no data leaves your machine. No API costs.
- Test directories are excluded from the audit plan. Test code often contains intentional vulnerable patterns (XSS payloads, injection strings) that produce false positives.

## License

For authorized security research only. Unauthorized use may violate computer fraud laws.
