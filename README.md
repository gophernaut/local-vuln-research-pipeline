# Local Vuln Research System

LLM-driven vulnerability research pipeline using a local uncensored MoE model. Not a SAST tool — the LLM is the primary analyst, hunting vulns through recursive clean-context passes over the codebase, guided by a CVE exploit pattern catalog. N-pass fuzzing architecture adapted from Hacker House's inference fuzzing methodology.

## Architecture

```
[Target Repo]
    |
Step 0  ─ Fingerprint + SBOM              (deterministic, 100% of files)
Step 1  ─ Classify target                 (15+ target types)
Step 2  ─ Dependency vuln scan            (NVD + EPSS/KEV ranked)
Step 2b ─ Secrets scan                    (gitleaks rules, all text files)
Step 3  ─ Static analysis (signal boost)  (Semgrep + sink finder + taint flow, 11 languages)
Step 4  ─ Threat model + CVE catalog      (1 LLM pass: entry points, trust boundaries, sinks, coverage plan)
Step 5  ─ N-pass clean-context fuzz       (20+ independent passes, 4 files each, fresh context per pass)
Step 5b ─ Triage                          (LLM verifies all candidates against source, discards noise)
Step 6  ─ Iterative deep trace            (per-finding, LLM requests files mid-trace, per-hyp checkpoint)
Step 7  ─ Validation + chain synthesis    (12 filters + LLM chains medium into critical)
Step 8  ─ Anomaly check                   (prompt injection detection)
Step 9  ─ Report + runnable PoC           (root cause, exploit path, steps, impact, remediation)
    |
Output: 0-2 HIGH/CRITICAL findings, or "SECURE"
```

**Key differentiator from SAST**: Steps 5-9 are LLM-driven. Step 5 runs N independent clean-context passes — each pass starts fresh, anchors on different files, and walks different attack surface. The union of passes covers ground no single pass could. Step 5b then acts as skeptic, verifying every candidate against actual source.

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

**Target classifications**: kernel, browser/sandbox, PowerShell, AI/ML framework, compiler, embedded/IoT, native C/C++ library, distributed system, container runtime, CLI tool, Java, .NET, web app, IDE/editor, database, protocol handler, general application.

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
~45 min with API key. 250K+ CVEs with EPSS + KEV.

### 7. Benchmark (optional)
```
python run_benchmark.py
```

### 8. Audit
```
python run_audit.py /path/to/target-repo
```

---

## Pipeline Deep Dive

### Step 3 — Static Analysis (Signal Boost, Not Gate)

Runs all deterministic analyzers in parallel. Zero taint flows does NOT block the pipeline — the LLM gets the full codebase overview and hunts independently.

### Step 4 — Threat Model + CVE Catalog (1 Pass)

One careful LLM pass builds the attack surface map that every fuzz pass consults:
- Entry point inventory (every externally reachable route, CLI arg, file parse, IPC handler)
- Trust boundaries (where data crosses privilege levels)
- Sink inventory (dangerous operations mapped to file:line)
- Coverage plan (all files ranked by risk, ~200 files for a typical repo)

### Step 5 — N-Pass Clean-Context Fuzz Audit

**Architecture adapted from Hacker House's inference fuzzing methodology** — splitting recall and precision.

For each pass (20+ passes):
1. Clean context — no memory of previous passes
2. 4 files selected from uncovered areas (coverage tracker ensures no repeats)
3. Threat model + CVE catalog provided as reference
4. LLM walks entry → trace → sink, reports all candidates
5. Candidate saved to disk. Context discarded. Next pass starts fresh.

Why clean context: a model with long history anchors on what's already seen and circles the same findings. Wiping between passes is what produces variation — like a fuzzer randomizing its seed. The union of 20+ independent walks covers ground no single pass could.

Noise is expected. The model is told: "report anything plausible, don't self-censor, false positives are OK." This is recall, not precision.

### Step 5b — Triage

The LLM acts as a skeptical reviewer. For every candidate:
- Re-opens referenced files, confirms code says what the finding claims
- Traces each hop independently
- Checks: existing sanitizer, parameterized query, auth check, bounds guard
- Discards hallucinations, unreachable paths, mitigated issues
- Keeps only verified findings with adjusted confidence

### Step 6 — Iterative Deep Trace

Per-hypothesis checkpointing. LLM requests files it needs mid-trace — up to 5 iterations. Methodology-specific tracing: kernel traces differently from web app traces differently from PowerShell.

### Step 7 — Validation + Chain Synthesis

12 filters: Precondition Power Test, Reachability Gate, Circular Threat, Trusted Input Reclass, DoS Exclusion, AI Slop Check, and 6 more. LLM-driven chain synthesis: can medium findings chain into critical?

---

## Time Budget

| Phase | Time (2400 files) |
|-------|-------------------|
| Steps 0-3 (deterministic) | ~30 seconds |
| Step 4 (threat model) | ~3 minutes |
| Step 5 (20 fuzz passes) | ~25 minutes |
| Step 5b (triage) | ~5 minutes |
| Steps 6-9 (trace+validate+report) | ~5-10 minutes |
| **Total** | **~40-45 minutes** |

Larger repos scale linearly: kernel (28M lines) ~4-6 hours. Pass count auto-scales with repo size.

## Checkpointing

Power cut mid-fuzz? Resume from last saved pass. Each pass is independent — zero context dependency between passes.

```
data/checkpoints/<hash>/
├── progress.md              Human-readable: pass 12/20, 8 candidates, 2 verified
├── fuzz_progress.json       Coverage tracker + accumulated candidates
├── fuzz_progress.md         
├── triage_verified.json     Post-triage findings
├── trace_hyp_0.json         Per-hypothesis deep trace checkpoints
├── validated_findings.json
└── report.md
```

---

## Commands

| Command | Description |
|---------|-------------|
| `python start_server.py` | Start llama-server |
| `python run_benchmark.py` | Run model benchmark |
| `python run_audit.py <path>` | Full audit pipeline |
| `python run_audit.py <path> --resume` | Resume from checkpoint |
| `python -m src.main setup` | Print setup instructions |
| `python -m src.main update-cve` | Download/build CVE database |
| `python -m src.main eval` | Run evaluation harness |

## CVE Database

NVD (250K+) + EPSS (exploit probability) + CISA KEV (1,635 actively exploited). SQLite with FTS5 + 384-dim embeddings. Hybrid ranking: KEV > EPSS > CVSS.

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
      step0_fingerprint.py             Fingerprinting + SBOM
      step1_classify.py                15+ target types
      step2_deps.py                    Dependency vuln scan
      step2_secrets.py                 Secrets scanner
      step3_static.py                  Static analysis (signal boost)
      step4_threat_model.py            Threat model + CVE catalog (foundation)
      step5_fuzz.py                    N-pass clean-context fuzz audit
      step5b_triage.py                 Candidate verification + dedup
      step6_deep_trace.py              Iterative deep trace + checkpointing
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
    cve/nvd.sqlite                     Unified CVE database
    checkpoints/                       Per-repo audit state + per-hyp trace state
  config.yaml, requirements.txt
  start_server.py, run_benchmark.py, run_audit.py
```

## Caveats

- Authorized security research only. Confirmation required before every audit.
- Model quality ceiling: IQ3_M at 3B active params may miss complex multi-hop logic. More quantization = better reasoning.
- False positives in fuzz phase are by design. Triage phase discards them.
- Local-only model — no data leaves your machine. No API costs.

## License

For authorized security research only. Unauthorized use may violate computer fraud laws.
