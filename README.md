# Local Vuln Research System

LLM-driven vulnerability research pipeline. Uses a local uncensored MoE model (Qwen3.6 35B, 3B active, IQ3_M) to audit ANY source code for real, exploitable High/Critical vulnerabilities. Not a static analyzer. The LLM is the primary reasoning engine — it hunts vulns by understanding code, guided by a CVE exploit pattern catalog.

## Architecture

```
[Target Repo]
    |
Step 0 ─ Fingerprint + SBOM              (deterministic, 100% of files)
Step 1 ─ Classify target                 (15+ target types: kernel, IDE, compiler, AI, etc.)
Step 2 ─ Dependency vuln scan            (NVD + EPSS/KEV ranked)
Step 2b─ Secrets scan                    (gitleaks rules, all text files)
Step 3 ─ Static analysis (signal boost)  (Semgrep + sink finder + taint flow)
    |    Covers 100% of code              (11 languages, 200+ sink patterns)
Step 4 ─ CVE exploit pattern catalog     (15 exploit classes, KEV-prioritized, hunting guidance)
Step 5 ─ LLM-driven vulnerability hunt   (LLM reasons about code, generates hypotheses)
Step 6 ─ Iterative deep code trace       (LLM requests files it needs, per-hypothesis checkpoint)
Step 7 ─ Validation + chain synthesis    (12 filters + LLM chains medium findings into critical)
Step 8 ─ Anomaly check                   (prompt injection detection)
Step 9 ─ Report + runnable PoC           (root cause, exploit path, steps, impact, remediation)
    |
Output: 0-2 HIGH/CRITICAL findings, or "SECURE"
```

**Key difference from SAST tools**: Steps 5-7 are LLM-driven. The LLM receives a full CVE exploit catalog organized by attack class, a codebase overview with directory structure and hot files, and reasons about code directly. It hunts for patterns analogous to known exploits, not just regex matches.

## Language & Target Coverage

| Language | Sinks | Entry Points | Semgrep | Secrets |
|----------|-------|-------------|---------|---------|
| Python | 20 patterns | 14 source types | full | full |
| JavaScript/TS | 11 | 6 source types | full | full |
| Java | 12 | 9 source types | full | full |
| C# | 21 | 13 source types | full | full |
| C/C++ | 12 | 17 source types (kernel, ioctl, exported API) | partial | full |
| Go | 9 | 10 source types | partial | full |
| Rust | 9 | 12 source types (unsafe, FFI) | partial | full |
| PHP | 19 | 14 source types | partial | full |
| Ruby | 7 | 10 source types | partial | full |
| PowerShell | 17 | 16 source types (param, args, cmdlet, COM) | — | full |

**Target classifications**: kernel, browser/sandbox, PowerShell, AI/ML framework, compiler, embedded/IoT, native C/C++ library, distributed system, container runtime, CLI tool, Java platform, .NET platform, web application, IDE/editor, database, protocol handler, general application.

**Attack surface detection**: HTTP endpoints, CLI arguments, syscalls, ioctl handlers, IPC messages, plugin APIs, file parsing, kernel userspace boundaries, PowerShell remoting, FFI boundaries, exported APIs.

## Hardware

**Tested configuration:**
- GPU: RTX 4070 Ti SUPER (16GB VRAM)
- CPU: Ryzen 7 7700 (8C/16T)
- RAM: 32GB DDR5 6000MHz
- Model: Qwen3.6-35B-A3B IQ3_M (15GB, fits VRAM fully)
- Performance: **39 tok/s**, 100% JSON compliance, 131K context usable
- Server: llama.cpp with `--jinja` (Qwen chat template), flash attention, Q4 KV cache

## Quick Start

### 1. Prerequisites

**Windows:**
```
winget install llama.cpp
pip install huggingface_hub
```

**macOS / Linux:**
```
brew install llama.cpp
pip install huggingface_hub
```

### 2. Download model

```
huggingface-cli download HauhauCS/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive \
  Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-IQ3_M.gguf \
  --local-dir models/
```

Available quants:

| Quant | Size | VRAM needed |
|-------|------|-------------|
| `IQ3_M` | 15 GB | 16GB — full GPU fit, zero PCIe latency |
| `IQ4_XS` | 19 GB | 24GB — better quality |
| `Q4_K_M` | 21 GB | 32GB — best quality |

### 3. Install dependencies

```
pip install -r requirements.txt
```

### 4. Start model server

```
python start_server.py
```

Tunable:
```
python start_server.py --quant iq4_xs --context 65536 --ncmoe 24
```

### 5. Get NVD API key

https://nvd.nist.gov/developers/request-an-api-key (free, 30 seconds)

### 6. Download CVE database

```powershell
$env:NVD_API_KEY="your-key-here"
python -m src.main update-cve
```

Downloads 250K+ CVEs with EPSS, KEV. ~45 min with API key.

### 7. Benchmark model (optional)

```
python run_benchmark.py
```

### 8. Audit

```
python run_audit.py /path/to/target-repo
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

---

## Pipeline Deep Dive

### Step 3 — Static Analysis (Signal Boost, Not Gate)

Runs all deterministic analyzers in parallel:
- **Semgrep**: Built-in `p/default` rule set + custom rules
- **Sink finder**: 200+ regex patterns across 11 languages — command injection, SQLi, SSRF, deserialization, buffer overflow, path traversal, XXE, format string, crypto, PowerShell-specific (Invoke-Expression, Add-Script, & operator, COM interop)
- **Taint flow**: Source→sink matching with 50+ source type patterns across all languages
- **File inventory**: Full directory tree with language counts and hot-file ranking

Zero taint flows does NOT block the pipeline. The LLM gets the full codebase overview and hunts independently.

### Step 4 — CVE Exploit Pattern Catalog

Queries the unified CVE database and builds a structured catalog:
- **15 exploit classes**: memory safety, command injection, SQLi, deserialization, SSRF, auth bypass, path traversal, XXE, race condition, crypto, info leak, privilege escalation, XSS, CSRF, format string
- **Per-class hunting guidance**: tells the LLM exactly what to look for
- **KEV-prioritized**: actively exploited CVEs highlighted
- **Cross-technology**: searches for CVEs in similar target types, not just exact matches

### Step 5 — LLM-Driven Hunting

The LLM receives:
1. Full CVE exploit catalog with per-class search guidance
2. Complete codebase overview (directory tree, language breakdown, hot files)
3. Attack surface hints for this target type
4. Strategic code samples (entry points, hot files, large important files)

The LLM outputs:
- Exploit hypotheses with exact file:line references
- Files it wants to inspect next (fed to Step 6)
- Confidence and priority scores
- Self-consistency (3-run consensus) for borderline findings

### Step 6 — Iterative Deep Trace

- **Per-hypothesis checkpointing**: if a 3-hour trace crashes, resume from where it left off
- **LLM requests missing files**: up to 5 iterations of "I need handler.c to verify" → system loads it → LLM continues
- **Methodology-specific tracing**: kernel traces differently from web app traces differently from PowerShell

### Step 7 — Validation + Chain Synthesis

- **12 hard/standard filters**: Precondition Power Test, Reachability Gate, Circular Threat, Trusted Input Reclass, DoS Exclusion, AI Slop Check, etc.
- **LLM-driven chain synthesis**: if no single HIGH/CRIT finding, LLM checks if medium findings chain together (SSRF + auth bypass, file write + path traversal, etc.)

### Step 8 — Prompt Injection Detection

Compares LLM findings ratio against calibrated baseline from clean repos. If ratio falls below 3σ, flags anomaly.

---

## Output

Findings: `data/checkpoints/<repo_hash>/report.md`

Each report:
- Root cause analysis with file:line references
- Runnable Proof of Concept (setup + exploit code + step-by-step + expected output)
- Real-world attack scenarios
- Impact assessment
- Remediation with code diff
- Validation checklist

### Progress Tracking

`data/checkpoints/<repo_hash>/progress.md`:

```
| Step | Name              | Status  | Duration |
|------|-------------------|---------|----------|
| 0    | Fingerprint + SBOM | Done   | 2.3s     |
| 1    | Classification     | Done   | 1.1s     |
| 2    | Dependency Vulns   | Done   | 4.7s     |
| 2b   | Secrets Scan       | Done   | 0.8s     |
| 3    | Static Analysis    | Done   | 28.3s    |
| 4    | CVE Catalog        | Done   | 14.5s    |
| 5    | LLM Hunting        | Done   | 142s     |
| 6    | Deep Trace         | Running... | -   |
```

Content-hash checkpointing: editing code → new hash → fresh audit. Power cut → `--resume` resumes from last completed step.

---

## CVE Database

| Source | Content | Update |
|--------|---------|--------|
| NVD CVEList V5 | 250K+ CVEs — descriptions, CVSS, CWE, CPE | Weekly |
| EPSS | Exploit prediction scoring (30-day probability) | Daily |
| CISA KEV | Known Exploited Vulnerabilities catalog (1,635 actively exploited) | Daily |

SQLite with FTS5 full-text search. Embeddings (all-MiniLM-L6-v2, 384-dim) for semantic retrieval. Hybrid ranking: KEV > EPSS > CVSS > recency.

---

## Configuration

`config.yaml` (AUTO values set by benchmark):

```yaml
model:
  quant: "IQ3_M"
  file: "models/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-IQ3_M.gguf"

server:
  port: 8080
  context_length: AUTO   # Benchmark result: 131K optimal
  ncmoe: AUTO            # Benchmark result
  flash_attn: true

pipeline:
  max_hypotheses: AUTO
  self_consistency_runs: 3
  parallel_analyzers: 16

thresholds:
  hypothesis_confidence_cutoff: AUTO  # Eval calibration
  epss_min_score: 0.01

knowledge:
  sources:
    nvd: true
    epss: true
    kev: true
```

---

## File Structure

```
  models/                              GGUF model files
  src/
    orchestrator.py                    Master pipeline + checkpointing
    pipeline/
      step0_fingerprint.py             Repo fingerprinting + SBOM
      step1_classify.py                15+ target types
      step2_deps.py                    Dependency vuln scan
      step2_secrets.py                 Secrets scanner
      step3_static.py                  Static analysis (signal boost)
      step4_cve.py                     CVE exploit pattern catalog
      step5_hypotheses.py              LLM-driven hunting (primary analysis)
      step6_deep_trace.py              Iterative deep trace + checkpointing
      step7_validate.py                Filters + LLM chain synthesis
      step8_anomaly.py                 Injection detection
      step9_report.py                  Report + PoC
    analysis/
      sink_finder.py                   200+ sink patterns, 11 languages
      data_flow.py                     50+ source patterns, all languages
      semgrep_runner.py                Semgrep integration
      secrets_scanner.py               gitleaks rules
      ast_parser.py                    tree-sitter AST
      call_graph.py                    Call graph builder
    knowledge/
      downloader.py                    NVD/EPSS/KEV fetcher
      importer.py                      SQLite builder
      cve_db.py                        FTS5 + embedding search
      embeddings.py                    all-MiniLM-L6-v2
      epss.py + kev.py                Score queries
      sbom.py                          Multi-format SBOM parser
    llm/
      client.py                        OpenAI-compatible API + JSON repair
      prompts.py                       Methodology prompts + guard
      context.py                       Context window management
      guard.py                         Injection guard + anomaly detection
    eval/
      harness.py, datasets.py,
      metrics.py, calibration.py
  data/
    cve/nvd.sqlite                     Unified CVE database
    rules/                             Custom semgrep rules
    checkpoints/                       Per-repo audit state + per-hypothesis trace state
  config.yaml                          Main configuration
  start_server.py                      Start llama-server
  run_benchmark.py / run_audit.py      Python runners
```

## Caveats

- Authorized security research only. The tool enforces authorization confirmation before every audit.
- LLM steps require the model server running. Steps 0-4 run without LLM.
- First CVE download: ~45 min with free NVD API key. Embedding generation: CPU, ~30 min.
- GPU utilization shown in `nvidia-smi` (77%). Windows Task Manager reports compute differently.

## License

For authorized security research only. Unauthorized use may violate computer fraud laws.
