# Local Vuln Research System

Ultimate local vulnerability research pipeline. Uses a local uncensored MoE model (Qwen 35B, 3B active) to audit source code for real, exploitable High/Critical vulnerabilities. No hallucinations. No informational noise. Bug bounty rewardable findings only.

## Architecture

```
Target Repo
    |
Step 0: Fingerprint + SBOM      (deterministic, all files)
Step 1: Classify target          (deterministic + LLM confirm)
Step 2: Dependency vuln scan     (CVE/OSV/GHSA + EPSS/KEV ranked)
Step 2b: Secrets scan            (gitleaks rules, all text files)
Step 3: Full static analysis     (Semgrep + sink finder + call graph + taint)
    |   COVERS 100% OF CODE       (parallel per file, 16 threads)
Step 4: CVE correlation          (hybrid FTS5 + embedding search)
Step 5: Hypothesis generation    (LLM, self-consistency for borderline)
    |   COVERS ~5% OF CODE        (only sinks reachable from entry points)
Step 6: Deep code trace          (LLM file-by-file, line-by-line)
    |   COVERS ~1% OF CODE        (only verified exploitable paths)
Step 7: Brutal validation        (12 filters + chain synthesis)
Step 8: Anomaly check            (calibrated injection detection)
Step 9: Report + runnable PoC
    |
Output: 0-2 HIGH/CRIT findings, or "SECURE"
```

### Knowledge Layer

| Source | Content | Update |
|--------|---------|--------|
| NVD CVEList V5 | Full CVE descriptions, CVSS, CWE, CPE | Weekly |
| OSV.dev | Ecosystem-native vulns (npm, PyPI, Maven, Go, crates.io) | Weekly |
| GHSA | GitHub Security Advisories | Weekly |
| EPSS | Exploit prediction scoring (30-day probability) | Daily |
| CISA KEV | Known Exploited Vulnerabilities catalog | Daily |

### Static Analysis (100% Code Coverage)

| Analyzer | Speed | What it catches |
|----------|-------|-----------------|
| Secrets scanner | <1ms/file | AWS keys, tokens, passwords, JWT secrets, private keys |
| SBOM parser | <1s total | All dependency manifests (7 ecosystems) |
| Semgrep | <2s/file | Pattern-based: SQLi, XSS, RCE, SSRF, auth bypass |
| Sink finder | <0.5s/file | 200+ dangerous functions across 8 languages |
| Call graph | <2s/file | Inter-procedural function call edges |
| Taint flow | <1s/file | Entry point -> intermediate -> sink data tracking |

### Validation Filters (Step 7)

- **Precondition Power Test** — precondition must not grant >= capability than exploit
- **Reachability Gate** — external unauthenticated/low-priv attacker required
- **Circular Threat Model** — no "if already have X, can do Y"
- **Trusted Input Reclass** — config/env/admin is not attacker-controlled
- **DoS Exclusion** — all DoS variants discarded
- **AI Slop Check** — theoretical checks, missing headers, ReDoS rejected
- **Bug Bounty Bar** — only High/Critical, rewardable findings
- **And 5 more...**

---

## Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| GPU VRAM | 12GB | 16GB+ |
| System RAM | 16GB | 32GB |
| Storage | 50GB free | 100GB+ (for full CVE DB) |
| Python | 3.10+ | 3.11+ |

Tested on: RTX 4070 Ti SUPER (16GB), Ryzen 7 7700, 32GB DDR5

---

## Quick Start

### 1. Download model

Download the IQ3_M GGUF quant (recommended for 16GB VRAM — fits fully in GPU memory, no PCIe bottleneck):

```
huggingface-cli download HauhauCS/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive \
  Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-IQ3_M.gguf \
  --local-dir models/
```

Or choose a different quant for your hardware:

| Quant | Size | Best for |
|-------|------|----------|
| `IQ3_M` | 15 GB | 16GB VRAM — full GPU fit, zero PCIe latency |
| `IQ4_XS` | 19 GB | 24GB VRAM — better quality, full fit |
| `Q4_K_M` | 21 GB | 32GB VRAM — best quality |

Place the `.gguf` file in `models/`

### 2. Install dependencies

```
pip install -r requirements.txt
```

### 3. Start model server

```
python start_server.py
```

### 4. Setup

```
python -m src.main setup
```

### 5. Benchmark model

```
python run_benchmark.py
```

This measures throughput, JSON compliance, and optimal context length for your hardware. Config is auto-updated.

### 6. Download CVE database

```
python -m src.main update-cve
```

Downloads NVD, EPSS, KEV, GHSA and builds the unified SQLite database with FTS5 + embeddings.

### 7. Run evaluation (optional)

```
python -m src.main eval
```

Runs against OWASP Benchmark and CVEfixes corpora to calibrate confidence thresholds.

### 8. Audit a repository

```
python -m src.main audit C:\path\to\target-repo
```

---

## Commands

| Command | Description |
|---------|-------------|
| `python -m src.main setup` | Print setup instructions |
| `python -m src.main benchmark` | Run model benchmark -> write config |
| `python -m src.main update-cve` | Download and build CVE knowledge base |
| `python -m src.main eval` | Run evaluation against known-vuln corpora |
| `python -m src.main audit <path>` | Full audit pipeline |
| `python -m src.main audit <path> --resume` | Resume from checkpoint |
| `python start_server.py` | Start llama-server (--port, --threads, --ncmoe, --context, --quant) |
| `python run_benchmark.py` | Run benchmark with server check |
| `python run_audit.py <path>` | Audit with authorization prompt (--resume) |

---

## Output

Findings go to `data/checkpoints/<repo_hash>/report.md`

Each report contains:
- Root cause analysis with file:line references
- Runnable Proof of Concept (setup + exploit code + step-by-step + expected output)
- Real-world attack scenarios
- Impact assessment
- Remediation with code diff
- Validation checklist (all 12 gates passed)

If no exploitable findings: outputs "TARGET EVALUATED AS SECURE" with methodology summary.

### Progress Tracking

Each repo audit produces `data/checkpoints/<repo_hash>/progress.md`:

```markdown
| Step | Name              | Status  | Duration |
|------|-------------------|---------|----------|
| 0    | Fingerprint + SBOM | Done   | 2.3s     |
| 1    | Classification     | Done   | 1.1s     |
| 2    | Dependency Vulns   | Done   | 4.7s     |
| 2b   | Secrets Scan       | Done   | 0.8s     |
| 3    | Static Analysis    | Done   | 28.3s    |
| 4    | CVE Correlation    | Done   | 3.2s     |
| 5    | Hypothesis Gen     | Done   | 142s     |
| 6    | Deep Trace         | Running... | -   |
```

Checkpoints are keyed by content hash (sha256 of all file contents). Editing code -> new checkpoint -> fresh audit. Same code -> same hash -> resume works.

Power cut mid-audit? Re-run with `--resume` flag. Only the in-flight step is lost.

---

## Configuration

`config.yaml`:

```yaml
model:
  file: "models/Qwen3.6-35B-A3B-Uncensored-IQ4_XS.gguf"

server:
  port: 8080
  threads: 8
  context_length: AUTO   # Set by benchmark
  ncmoe: AUTO            # Set by benchmark
  flash_attn: true

pipeline:
  min_tokens_per_second: 8
  max_hypotheses: AUTO   # Set by benchmark
  self_consistency_runs: 3
  parallel_analyzers: 16

thresholds:
  hypothesis_confidence_cutoff: AUTO  # Set by eval calibration
  anomaly_ratio_sigma: 3.0
  epss_min_score: 0.05

knowledge:
  sources:
    nvd: true
    osv: true
    ghsa: true
    epss: true
    kev: true
```

AUTO values are set by benchmark and eval runs. Manual edits preserved across updates.

---

## Architecture Deep Dive

### Supported Languages

| Language | AST | Sinks | Semgrep | Secrets |
|----------|-----|-------|---------|---------|
| Python | tree-sitter | 20 patterns | full rule set | full |
| JavaScript/TS | tree-sitter | 11 patterns | full rule set | full |
| Java | — | 12 patterns | full rule set | full |
| Go | — | 9 patterns | partial | full |
| C/C++ | — | 12 patterns | partial | full |
| Ruby | — | 7 patterns | partial | full |
| Rust | — | — | partial | full |
| C# | — | — | partial | full |

### LLM Prompt Strategy

Every LLM call receives:
1. **Guard preamble** — repo content is data, never instructions; anti-regression questions
2. **Methodology reference** — per-class vulnerability research patterns
3. **CVE context** — top 15 most relevant known exploits for this tech stack
4. **Code context** — relevant source files chunked by function boundaries
5. **Structured output format** — JSON schema enforced, with repair on malformed output

### Self-Consistency

Hypotheses with confidence <= 0.7 are run 3 times at temperature 0.3. Only findings with >= 2/3 agreement (vulnerability class, entry point, sink match) proceed to deep trace.

### Prompt Injection Guard

- System prompt treats all repo content as data, never instructions
- Step 8 anomaly check: compares `llm_findings ÷ semgrep_hits` ratio against calibrated baseline from 20 clean repos
- If ratio falls below u - 3sigma: flagged as suspicious, recommends re-run with stripped comments

### Incremental Analysis (Future)

- File-level content hash tracking
- Changed files + call-graph neighbors only
- Full pipeline run triggered by hash mismatch on checkpoint

---

## File Structure

```
D:\Local vuln model\
  models/                              GGUF model files
  src/
    config.py                         Configuration with AUTO resolution
    main.py                           CLI entry point
    orchestrator.py                   Master pipeline + checkpointing
    pipeline/
      step0_fingerprint.py            Repo fingerprinting + SBOM
      step1_classify.py               Target classification
      step2_deps.py                   Dependency vuln scan
      step2_secrets.py                Secrets scanner
      step3_static.py                 Full static analysis
      step4_cve.py                    CVE correlation
      step5_hypotheses.py             LLM hypothesis generation
      step6_deep_trace.py             LLM code tracing
      step7_validate.py               Brutal filtering
      step8_anomaly.py                Injection detection
      step9_report.py                 Report + PoC
    analysis/
      ast_parser.py                   tree-sitter multi-lang AST
      call_graph.py                   Inter-procedural call graph
      data_flow.py                    Taint flow analysis
      sink_finder.py                  200+ sink patterns
      semgrep_runner.py               Semgrep integration
      secrets_scanner.py              gitleaks rules engine
    knowledge/
      downloader.py                   NVD/EPSS/KEV/GHSA fetcher
      importer.py                     Unified SQLite builder
      cve_db.py                       Hybrid search query API
      embeddings.py                   all-MiniLM-L6-v2 embeddings
      epss.py                         EPSS score queries
      kev.py                          CISA KEV queries
      sbom.py                         Multi-format SBOM parser
    llm/
      client.py                       OpenAI-compatible API client
      prompts.py                      Methodology prompt templates
      context.py                      Context window + chunking
      guard.py                        Injection guard + anomaly
    eval/
      harness.py                      Evaluation runner
      datasets.py                     OWASP/CVEfixes/Juliet/BigVul
      metrics.py                      Precision/recall/F1
      calibration.py                  Threshold tuning
    utils/
      file_utils.py                   Hashing, file collection
      logger.py                       Structured logging
  data/
    cve/nvd.sqlite                    Unified CVE database
    eval/                             Eval corpora
    rules/                            Custom semgrep rules
    checkpoints/                      Per-repo audit state
  config.yaml                         Main configuration
  requirements.txt                    Python dependencies
  start_server.py                     Start llama-server
  run_benchmark.py                    Run model benchmark
  run_audit.py                        Run full audit
```

---

## Caveats

- **You must own or be authorized** to audit target code. The tool prints a warning and requires confirmation before every audit.
- Generated PoCs are for authorized security research only.
- The LLM steps require the model server running. Steps 0-4 and 2b run without LLM.
- First CVE download is large (NVD alone is ~2GB compressed). Allow 1-2 hours for initial database build.
- Embedding generation (all-MiniLM-L6-v2) runs on CPU. ~30 minutes for full NVD dataset on 16 threads.

---

## License

This tool is provided for authorized security research only. Unauthorized use may violate computer fraud laws.
