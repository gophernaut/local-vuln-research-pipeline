# Local Vuln Research System

LLM-driven exhaustive vulnerability research pipeline using a local code-specialized model. Not a SAST — the LLM reviews every source file with short, focused prompts in a 3-stage pipeline validated by [Project Black's research](https://projectblack.io/blog/local-ai-for-cyber-security/). The approach has found real 0-days in production codebases.

## Architecture

```
[Target Repo]
    |
Step 0  ─ Fingerprint + SBOM              (deterministic, full file inventory)
Step 1  ─ Classify target                 (17+ types, dual-language detection)
Step 2  ─ Dependency vuln scan            (NVD + EPSS/KEV ranked)
Step 2b ─ Secrets scan                    (gitleaks rules)
Step 3  ─ Static analysis                 (Semgrep + 200 sink patterns + taint flow, 11 languages)
Step 4  ─ Threat model + CVE catalog      (1 LLM pass, product-specific CVE search, coverage plan)
Step 5  ─ Exhaustive 3-stage fuzz         (per-file: pattern scan → reachability → document)
Step 5b ─ Triage                          (skeptic independent verification against source)
Step 6  ─ Iterative deep trace            (exact file loading, per-hyp checkpoint)
Step 7  ─ Validation + chain synthesis    (12 filters + LLM chain synthesis)
Step 8  ─ Anomaly check                   (prompt injection detection)
Step 9  ─ Report + PoC                    (root cause, exploit path, remediation)
    |
Output: Verified findings with source-reasoned evidence
```

**Validated by Project Black research**: The architecture mirrors the approach that found 0-days in PHPIPAM and myVesta — one focused file batch per pass, short specific prompts, simple tasks the model can handle, complex reasoning deferred to triage/deep-trace stages.

### Step 5 — 3-Stage File-by-File Scan

Each batch of files goes through 3 focused stages:

| Stage | Task | Prompt complexity |
|-------|------|------------------|
| 1. Pattern scan | Find dangerous calls: exec, Process.Start, AddScript, Path.Combine(user), deserialization, SSRF, secrets | ~10 lines |
| 2. Reachability | For each pattern: can a low-privileged attacker reach it? Check auth, validators, sanitizers | ~12 lines |
| 3. Document | Write structured finding: class, entry point, severity, confidence | ~8 lines |

Each prompt is short enough for any model to handle reliably. No 120-line monster prompts.

## Hardware

**Tested config:**
- GPU: RTX 4070 Ti SUPER (16GB VRAM)
- CPU: Ryzen 7 7700 (8C/16T)
- RAM: 32GB DDR5 6000MHz
- Model: Qwen2.5-Coder-7B-Abliterated Q6_K (7B dense, 6.25GB)
- Draft model: Qwen2.5-Coder-0.5B Q4_K_M (~400MB) for speculative decoding
- Performance: 40-60 tok/s base, **60-90 effective tok/s** with speculative decoding
- Context: 131K tokens (6.25GB model leaves 9.75GB free for KV cache)
- Server: llama.cpp with `--jinja`, flash attention, Q4 KV cache

## Quick Start

### 1. Prerequisites
```powershell
winget install llama.cpp      # Windows
brew install llama.cpp         # macOS / Linux
pip install -r requirements.txt
pip install huggingface_hub
```

### 2. Download models
```powershell
# Main model: Qwen2.5-Coder-7B-Abliterated Q6_K (6.25 GB)
huggingface-cli download bartowski/Qwen2.5-Coder-7B-Instruct-abliterated-GGUF `
  Qwen2.5-Coder-7B-Instruct-abliterated-Q6_K.gguf --local-dir models/

# Draft model: Qwen2.5-Coder-0.5B Q4_K_M (377 MB)
huggingface-cli download bartowski/Qwen2.5-Coder-0.5B-Instruct-abliterated-GGUF `
  Qwen2.5-Coder-0.5B-Instruct-abliterated-Q4_K_M.gguf --local-dir models/
```

### 3. Start model server
```powershell
python start_server.py
```
Auto-detects draft model and enables speculative decoding. Use `--no-speculative` to disable.

```powershell
# Custom options
python start_server.py --context 65536 --threads 4 --port 9090
```

### 4. Get free NVD API key
https://nvd.nist.gov/developers/request-an-api-key (30 seconds)

### 5. Download CVE database
```powershell
$env:NVD_API_KEY="your-key-here"
python -m src.main update-cve
```
~45 min. 364K+ CVEs with EPSS + KEV, product-specific search.

### 6. Audit
```powershell
python run_audit.py /path/to/target-repo
python run_audit.py /path/to/target-repo --resume   # resume from checkpoint
```

---

## Pipeline Deep Dive

### Steps 0-3: Deterministic Foundation

**Step 0 — Fingerprinting**: Detects languages, frameworks, build systems. Framework detection scans only manifest/config files (not every source file) and excludes test directories to avoid false signals.

**Step 1 — Classification**: 17 target types. Dual-language detection handles repos like PowerShell (C# + PS). Specialized types match before generic types.

**Step 3 — Static Analysis**: Full file inventory (not capped at 50 files). Semgrep + 200+ sink patterns + 50+ taint flow sources across 11 languages. Serves as signal boost, not gate — zero findings does not block the pipeline.

### Step 4: Threat Model + CVE Catalog

One LLM pass builds the attack surface map: entry points, trust boundaries, sink inventory, data flows. CVE catalog uses **product-specific searches** — PowerShell repos get PowerShell CVEs, .NET gets deserialization CVEs. Coverage plan includes ALL non-test source files, ranked by priority (entry points > sink-heavy > remaining). Robust static analysis fallback when LLM call fails.

### Step 5: Exhaustive 3-Stage Fuzz

**Every non-test source file** goes through 3 focused stages. No sampling, no shortcuts.

**Stage 1 — Pattern Scan**: "Find these 9 dangerous patterns: command injection, path traversal, code injection, deserialization, auth bypass, SSRF, hardcoded secrets, race conditions, info leak." Simple pattern matching — any model handles this.

**Stage 2 — Reachability Filter**: "For each pattern, can a low-privileged attacker reach it? Check auth guards, input validators, sanitizers." Drops unreachable patterns before they waste downstream resources.

**Stage 3 — Document**: "Write each finding with class, entry point, severity, confidence." Structured JSON output.

Each stage has a **8-12 line prompt** — short enough that even smaller models respond reliably. The blog research confirmed: "once pointed at the correct file, almost every model identified the vulnerability immediately." Complex multi-hop reasoning is deferred to Steps 5b/6/7.

**Dynamic batch packing**: Files are greedily packed into 400K char context budget (~100K tokens). Large files get dedicated passes; small files bundle 10-20 per pass. Per-batch checkpointing for resume.

### Step 5b: Triage

5-step skeptical verification: Read actual code → trace independently → check all mitigations → assess honestly → provide evidence. Full source files loaded. Every kept finding requires concrete source reasoning.

### Steps 6-7: Deep Trace + Validation

Exact referenced files loaded first (component → rglob → trace hops → sink files). LLM requests files mid-trace (up to 5 iterations). 12 validation filters + LLM chain synthesis.

---

## Time Budget (7B Dense + Speculative Decoding)

| Repo Size | Files in Plan | Est. Batches | Est. Time |
|-----------|---------------|-------------|-----------|
| Small (~200 files) | ~150 | ~25 | ~8-12 min |
| Medium (~800 files) | ~600 | ~100 | ~30-50 min |
| Large (~2000 files) | ~1400 | ~230 | ~70-120 min |
| Very Large (~5000 files) | ~3500 | ~580 | ~3-5 hours |

Each batch = 3 LLM calls (pattern + reachability + document). Time scales linearly. Checkpoint/resume at every batch.

## Checkpointing

```
data/checkpoints/<hash>/
├── progress.md              Human-readable: batch 87/230, 23 candidates
├── fuzz_progress.json       Coverage tracker + accumulated candidates
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
| `python start_server.py` | Start llama-server with speculative decoding |
| `python start_server.py --no-speculative` | Start without draft model |
| `python run_audit.py <path>` | Full audit (exhaustive 3-stage fuzz) |
| `python run_audit.py <path> --resume` | Resume from checkpoint |
| `python -m src.main setup` | Print setup instructions |
| `python -m src.main update-cve` | Download/build CVE database |

## Configuration

```yaml
model:
  name: "Qwen2.5-Coder-7B-Abliterated"
  file: "models/Qwen2.5-Coder-7B-Instruct-abliterated-Q6_K.gguf"
  draft_file: "models/Qwen2.5-Coder-0.5B-Instruct-abliterated-Q4_K_M.gguf"

server:
  context_length: 131072
  flash_attn: true
  cache_type_k: "q4_0"
  cache_type_v: "q4_0"
  speculative:
    enabled: true
    draft_n_max: 16

pipeline:
  self_consistency_runs: 3

knowledge:
  sources: [nvd, epss, kev]
```

---

## File Structure

```
  models/                              GGUF model files (main + draft)
  src/
    orchestrator.py                    Master pipeline + checkpointing
    pipeline/
      step0_fingerprint.py             Fingerprinting (manifest-only framework detect)
      step1_classify.py                17+ types + dual-language
      step2_deps.py                    Dependency vuln scan
      step2_secrets.py                 Secrets scanner
      step3_static.py                  Static analysis (full file inventory)
      step4_threat_model.py            Threat model + product-specific CVEs
      step5_fuzz.py                    3-stage exhaustive fuzz (pattern→reach→document)
      step5_hypotheses.py              Hypothesis generation
      step5b_triage.py                 5-step skeptical verification
      step6_deep_trace.py              Iterative deep trace + exact file loading
      step7_validate.py                Filters + chain synthesis
      step8_anomaly.py                 Injection detection
      step9_report.py                  Report + PoC
    analysis/
      sink_finder.py                   200+ patterns, 11 languages
      data_flow.py                     50+ source patterns
    knowledge/
      downloader.py, importer.py, cve_db.py, embeddings.py, epss.py, kev.py, sbom.py
    llm/
      client.py, prompts.py, context.py, guard.py
  data/
    cve/nvd.sqlite                     CVE database (364K+)
    checkpoints/                       Per-repo audit state
  config.yaml, requirements.txt
  start_server.py, run_audit.py
```

## Design Principles

- **Exhaustive coverage**: Every non-test source file is reviewed. No sampling.
- **Short, focused prompts**: 3-stage approach with 8-12 line prompts per stage. Any model can handle them.
- **Clean context per batch**: No memory between batches. Each starts fresh.
- **Skeptic triage**: Every finding is independently verified against source code.
- **Product-specific intelligence**: CVEs targeted to the actual tech stack, not generic top-10.
- **Proven methodology**: Architecture validated by Project Black research finding real 0-days.
- **Local only**: No data leaves your machine. No API costs.

## References

- [Project Black: Local AI for Penetration Testing & Research](https://projectblack.io/blog/local-ai-for-cyber-security/) — validated the file-by-file approach
- [RAPTOR: Autonomous Offensive/Defensive Research Framework](https://github.com/gadievron/raptor) — validation pipeline inspiration
- Model: [Qwen2.5-Coder-7B-Abliterated](https://huggingface.co/bartowski/Qwen2.5-Coder-7B-Instruct-abliterated-GGUF)

## License

For authorized security research only. Unauthorized use may violate computer fraud laws.
