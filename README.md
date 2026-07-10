# Local Vuln Research System

LLM-driven exhaustive vulnerability research pipeline using a local code-specialized 14B model. Not a SAST — the LLM reviews every source file with short, focused 3-stage prompts validated by [Project Black's research](https://projectblack.io/blog/local-ai-for-cyber-security/). This approach has found real 0-days in production codebases.

## Architecture

```
[Target Repo]
    |
Step 0  ─ Fingerprint + SBOM              (deterministic, full file inventory)
Step 1  ─ Classify target                 (17+ types, dual-language detection)
Step 2  ─ Dependency vuln scan            (NVD + EPSS/KEV ranked)
Step 2b ─ Secrets scan                    (gitleaks rules)
Step 3  ─ Static analysis                 (Semgrep + 200 sink patterns + taint flow, 11 languages)
Step 4  ─ Threat model + CVE catalog      (1 LLM pass, product-specific CVE search)
Step 5  ─ Exhaustive 3-stage fuzz         (per-file: pattern scan → reachability → document)
Step 5b ─ Triage                          (skeptic independent verification against source)
Step 6  ─ Iterative deep trace            (exact file loading, per-hyp checkpoint)
Step 7  ─ Validation + chain synthesis    (12 filters + LLM chain synthesis)
Step 8  ─ Anomaly check                   (prompt injection detection)
Step 9  ─ Report + PoC                    (root cause, exploit path, remediation)
    |
Output: Verified findings with source-reasoned evidence
```

### Step 5 — 3-Stage File-by-File Scan

Each batch of files goes through 3 focused stages:

| Stage | Task | Prompt size |
|-------|------|-------------|
| 1. Pattern scan | Find dangerous calls: exec, Process.Start, AddScript, Path.Combine(user), deserialization, SSRF, secrets | ~10 lines |
| 2. Reachability | For each pattern: can a low-privileged attacker reach it? Check auth, validators, sanitizers | ~12 lines |
| 3. Document | Write structured finding: class, entry point, severity, confidence | ~8 lines |

Short, focused prompts — any model handles them reliably. Complex reasoning deferred to triage/deep-trace.

## Hardware

**Tested config:**
- GPU: RTX 4070 Ti SUPER (16GB VRAM)
- CPU: Ryzen 7 7700 (8C/16T)
- RAM: 32GB DDR5 6000MHz
- Model: Qwen2.5-Coder-14B-Abliterated Q4_K_M (14B dense, 8.6GB)
- Draft model: Qwen2.5-Coder-0.5B Q4_K_M (~400MB) for speculative decoding
- Total VRAM: ~9GB models, ~7GB free for KV cache
- Performance: 25-35 tok/s base, **35-50 effective tok/s** with speculative decoding
- Context: 32K tokens (model training limit)
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
# Main model: Qwen2.5-Coder-14B-Abliterated Q4_K_M (8.6 GB)
huggingface-cli download bartowski/Qwen2.5-Coder-14B-Instruct-abliterated-GGUF `
  Qwen2.5-Coder-14B-Instruct-abliterated-Q4_K_M.gguf --local-dir models/

# Draft model for speculative decoding (377 MB)
huggingface-cli download bartowski/Qwen2.5-Coder-0.5B-Instruct-abliterated-GGUF `
  Qwen2.5-Coder-0.5B-Instruct-abliterated-Q4_K_M.gguf --local-dir models/
```

### 3. Start model server
```powershell
python start_server.py
```
Reads model path from `config.yaml`. Auto-detects draft model. Use `--no-speculative` to disable.

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

**Step 0 — Fingerprinting**: Languages, frameworks, build systems. Framework detection scans only manifest files, excludes test directories.

**Step 1 — Classification**: 17 target types with dual-language detection (e.g., PowerShell = C# + PS). Specialized types match before generic.

**Step 3 — Static Analysis**: Full file inventory (not capped). Semgrep + 200+ sink patterns + 50+ taint sources across 11 languages. Signal boost, not gate.

### Step 4: Threat Model + CVE Catalog

One LLM pass: entry points, trust boundaries, sink inventory, data flows. Product-specific CVE searches. Coverage plan: ALL non-test source files ranked by priority. Static analysis fallback when LLM fails.

### Step 5: Exhaustive 3-Stage Fuzz

**Every non-test source file** goes through 3 stages. No sampling.

**Stage 1 — Pattern Scan**: "Find 9 dangerous patterns: command injection, path traversal, code injection, deserialization, auth bypass, SSRF, secrets, race conditions, info leak." Simple pattern matching.

**Stage 2 — Reachability Filter**: "Can a low-privileged attacker reach each pattern? Check auth, validators, sanitizers." Drops dead ends.

**Stage 3 — Document**: "Write each finding with class, entry point, severity, confidence." Structured JSON.

Each prompt is ~10 lines. Blog research confirms: "once pointed at the correct file, almost every model identified the vulnerability immediately."

**Dynamic batch packing**: Files greedily packed into auto-calculated context budget (~86K chars for 32K context). Large files get dedicated batches; small files bundle together. Per-batch checkpointing.

### Step 5b: Triage

5-step verification: Read actual code → trace independently → check all mitigations → assess honestly → provide evidence. Full source files loaded.

### Steps 6-7: Deep Trace + Validation

Exact referenced files loaded first. Up to 5 iteration mid-trace file requests. 12 validation filters + LLM chain synthesis.

---

## Time Budget (14B Q4_K_M + Speculative Decoding)

| Repo Size | Files in Plan | Est. Batches | Est. Time |
|-----------|---------------|-------------|-----------|
| Small (~200 files) | ~150 | ~50 | ~15-25 min |
| Medium (~800 files) | ~600 | ~200 | ~1-2 hours |
| Large (~2000 files) | ~1400 | ~450 | ~3-6 hours |
| Very Large (~5000 files) | ~3500 | ~900 | ~6-12 hours |

Each batch = 3 LLM calls. Time scales linearly. Checkpoint/resume at every batch.

## Checkpointing

```
data/checkpoints/<hash>/
├── progress.md              Human-readable: batch 87/450, 23 candidates
├── fuzz_progress.json       Coverage tracker + accumulated candidates
├── fuzz_candidates.json     All raw candidates
├── triaged.json             Post-triage verified findings
├── trace_hyp_0.json         Per-hypothesis deep trace checkpoints
├── validated_findings.json
├── report.md
└── threat_model.json
```

---

## Commands

| Command | Description |
|---------|-------------|
| `python start_server.py` | Start server (reads model from config.yaml) |
| `python start_server.py --no-speculative` | Start without draft model |
| `python run_audit.py <path>` | Full exhaustive audit |
| `python run_audit.py <path> --resume` | Resume from checkpoint |
| `python -m src.main setup` | Setup instructions |
| `python -m src.main update-cve` | Download/build CVE database |

## Configuration

```yaml
model:
  name: "Qwen2.5-Coder-14B-Abliterated"
  file: "models/Qwen2.5-Coder-14B-Instruct-abliterated-Q4_K_M.gguf"

server:
  context_length: 32768
  flash_attn: true
  speculative:
    enabled: true

pipeline:
  self_consistency_runs: 3

knowledge:
  sources: [nvd, epss, kev]
```

## File Structure

```
  models/                              GGUF files (main + draft)
  src/
    orchestrator.py                    Master pipeline + checkpointing
    pipeline/
      step0_fingerprint.py             Fingerprinting (manifest-only framework detect)
      step1_classify.py                17+ types + dual-language
      step2_deps.py                    Dependency vuln scan
      step2_secrets.py                 Secrets scanner
      step3_static.py                  Static analysis (full file inventory)
      step4_threat_model.py            Threat model + product-specific CVEs
      step5_fuzz.py                    3-stage exhaustive fuzz
      step5_hypotheses.py              Hypothesis generation
      step5b_triage.py                 5-step skeptical verification
      step6_deep_trace.py              Iterative deep trace
      step7_validate.py                Filters + chain synthesis
      step8_anomaly.py                 Injection detection
      step9_report.py                  Report + PoC
    analysis/
      sink_finder.py                   200+ patterns, 11 languages
      data_flow.py                     50+ source patterns
    knowledge/
      cve_db.py, downloader.py, importer.py, embeddings.py, epss.py, kev.py, sbom.py
    llm/
      client.py, prompts.py, context.py, guard.py
  data/
    cve/nvd.sqlite                     CVE database (364K+)
    checkpoints/                       Per-repo audit state
  config.yaml, requirements.txt
  start_server.py, run_audit.py
```

## Design Principles

- **Exhaustive coverage**: Every non-test source file reviewed. No sampling.
- **Short, focused prompts**: 3-stage approach with ~10-line prompts. Any model handles them.
- **Clean context per batch**: No memory between batches.
- **Skeptic triage**: Every finding independently verified against source.
- **Product-specific CVEs**: Targeted to actual tech stack, not generic top-10.
- **Proven methodology**: Validated by Project Black research finding real 0-days.
- **Config-driven model**: Switch models by changing one line in config.yaml.
- **Local only**: No data leaves your machine. No API costs.

## References

- [Project Black: Local AI for Penetration Testing](https://projectblack.io/blog/local-ai-for-cyber-security/)
- [RAPTOR: Autonomous Security Research Framework](https://github.com/gadievron/raptor)
- [Qwen2.5-Coder-14B-Abliterated](https://huggingface.co/bartowski/Qwen2.5-Coder-14B-Instruct-abliterated-GGUF)

## License

For authorized security research only. Unauthorized use may violate computer fraud laws.
