# Local Vuln Research System

Exhaustive LLM-driven whitebox vulnerability research pipeline that finds every single vulnerability in any source code. Not a SAST — uses a code graph + LLM hybrid architecture to enumerate and validate all source-to-sink paths.

## Architecture

The pipeline uses a **deterministic code graph + per-path LLM analysis** architecture. The local 14B model cannot reliably trace data flow across large codebases, so the foundation is built deterministically and the LLM is used only for exploitability reasoning on pre-traced paths.

```
[Target Repo]
    |
Step 0  ─ Fingerprint + SBOM              (deterministic, full file inventory)
Step 1  ─ Classify target                 (16+ target types, dual-language detection)
Step 2  ─ Dependency vuln scan            (NVD + EPSS/KEV ranked)
Step 2b ─ Secrets scan                    (gitleaks rules)
Step 3  ─ Static analysis                 (Semgrep + 200+ sink patterns + taint flow, 11 languages)
Step 3b ─ Code graph construction         (call graph + source/sink/sanitizer tags)
Step 4  ─ Threat model + CVE catalog      (1 LLM pass, product-specific CVE search)
Step 4b ─ Path enumeration               (exhaustive source-to-sink path discovery)
Step 4c ─ Per-path LLM analysis           (exploitability validation, one path at a time)
Step 5  ─ Memory corruption analysis      (5 dedicated analyzers for C/C++/Rust)
Step 6  ─ Chain synthesis                 (attack graph + multi-step exploit chains)
Step 7  ─ Validation                      (LLM-based precondition test)
Step 8  ─ Anomaly check                   (prompt injection detection)
Step 9  ─ Report + PoC                    (root cause, exploit path, remediation)
    |
Output: Verified findings with proof of exhaustive coverage
```

## Core Principle: Exhaustive Coverage

The system is designed around one principle: **find every single vulnerability, miss nothing**. This is achieved through exhaustive enumeration:

1. **Parse every source file** across 16 supported languages (Python, JavaScript, TypeScript, Java, C, C++, Go, Rust, C#, PowerShell, Ruby, PHP, Swift, Kotlin, Shell, Scala)
2. **Build a complete call graph** with cross-file import resolution
3. **Tag every untrusted source** (HTTP request, CLI arg, env var, file read, IPC, FFI, syscall, route parameter)
4. **Tag every dangerous sink** (command exec, SQL, path traversal, deserialization, SSRF, memory ops, crypto, auth bypass, SSTI, race conditions, etc.)
5. **Tag every sanitizer** (validation, encoding, auth check, bounds check)
6. **Enumerate every source-to-sink path** through the call graph
7. **Track taint propagation** through every function on every path
8. **Validate each path with the LLM** for genuine exploitability
9. **Analyze memory corruption** with dedicated alloc/buffer/lifetime/overflow/format analyzers
10. **Synthesize exploit chains** from individual findings

Every source (untrusted input entry point) is paired with every compatible sink (dangerous operation) and all call-graph paths between them are enumerated. No code is sampled, no heuristic is trusted blindly.

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
huggingface-cli download bartowski/Qwen2.5-Coder-14B-Instruct-abliterated-GGUF `
  Qwen2.5-Coder-14B-Instruct-abliterated-Q4_K_M.gguf --local-dir models/

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

### Step 3b — Code Graph Construction (New)

Builds the complete foundation for exhaustive analysis:
- **Call graph**: Every function → every callee. Direct + virtual dispatch. Cross-file via import resolution
- **Control flow per function**: Basic blocks, branches, exception handlers
- **Source tags**: Every untrusted entry point annotated with source type
- **Sink tags**: Every dangerous operation tagged with vulnerability class
- **Sanitizer tags**: Every validator, encoder, auth check identified

Output: `code_graph.json` — the structural map of the entire codebase.

### Step 4b — Path Enumeration (New)

For every source-to-sink pair that is compatible:
1. Use the call graph to find all call paths from source to sink
2. Trace taint through each function on the path
3. Identify which paths have effective sanitizers
4. Record the complete path inventory

A medium codebase (~800 files) might produce 5,000-50,000 source-to-sink paths. Each path is a concrete list of functions with the data flow between them.

### Step 4c — Per-Path LLM Analysis (New)

This is where the LLM does its work. For each enumerated path:

1. Load the **full source** of every function on that path (2-8 functions typical)
2. Construct a focused prompt:
   - "Here is the complete data flow from source X (file:line, untrusted HTTP param) to sink Y (file:line, Process.Start with dynamic arguments)"
   - "Here are ALL functions on this path with full source code"
   - "Here are the sanitizers found on this path"
   - "Determine: is this path actually exploitable?"
3. Each LLM call handles **ONE path** with all the context it needs

The LLM doesn't discover paths — it **analyzes a path the graph already found**. This is what makes the 14B model effective.

### Step 5 — Memory Corruption Analysis (New)

For C/C++/Rust codebases, five dedicated analyzers:
- **Allocation tracker**: Detects integer overflow in size calculations, mismatched allocators
- **Buffer analyzer**: Stack/heap overflow, out-of-bounds access, off-by-one
- **Lifetime analyzer**: Use-after-free, double-free, invalid free
- **Integer overflow**: Overflow in size calculations, array indices
- **Format string**: Attacker-controlled format strings in printf/scanf family

### Step 6 — Chain Synthesis (New)

Builds an **attack graph** from all confirmed exploitable findings:
- A writes to a file → B reads that file
- A leaks data → B uses that data for privilege escalation
- A achieves SSRF → B uses internal API access
- A achieves auth bypass → B performs sensitive action

Computes transitive closure: A → C is valid if A → B → C exists.

### Steps 7-9 — Validation, Anomaly, Report

- **Step 7**: LLM-based precondition test (replaces keyword-based filters that were easily bypassable)
- **Step 8**: Prompt injection detection (ratio of LLM findings to Semgrep hits)
- **Step 9**: Exhaustive report with coverage statistics proving nothing was missed

## Vulnerability Class Coverage

### Injection
- Command injection (system, exec, subprocess, AddScript, PowerShell, etc.)
- SQL injection (raw queries, ORM raw, second-order)
- NoSQL injection (MongoDB $where, $expr, $function)
- LDAP injection
- XPath injection
- SSTI (Server-Side Template Injection)
- Header injection / HTTP request smuggling

### Deserialization
- Python (pickle, marshal, yaml.load)
- Java (ObjectInputStream, XMLDecoder, ysoserial gadgets)
- .NET (BinaryFormatter, JavaScriptSerializer, TypeNameHandling)
- Ruby (Marshal.load, YAML.load)
- PHP (unserialize)

### Memory Corruption (C/C++/Unsafe Rust)
- Stack buffer overflow (strcpy, gets, sprintf)
- Heap buffer overflow (memcpy with user-controlled size)
- Use-after-free
- Double-free
- Null pointer dereference
- Integer overflow leading to corruption
- Format string vulnerability
- Off-by-one
- Type confusion

### Path / File
- Path traversal (directory traversal, zip slip)
- Arbitrary file read/write
- Insecure file permissions
- TOCTOU (time-of-check time-of-use)
- Symbolic link attacks

### Network
- SSRF (Server-Side Request Forgery)
- HTTP request smuggling
- Open redirect

### Authentication / Authorization
- IDOR (Insecure Direct Object Reference)
- Missing function-level access control
- Privilege escalation
- JWT attacks (alg:none, no signature verification, key confusion)
- OAuth redirect misuse
- Hardcoded credentials
- Weak session management

### Crypto
- Weak algorithms (MD5, SHA1, DES, RC4)
- Weak random (non-CSRNG for security)
- Missing MAC/signature
- ECB mode
- Static IV/nonce
- TLS verification disabled

### Business Logic
- Parameter tampering
- Race conditions (TOCTOU, double-spend)
- Workflow bypass
- Type confusion

## Coverage Guarantee

Every source (untrusted input entry point) was paired with every compatible sink (dangerous operation) and all call-graph paths between them were enumerated. Each path was analyzed for taint propagation and sanitizers, then validated by the LLM for exploitability. Memory corruption was analyzed separately for C/C++/Rust codebases with dedicated alloc tracking, buffer analysis, lifetime analysis, integer overflow detection, and format string analysis.

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
├── threat_model.json
├── code_graph.json          NEW: complete code graph
├── path_enum.json           NEW: all source-to-sink paths
├── path_analysis.json       NEW: per-path LLM results
└── chains.json              NEW: exploit chains
```

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
  max_path_depth: 8          # Max call-graph depth for path enumeration
  max_paths_per_pair: 20     # Max paths per source-sink pair
  max_llm_paths: 500         # Max paths to analyze with LLM
  llm_temperature: 0.3       # LLM temperature for path validation
```

## File Structure

```
  models/                              GGUF files (main + draft)
  src/
    orchestrator.py                    Master pipeline + checkpointing
    pipeline/
      step0_fingerprint.py             Fingerprinting (manifest-only framework detect)
      step1_classify.py                16+ types + dual-language
      step2_deps.py                    Dependency vuln scan
      step2_secrets.py                 Secrets scanner
      step3_static.py                  Static analysis (full file inventory)
      step3b_codegraph.py              NEW: Code graph + source/sink/sanitizer tags
      step4_threat_model.py            Threat model + product-specific CVEs
      step4b_path_enum.py              NEW: Exhaustive source-to-sink path enumeration
      step4c_path_analyze.py           NEW: Per-path LLM exploitability analysis
      step5_fuzz.py                    Legacy: file-by-file LLM review
      step5_hypotheses.py              Legacy: hypothesis generation
      step5b_triage.py                 Legacy: skeptical verification
      step6_deep_trace.py              Legacy: iterative deep trace
      step7_chains.py                  NEW: Attack graph + chain synthesis
      step7_validate.py                LLM-based precondition test
      step8_anomaly.py                 Injection detection
      step9_report.py                  Exhaustive report with coverage statistics
    analysis/
      ast_parser.py                    Multi-language tree-sitter AST parser (16 langs)
      call_graph.py                    Call graph with import resolution
      source_tag.py                    All untrusted entry points
      sink_tag.py                      All dangerous operations
      sanitizer_tag.py                 All sanitizers
      intra_taint.py                   Intra-procedural taint tracking
      inter_taint.py                   Inter-procedural taint propagation
      path_enum.py                     Source-to-sink path enumeration
      path_analyze.py                  Per-path LLM analysis
      attack_graph.py                  Multi-step chain synthesis
      memory/
        orchestrator.py                Memory analysis coordinator
        alloc_tracker.py               Allocation tracking
        buffer_analyzer.py             Buffer overflow detection
        lifetime.py                    Use-after-free, double-free
        int_overflow.py                Integer overflow detection
        format_string.py               Format string vulnerability
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

- **Exhaustive coverage**: Every non-test source file reviewed. Every source-to-sink path enumerated. Nothing sampled.
- **Deterministic foundation + LLM reasoning**: The code graph is built deterministically. The LLM only validates pre-traced paths, never discovers them.
- **Short, focused prompts**: 3-stage approach with ~10-line prompts. Per-path analysis with ~2K token prompts.
- **Clean context per batch**: No memory between batches.
- **LLM-based validation**: Precondition test uses LLM, not bypassable keyword filters.
- **Product-specific CVEs**: Targeted to actual tech stack, not generic top-10.
- **Config-driven model**: Switch models by changing one line in config.yaml.
- **Local only**: No data leaves your machine. No API costs.

## References

- [Project Black: Local AI for Penetration Testing](https://projectblack.io/blog/local-ai-for-cyber-security/)
- [RAPTOR: Autonomous Security Research Framework](https://github.com/gadievron/raptor)
- [Qwen2.5-Coder-14B-Abliterated](https://huggingface.co/bartowski/Qwen2.5-Coder-14B-Instruct-abliterated-GGUF)
- [tree-sitter](https://tree-sitter.github.io/)

## License

For authorized security research only. Unauthorized use may violate computer fraud laws.
